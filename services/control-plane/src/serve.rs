//! The listener: a blocking `std::net` accept loop over `httparse`, one request per
//! connection, `Connection: close` on every response.
//!
//! What it does: read one request head within [`Limits`], parse it, look the method and
//! path up in the route table `mandate_server::routes` declares, decode the request through
//! `mandate_server::decode`, hand the decoded input to the composition ([`Deployment`]), and
//! render the outcome as the RFC 6749 / 7662 / 8414 wire form. Every refusal is an RFC 6749
//! error body whose code comes from `mandate_proto::oauth`; no description carries a byte a
//! caller sent.
//!
//! What it does not do: dispatch on a path outside the route table (a generated
//! `/<domain>/commands/<Command>` projection is refused like any other unknown path), keep a
//! connection open, log a request, or read a body beyond the decoders' ceiling.
//!
//! # One connection at a time, and what bounds every other client's wait
//!
//! **This listener answers one connection at a time.** [`Listener::serve`] accepts, answers,
//! closes, and only then accepts again; there is no thread per connection and no runtime
//! behind it (ruling D2 — `hyper` and `tokio` arrive with the event-log adapter's runtime).
//! So the time one client takes is the time every other client waits, and the client chooses
//! it: a connection that dribbles a byte at a time under the read timeout makes progress on
//! every read and never trips one.
//!
//! What bounds that is [`Limits::request_deadline`]: the **whole** exchange — every read of
//! the head and the body, and the write of the response — finishes within it or the request
//! is refused. Each blocking call is given the smaller of what is left of the deadline and
//! its own timeout, so the deadline holds however the bytes are spread. The one exception is
//! the refusal a lapsed deadline itself produces: that response is written under
//! [`Limits::write_timeout`] alone, because a deadline that bounded its own refusal out of
//! existence would answer a slow client with a closed socket and nothing else.
//!
//! **A response is written in two bounded calls** — the head, then the body — and each is
//! given its own [`Limits::write_timeout`] once the deadline has lapsed, so the bound on one
//! connection is `request_deadline + 2 × write_timeout`, and so is every other client's wait
//! behind it. (Both calls blocking for their full timeout needs a response larger than the
//! peer's receive window; no response this road renders is, so the second term is arithmetic
//! rather than something a client can spend. It is stated because a bound that is quoted has
//! to be the bound that holds.) A property of the first served vertical, written here because
//! it is the kind of thing a reader assumes away.
//!
//! Transport (ruling D2, `story:product-listener`): `std::net` and `httparse`; `hyper` and
//! `tokio` arrive with the event-log adapter's runtime.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use mandate_federation::FederationVerifier;
use mandate_federation::verifier_real::Clock;
use mandate_proto::oauth::{self, ErrorBody, ErrorCode};
use mandate_server::decode::{self, Refusal as DecodeRefusal, Request};
use mandate_server::routes::{self, Binding, Document, Method, Route};
use mandate_sts::redemption::RedemptionRefused;
use mandate_sts::{IdentityAllocator, SecretSource};
use mandate_types::value::encode_base64;

use crate::adapters::{AuthorizationRefusal, Deployment, Refusal};

/// What this listener will read from one connection, and how long it waits for it.
#[derive(Debug, Clone)]
pub struct Limits {
    /// The most bytes a request head (request line and headers) may span.
    pub max_head_bytes: usize,
    /// The most header fields a request may carry.
    pub max_headers: usize,
    /// The most body bytes read; the decoders' own ceiling refuses the request past
    /// [`decode::MAX_BODY_BYTES`], so this bound only stops the read.
    pub max_body_bytes: usize,
    /// How long one read on the connection may block.
    pub read_timeout: Duration,
    /// How long one write on the connection may block.
    pub write_timeout: Duration,
    /// How long the whole exchange on one connection may take.
    ///
    /// Every read of the head and the body and the write of the response happen within it,
    /// so a connection that keeps making progress under [`Limits::read_timeout`] — a byte at
    /// a time — is still ended here. **This listener answers one connection at a time**, so
    /// this is also the bound on what one client can make every other client wait: this
    /// deadline plus `2 ×` [`Limits::write_timeout`], the two bounded writes the refusal it
    /// produces is sent in.
    pub request_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 8 * 1024,
            max_headers: 64,
            max_body_bytes: decode::MAX_BODY_BYTES + 1,
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            request_deadline: Duration::from_secs(10),
        }
    }
}

/// What is left of one exchange's [`Limits::request_deadline`].
#[derive(Debug, Clone, Copy)]
struct Deadline {
    started: Instant,
    span: Duration,
}

impl Deadline {
    /// The deadline, starting now.
    fn starting(span: Duration) -> Self {
        Self {
            started: Instant::now(),
            span,
        }
    }

    /// What is left of it, or `None` once it has lapsed.
    fn remaining(self) -> Option<Duration> {
        self.span.checked_sub(self.started.elapsed()).filter(
            // A zero timeout on a socket is not a timeout at all — it blocks forever — and
            // `std` refuses to set one. A deadline with nothing left has lapsed.
            |left| !left.is_zero(),
        )
    }

    /// How long one blocking call may take: what is left of the deadline, or its own bound,
    /// whichever is shorter.
    fn budget(self, timeout: Duration) -> Option<Duration> {
        self.remaining().map(|left| left.min(timeout))
    }
}

/// The refusal a lapsed deadline answers with.
///
/// RFC 9110 section 15.5.9's 408 is the status for "the server did not receive a complete
/// request message within the time that it was prepared to wait". The body is this road's own
/// RFC 6749 error, and the status stays 400 with it: every refusal this listener renders
/// carries one of those bodies, and `invalid_request` is what a request that was never framed
/// is.
fn deadline_lapsed() -> Response {
    Response::error(
        400,
        ErrorBody::new(
            ErrorCode::InvalidRequest,
            "the request did not arrive within the deadline",
        ),
    )
}

/// A bound socket, serving one request per accepted connection.
#[derive(Debug)]
pub struct Listener {
    socket: TcpListener,
    limits: Limits,
}

impl Listener {
    /// Bind the address.
    ///
    /// # Errors
    ///
    /// The socket's own error when the address cannot be bound.
    pub fn bind(address: impl ToSocketAddrs, limits: Limits) -> io::Result<Self> {
        Ok(Self {
            socket: TcpListener::bind(address)?,
            limits,
        })
    }

    /// The address the socket is bound to.
    ///
    /// # Errors
    ///
    /// The socket's own error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Accept connections until the socket fails, answering each with one response.
    ///
    /// A failure on one connection — a malformed head, a timeout, a peer that went away —
    /// ends that connection and nothing else.
    ///
    /// # Errors
    ///
    /// The socket's own error when `accept` fails.
    pub fn serve<V, C, X, A>(&self, deployment: &mut Deployment<V, C, X, A>) -> io::Result<()>
    where
        V: FederationVerifier,
        C: Clock,
        X: SecretSource,
        A: IdentityAllocator,
    {
        loop {
            let (stream, _) = self.socket.accept()?;
            // Nothing a connection does reaches the loop: the response to a refused read is
            // written on a best-effort basis and the stream is closed either way.
            let _ = self.answer(stream, deployment);
        }
    }

    /// Serve exactly one connection.
    fn answer<V, C, X, A>(
        &self,
        mut stream: TcpStream,
        deployment: &mut Deployment<V, C, X, A>,
    ) -> io::Result<()>
    where
        V: FederationVerifier,
        C: Clock,
        X: SecretSource,
        A: IdentityAllocator,
    {
        let deadline = Deadline::starting(self.limits.request_deadline);
        let response = match read_request(&mut stream, &self.limits, deadline) {
            Ok(request) => dispatch(&request, deployment),
            Err(refused) => refused,
        };
        let written = response.write_to(&mut stream, &self.limits, deadline);
        let _ = stream.shutdown(Shutdown::Both);
        written
    }
}

// ---------------------------------------------------------------------------------------
// Reading one request
// ---------------------------------------------------------------------------------------

/// One read on the connection, bounded by what is left of the deadline.
///
/// The socket's timeout is set before **every** read rather than once per connection: the
/// deadline is what is left of the exchange and it shrinks with each read, so a connection
/// that dribbles is ended by the deadline even though no single read of it ever times out.
fn read_within(
    stream: &mut TcpStream,
    limits: &Limits,
    deadline: Deadline,
    into: &mut [u8],
) -> Result<usize, Response> {
    let budget = deadline
        .budget(limits.read_timeout)
        .ok_or_else(deadline_lapsed)?;
    stream
        .set_read_timeout(Some(budget))
        .map_err(|_| deadline_lapsed())?;
    stream.read(into).map_err(|_| {
        if deadline.remaining().is_none() {
            deadline_lapsed()
        } else {
            Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request did not arrive"),
            )
        }
    })
}

/// Read and parse one request within the limits, or the response that refuses it.
fn read_request(
    stream: &mut TcpStream,
    limits: &Limits,
    deadline: Deadline,
) -> Result<Request, Response> {
    let mut buffer = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() >= limits.max_head_bytes {
            return Err(Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request head is too large"),
            ));
        }
        let mut chunk = [0_u8; 1024];
        let read = read_within(stream, limits, deadline, &mut chunk)?;
        if read == 0 {
            return Err(Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request head is incomplete"),
            ));
        }
        let room = limits.max_head_bytes.saturating_sub(buffer.len()).min(read);
        buffer.extend_from_slice(&chunk[..room]);
        if room < read {
            // The head has outgrown the limit even before its terminator; the bytes past it
            // may be body bytes, and this listener will not read a body for a head it refused.
            return Err(Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request head is too large"),
            ));
        }
    };

    let mut headers = vec![httparse::EMPTY_HEADER; limits.max_headers];
    let mut parsed = httparse::Request::new(&mut headers);
    let consumed = match parsed.parse(&buffer[..head_end]) {
        Ok(httparse::Status::Complete(consumed)) => consumed,
        Ok(httparse::Status::Partial) | Err(_) => {
            return Err(Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request head is malformed"),
            ));
        }
    };
    debug_assert_eq!(consumed, head_end);
    let (Some(method), Some(target)) = (parsed.method, parsed.path) else {
        return Err(Response::error(
            400,
            ErrorBody::new(ErrorCode::InvalidRequest, "the request head is malformed"),
        ));
    };
    let Some(target) = origin_form(target) else {
        return Err(Response::error(
            400,
            ErrorBody::new(
                ErrorCode::InvalidRequest,
                "the request target names no path this listener serves",
            ),
        ));
    };
    let mut request = Request::new(method, &target);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut hosts = 0_usize;
    let mut host_is_empty = false;
    for header in parsed.headers.iter() {
        let Ok(value) = core::str::from_utf8(header.value) else {
            return Err(Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "a header value is not UTF-8"),
            ));
        };
        if header.name.eq_ignore_ascii_case("content-length") {
            // RFC 9112 section 6.3: a repeated `Content-Length` is a request whose framing
            // two readers may disagree on, and it is refused rather than resolved.
            if content_length.is_some() {
                return Err(Response::error(
                    400,
                    ErrorBody::new(ErrorCode::InvalidRequest, "the content length is repeated"),
                ));
            }
            content_length = Some(content_length_of(value).ok_or_else(|| {
                Response::error(
                    400,
                    ErrorBody::new(ErrorCode::InvalidRequest, "the content length is malformed"),
                )
            })?);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = true;
        }
        if header.name.eq_ignore_ascii_case("host") {
            hosts += 1;
            host_is_empty = value.is_empty();
        }
        request = request.with_header(header.name, value);
    }
    if chunked {
        return Err(Response::error(
            400,
            ErrorBody::new(
                ErrorCode::InvalidRequest,
                "this listener reads a body by its content length only",
            ),
        ));
    }
    // RFC 9112 section 3.2: "A server MUST respond with a 400 (Bad Request) status code to
    // any HTTP/1.1 request message that lacks a Host header field and to any request message
    // that contains more than one Host header field line or a Host header field with an
    // invalid field value."
    //
    // The third framing-critical field this listener reads, beside `Content-Length` and
    // `Transfer-Encoding`, and it is the addressing half rather than the framing half: two
    // `Host` lines is the shape a front end that routes on the first and a listener that
    // reads neither disagree over. Repeated or empty is refused at every version; *absent* is
    // refused for HTTP/1.1 alone, because RFC 9112 obliges the field there and an HTTP/1.0
    // request that omits it is not malformed.
    let speaks_1_1 = parsed.version != Some(0);
    if hosts > 1 || host_is_empty || (hosts == 0 && speaks_1_1) {
        return Err(Response::error(
            400,
            ErrorBody::new(
                ErrorCode::InvalidRequest,
                "the request names no host, or more than one",
            ),
        ));
    }

    // The body: whatever the head already carried past its terminator, then the rest, up to
    // the declared length.
    //
    // **RFC 9112 section 6: the declared length is the frame.** A byte on the connection past
    // it is not part of this request — to a proxy in front of this listener it is the start of
    // the next one, which is the disagreement a repeated `Content-Length` is already refused
    // for. So the body is truncated *to the declared length* and never to what happened to
    // arrive with the head.
    let wanted = content_length.unwrap_or(0);
    if wanted > limits.max_body_bytes {
        // Declared longer than this listener reads: the decoders' ceiling refusal, decided on
        // the declared length and taken before a body byte is read. The bound is the decoders'
        // ceiling plus one so that a body at the ceiling is still read and refused by them.
        return Err(Response::error(400, DecodeRefusal::BodyTooLarge.body()));
    }
    let mut body: Vec<u8> = buffer[head_end..].to_vec();
    body.truncate(wanted);
    while body.len() < wanted {
        let mut chunk = [0_u8; 1024];
        let read = read_within(stream, limits, deadline, &mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        body.truncate(wanted);
    }
    if body.len() < wanted {
        return Err(Response::error(
            400,
            ErrorBody::new(ErrorCode::InvalidRequest, "the request body is incomplete"),
        ));
    }
    Ok(request.with_body(body))
}

/// The length a `Content-Length` field value declares, or `None` when it declares none.
///
/// RFC 9112 section 6.3: `Content-Length = 1*DIGIT`, and a message received without a
/// `Transfer-Encoding` and with an invalid `Content-Length` "has invalid framing" — which the
/// recipient treats as an unrecoverable error rather than repairing. `str::parse::<usize>`
/// admits a leading `+`, which no conformant reader does, so the digits are decided here and
/// `parse` is only asked for the value.
///
/// The optional whitespace RFC 9112 section 5 admits around a field value is not part of the
/// value, and `httparse` has already removed it, so nothing is trimmed here: what is left of
/// the value must be `1*DIGIT` in full. A value that overflows a `usize` names no length this
/// listener can frame and is refused with the rest.
fn content_length_of(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// The origin-form of a request target, or `None` for a form this listener does not serve.
///
/// RFC 9112 section 3.2 declares exactly four forms, and all four are decided here rather than
/// left to the route lookup:
///
/// * **origin-form** (`/path?query`) — what a client sends to a server, taken as it stands.
/// * **absolute-form** (`http://host/path?query`) — "a server MUST accept the absolute-form in
///   requests, even though HTTP/1.1 clients will only send them in requests to proxies"
///   (section 3.2.2). It is reduced to the origin-form the same request names, so the route it
///   names is the route it reaches: the authority is dropped and the path and query kept, and
///   an absolute-form that carries no path names `/`.
/// * **authority-form** (`host:port`) — `CONNECT`'s, and this listener serves no `CONNECT`.
/// * **asterisk-form** (`*`) — `OPTIONS`'s server-wide target, and this listener serves no
///   `OPTIONS`.
///
/// The last two name no path at all. They are refused rather than passed on, because a route
/// lookup reading `mandate.example:443` as a path answers "no product route serves this path",
/// which says something false about a target that named no path to serve.
fn origin_form(target: &str) -> Option<String> {
    if target.starts_with('/') {
        return Some(target.to_owned());
    }
    // RFC 3986 section 3.1: the scheme is case-insensitive.
    let lowered = target.to_ascii_lowercase();
    let authority = ["http://", "https://"]
        .into_iter()
        .find_map(|scheme| lowered.starts_with(scheme).then(|| &target[scheme.len()..]))?;
    let rest = authority
        .find(['/', '?', '#'])
        .map_or("", |offset| &authority[offset..]);
    Some(match rest.as_bytes().first() {
        None => "/".to_owned(),
        Some(b'/') => rest.to_owned(),
        // `http://host?q` names the empty path, which is the origin-form `/?q`.
        Some(_) => format!("/{rest}"),
    })
}

/// The offset just past the `\r\n\r\n` that ends a request head.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

// ---------------------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------------------

/// Route the request and answer it.
fn dispatch<V, C, X, A>(request: &Request, deployment: &mut Deployment<V, C, X, A>) -> Response
where
    V: FederationVerifier,
    C: Clock,
    X: SecretSource,
    A: IdentityAllocator,
{
    let path = request.route_path();
    let method = match request.method.as_str() {
        "GET" => Some(Method::Get),
        "POST" => Some(Method::Post),
        _ => None,
    };
    let route = method.and_then(|method| routes::lookup(method, path));
    let Some(route) = route else {
        // The path is served under another method, or under none. A generated command
        // projection lands here with every other unknown path: nothing dispatches on it.
        let declared: Vec<&Route> = routes::ROUTES
            .iter()
            .filter(|route| route.path == path)
            .collect();
        if declared.is_empty() {
            return Response::error(
                404,
                ErrorBody::new(
                    ErrorCode::InvalidRequest,
                    "no product route serves this path",
                ),
            );
        }
        let allow = declared
            .iter()
            .map(|route| route.method.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Response::error(405, DecodeRefusal::MethodNotAllowed.body())
            .with_header("Allow", &allow);
    };

    match route.binds {
        Binding::Document(Document::AuthorizationServerMetadata) => {
            Response::json(200, deployment.metadata().to_json())
        }
        Binding::Document(Document::Jwks) => match deployment.jwks() {
            Ok(jwks) => Response::json(200, jwks.to_json()),
            Err(_) => Response::error(
                500,
                ErrorBody::new(
                    ErrorCode::TemporarilyUnavailable,
                    "the key set could not be rendered",
                ),
            ),
        },
        Binding::Command("mandate.federation.AuthenticateFederation") => {
            match decode::authenticate_federation(request) {
                Err(refused) => Response::refused(&refused),
                Ok(input) => match deployment.authenticate(&input) {
                    Ok(login) => Response::json(
                        200,
                        serde_json::json!({
                            "session_id": login.session_id.to_string(),
                            "principal_id": login.principal_id.to_string(),
                            "organization_id": login.organization_id.to_string(),
                            "epochs": login.epochs.to_string(),
                            "expires_at": login.expires_at.to_string(),
                            "session_proof": encode_base64(login.session_proof.expose_bytes()),
                        })
                        .to_string(),
                    )
                    .no_store(),
                    Err(refusal) => Response::denied(&refusal),
                },
            }
        }
        Binding::Command("mandate.federation.AuthorizePublicClient") => {
            match decode::authorize_public_client(request) {
                Err(refused) => Response::refused(&refused),
                Ok(input) => match deployment.authorize(&input) {
                    Ok(authorization) => {
                        match redirect_to(
                            &authorization.redirect_uri.to_string(),
                            &[
                                ("code", &encode_base64(authorization.code.expose_bytes())),
                                ("state", &authorization.state),
                            ],
                        ) {
                            Ok(location) => Response::redirect(&location),
                            // The code was issued and is now unreachable: the registration
                            // this deployment holds cannot carry it. Nothing is redirected.
                            Err(refused) => redirect_unusable(refused),
                        }
                    }
                    Err(AuthorizationRefusal::InPlace(refusal)) => Response::denied(&refusal),
                    Err(AuthorizationRefusal::AtRedirect {
                        refusal,
                        redirect_uri,
                        state,
                    }) => {
                        let code = oauth::code_for_denial(&refusal.clause, refusal.reason);
                        match redirect_to(
                            &redirect_uri.to_string(),
                            &[("error", code.as_str()), ("state", &state)],
                        ) {
                            Ok(location) => Response::redirect(&location),
                            // RFC 6749 section 4.1.2.1's redirect is impossible, so the
                            // refusal is rendered — and it names the registration rather
                            // than the denial, because the registration is what a reader of
                            // this response can fix.
                            Err(refused) => redirect_unusable(refused),
                        }
                    }
                },
            }
        }
        Binding::Command("mandate.credential.RedeemAuthorizationCode") => {
            match decode::redeem_authorization_code(request) {
                Err(refused) => Response::refused(&refused).no_store(),
                Ok(input) => match deployment.redeem(&input) {
                    Ok(token) => {
                        // `expires_in` is RECOMMENDED (RFC 6749 section 5.1) and not declared by
                        // the contract's response; the descriptor's own `expires_at` is the
                        // instant the credential states, and introspection answers it. Omitted
                        // rather than derived from a clock the response does not carry.
                        let body = serde_json::json!({
                            "access_token": encode_base64(token.credential.expose_bytes()),
                            "token_type": "Bearer",
                            "credential_id": token.credential_id.to_string(),
                        });
                        Response::json(200, body.to_string()).no_store()
                    }
                    Err(RedemptionRefused::Denied(denied)) => {
                        let code = oauth::code_for_clause(denied.clause);
                        Response::error(
                            status_for(code),
                            ErrorBody::new(code, "the grant was refused"),
                        )
                        .no_store()
                    }
                    Err(RedemptionRefused::Append(_)) => Response::error(
                        503,
                        ErrorBody::new(
                            ErrorCode::TemporarilyUnavailable,
                            "the redemption could not be recorded",
                        ),
                    )
                    .no_store(),
                    // `RedemptionRefused` is non-exhaustive: a refusal this listener does
                    // not know is answered as unavailable, never as a grant that worked.
                    Err(_) => Response::error(
                        503,
                        ErrorBody::new(
                            ErrorCode::TemporarilyUnavailable,
                            "the redemption could not be decided",
                        ),
                    )
                    .no_store(),
                },
            }
        }
        Binding::Command("mandate.credential.IntrospectCredential") => {
            match decode::introspect_credential(request) {
                Err(refused) => Response::refused(&refused).no_store(),
                Ok(input) => match deployment.introspect(&input) {
                    Ok(introspection) => {
                        let mut body = serde_json::json!({ "active": introspection.active });
                        if let Some(id) = introspection.credential_id {
                            body["credential_id"] = serde_json::Value::from(id.to_string());
                        }
                        if let Some(descriptor) = introspection.descriptor {
                            body["aud"] = serde_json::Value::from(descriptor.audience.to_string());
                            body["sub"] = serde_json::Value::from(descriptor.subject.to_string());
                        }
                        Response::json(200, body.to_string()).no_store()
                    }
                    Err(denied) => {
                        // RFC 7662 section 2.3: the caller's own standing is answered as an
                        // error; anything about the presented token is `active: false`.
                        let code = oauth::code_for_clause(denied.clause);
                        if code == ErrorCode::InvalidClient {
                            Response::error(401, ErrorBody::new(code, "the caller was refused"))
                                .no_store()
                        } else {
                            Response::json(200, serde_json::json!({ "active": false }).to_string())
                                .no_store()
                        }
                    }
                },
            }
        }
        Binding::Command(_) => Response::error(
            404,
            ErrorBody::new(
                ErrorCode::InvalidRequest,
                "no product route serves this path",
            ),
        ),
    }
}

/// RFC 6749 section 5.2: `invalid_client` may answer 401; every other code answers 400.
fn status_for(code: ErrorCode) -> u16 {
    if code == ErrorCode::InvalidClient {
        401
    } else {
        400
    }
}

/// The response parameters RFC 6749 sections 4.1.2 and 4.1.2.1 add to a redirect.
///
/// Named here so that the composer's refusal is decided against the same three names the
/// composer would write, and so a fourth response parameter cannot be added in one place.
const RESPONSE_PARAMETERS: &[&str] = &["code", "state", "error"];

/// Why a registered redirection endpoint URI carries no response at all.
///
/// **This is the client-registration class**: every variant is a fact about the URI the
/// client registered, not about the request. RFC 6749 section 4.1.2.1 answers it in place —
/// "If the request fails due to a missing, invalid, or mismatching redirection URI ... the
/// authorization server SHOULD inform the resource owner of the error and MUST NOT
/// automatically redirect the user-agent to the invalid redirection URI" — so none of these
/// is ever redirected to, on either branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectRefused {
    /// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST NOT include a fragment
    /// component." By RFC 3986 section 3.5 every parameter appended after the `#` is inside
    /// the fragment, which the redirection endpoint never receives.
    Fragment,
    /// The registered query is not an `application/x-www-form-urlencoded` form, so a
    /// parameter added to it is not a parameter: `mandate_proto::oauth::decode_form` — the
    /// reader a client of this road uses — refuses the result.
    QueryNotAForm,
    /// The registered query already names one of [`RESPONSE_PARAMETERS`]. Appending a second
    /// one leaves a query that names it twice: `decode_form` refuses it, and every reader
    /// that resolves the repeat by picking one may pick the registrant's value where RFC 6749
    /// section 4.1.2 requires "the exact value received from the client".
    QueryNamesResponseParameter,
}

impl RedirectRefused {
    /// What is said to the resource owner. Fixed text, carrying no byte a caller sent.
    const fn description(self) -> &'static str {
        match self {
            Self::Fragment => "the registered redirection URI carries a fragment",
            Self::QueryNotAForm => "the registered redirection URI's query is not a form",
            Self::QueryNamesResponseParameter => {
                "the registered redirection URI's query names a response parameter"
            }
        }
    }
}

/// The `Location` a redirect to a registered redirection endpoint URI carries, or why that
/// URI can carry no response.
///
/// **One composer for both branches of RFC 6749 section 4.1.2**, the code and the error,
/// because the rule is the same rule and a second copy is the one that gets it wrong.
///
/// Section 3.1.2 admits a query component on the registered URI — "The endpoint URI MAY
/// include an `application/x-www-form-urlencoded` formatted query component ... which MUST be
/// retained when adding additional query parameters" — and sections 4.1.2 and 4.1.2.1 add the
/// response parameters *to the query component*. A parameter is a parameter only if the
/// result is still a form, so **the registered query is parsed before it is extended** and
/// the three ways it cannot be are [`RedirectRefused`]. The separator follows from the parse
/// rather than from `contains('?')`: `&` after a query that carries a pair, nothing after a
/// query component that is present and empty, `?` where there is no query component at all.
///
/// The registered URI is written out as it was registered — it is not this listener's to
/// re-encode — and every value is percent-encoded outside RFC 3986's unreserved set, so a
/// `state` carrying `&`, `=`, `#` or a newline is one parameter's value and never a second
/// parameter or a second header.
///
/// # Errors
///
/// Returns [`RedirectRefused`] when the registered URI carries a fragment, or a query that is
/// not a form or that already names a response parameter.
fn redirect_to(redirect_uri: &str, parameters: &[(&str, &str)]) -> Result<String, RedirectRefused> {
    if redirect_uri.contains('#') {
        return Err(RedirectRefused::Fragment);
    }
    let registered_query = redirect_uri.split_once('?').map(|(_, query)| query);
    if let Some(query) = registered_query {
        let form = oauth::decode_form(query).map_err(|_| RedirectRefused::QueryNotAForm)?;
        if form.keys().any(|name| RESPONSE_PARAMETERS.contains(&name)) {
            return Err(RedirectRefused::QueryNamesResponseParameter);
        }
    }
    let mut location = redirect_uri.to_owned();
    let mut separator = match registered_query {
        // A query component that is present and empty is an empty form: the first parameter
        // follows the `?` directly, and a `&` there would leave an empty first segment.
        Some("") => None,
        Some(_) => Some('&'),
        None => Some('?'),
    };
    for (name, value) in parameters {
        if let Some(separator) = separator {
            location.push(separator);
        }
        location.push_str(name);
        location.push('=');
        location.push_str(&percent_encode(value));
        separator = Some('&');
    }
    Ok(location)
}

/// The response a registered redirection URI that carries no response is answered with.
///
/// Rendered, never redirected (RFC 6749 section 4.1.2.1), and `invalid_request` because what
/// is invalid is the value of the `redirect_uri` parameter the request presented — which at
/// this point is byte-for-byte the one the client registered, so the fault is the
/// registration's and the answer says which part of it.
fn redirect_unusable(refused: RedirectRefused) -> Response {
    Response::error(
        400,
        ErrorBody::new(ErrorCode::InvalidRequest, refused.description()),
    )
}

/// Percent-encode everything outside RFC 3986's unreserved set.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------

/// One write on the connection, bounded by what is left of the deadline — or, once it has
/// lapsed, by the write timeout alone.
///
/// **The refusal a lapsed deadline produces is still written.** A deadline that bounded its
/// own refusal out of existence would answer a slow client with a closed socket and nothing
/// else, which is the one thing [`deadline_lapsed`] exists to avoid. So one connection is
/// bounded by `request_deadline + write_timeout` and not by the deadline alone, and that is
/// the number a reader should hold.
fn write_within(
    stream: &mut TcpStream,
    limits: &Limits,
    deadline: Deadline,
    bytes: &[u8],
) -> io::Result<()> {
    let budget = deadline
        .budget(limits.write_timeout)
        .unwrap_or(limits.write_timeout);
    stream.set_write_timeout(Some(budget))?;
    stream.write_all(bytes)
}

/// One response: status, headers, body. Always `Connection: close`.
#[derive(Debug, Clone)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: String) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.into_bytes(),
        }
    }

    fn error(status: u16, body: ErrorBody) -> Self {
        Self::json(status, body.to_json())
    }

    /// A decoder refusal: its own code and description, 405 where the method is the fault.
    fn refused(refused: &DecodeRefusal) -> Self {
        let status = match refused {
            DecodeRefusal::MethodNotAllowed => 405,
            _ => status_for(refused.error_code()),
        };
        Self::error(status, refused.body())
    }

    /// A handler's denial, rendered in place.
    fn denied(refusal: &Refusal) -> Self {
        let code = oauth::code_for_denial(&refusal.clause, refusal.reason);
        Self::error(
            status_for(code),
            ErrorBody::new(code, "the request was refused"),
        )
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            headers: vec![("Location".to_owned(), location.to_owned())],
            body: Vec::new(),
        }
        .no_store()
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// RFC 6749 section 5.1: a response carrying a credential is not cached.
    fn no_store(self) -> Self {
        self.with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache")
    }

    /// Write the response, each call bounded by what is left of the exchange's deadline.
    ///
    /// A client that stops reading is a client that could otherwise hold this listener — and
    /// every other client behind it — for as long as it liked, so the write is inside the
    /// deadline exactly as the reads are. A lapsed deadline here answers nothing: there is
    /// nowhere left to write a refusal to.
    fn write_to(
        &self,
        stream: &mut TcpStream,
        limits: &Limits,
        deadline: Deadline,
    ) -> io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "",
        };
        let mut head = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        head.push_str("Connection: close\r\n\r\n");
        write_within(stream, limits, deadline, head.as_bytes())?;
        write_within(stream, limits, deadline, &self.body)?;
        stream.flush()
    }
}
