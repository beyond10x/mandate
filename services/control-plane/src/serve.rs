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
//! Transport (ruling D2, `story:product-listener`): `std::net` and `httparse`; `hyper` and
//! `tokio` arrive with the event-log adapter's runtime.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

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
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_bytes: 8 * 1024,
            max_headers: 64,
            max_body_bytes: decode::MAX_BODY_BYTES + 1,
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
        }
    }
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
        stream.set_read_timeout(Some(self.limits.read_timeout))?;
        stream.set_write_timeout(Some(self.limits.write_timeout))?;
        let response = match read_request(&mut stream, &self.limits) {
            Ok(request) => dispatch(&request, deployment),
            Err(refused) => refused,
        };
        let written = response.write_to(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
        written
    }
}

// ---------------------------------------------------------------------------------------
// Reading one request
// ---------------------------------------------------------------------------------------

/// Read and parse one request within the limits, or the response that refuses it.
fn read_request(stream: &mut TcpStream, limits: &Limits) -> Result<Request, Response> {
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
        let read = stream.read(&mut chunk).map_err(|_| {
            Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request head did not arrive"),
            )
        })?;
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
    let mut request = Request::new(method, target);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
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
            content_length = Some(value.trim().parse().map_err(|_| {
                Response::error(
                    400,
                    ErrorBody::new(ErrorCode::InvalidRequest, "the content length is malformed"),
                )
            })?);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = true;
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

    // The body: whatever the head already carried past its terminator, then the rest, up to
    // the read bound. The decoders refuse a body past their own ceiling; this bound only
    // stops the read at that ceiling plus one so the refusal has something to decide on.
    let content_length = content_length.unwrap_or(0);
    let mut body: Vec<u8> = buffer[head_end..].to_vec();
    let wanted = content_length.min(limits.max_body_bytes);
    while body.len() < wanted {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).map_err(|_| {
            Response::error(
                400,
                ErrorBody::new(ErrorCode::InvalidRequest, "the request body did not arrive"),
            )
        })?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(wanted.max(body.len().min(limits.max_body_bytes)));
    if body.len() < wanted {
        return Err(Response::error(
            400,
            ErrorBody::new(ErrorCode::InvalidRequest, "the request body is incomplete"),
        ));
    }
    if content_length > limits.max_body_bytes {
        // Declared longer than this listener reads: the decoders' ceiling refusal, decided
        // on the declared length rather than on bytes never read.
        return Err(Response::error(400, DecodeRefusal::BodyTooLarge.body()));
    }
    Ok(request.with_body(body))
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
                        let location = format!(
                            "{}?code={}&state={}",
                            authorization.redirect_uri,
                            percent_encode(&encode_base64(authorization.code.expose_bytes())),
                            percent_encode(&authorization.state)
                        );
                        Response::redirect(&location)
                    }
                    Err(AuthorizationRefusal::InPlace(refusal)) => Response::denied(&refusal),
                    Err(AuthorizationRefusal::AtRedirect {
                        refusal,
                        redirect_uri,
                        state,
                    }) => {
                        let code = oauth::code_for_denial(&refusal.clause, refusal.reason);
                        let location = format!(
                            "{redirect_uri}?error={}&state={}",
                            code.as_str(),
                            percent_encode(&state)
                        );
                        Response::redirect(&location)
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

    fn write_to(&self, stream: &mut TcpStream) -> io::Result<()> {
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
        stream.write_all(head.as_bytes())?;
        stream.write_all(&self.body)?;
        stream.flush()
    }
}
