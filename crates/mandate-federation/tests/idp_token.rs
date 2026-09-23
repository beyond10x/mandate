//! The token-endpoint port of the relying party (`story:relying-party-code-flow`).
//!
//! [`UreqIdpToken`] is driven against a listener this file owns on the loopback interface,
//! which `UreqJwks::admits` admits over plain `http` for a loopback issuer. No case reaches
//! the network.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use mandate_federation::idp_token::{
    ClientSecret, CodeRedemption, IdpTokenEndpoint, TokenRefusal, UreqIdpToken,
    authorization_request, basic_authorization, endpoints, nonce_matches,
};
use mandate_federation::verifier::VerifiedProof;
use mandate_types::value::encode_base64;
use mandate_types::{ClientId, CredentialProof, ExternalSubject, Issuer};

/// What one request to the listener carried.
struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(held, _)| held.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A listener answering every request with `status` and `body`, handing each request back.
fn listener(status: u16, body: &'static str) -> (SocketAddr, Receiver<Captured>) {
    let socket = TcpListener::bind("127.0.0.1:0").expect("a loopback socket");
    let address = socket.local_addr().expect("the bound address");
    let (sending, received) = channel();
    std::thread::spawn(move || {
        for stream in socket.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().expect("a second handle"));
            let mut request_line = String::new();
            let _ = reader.read_line(&mut request_line);
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let line = line.trim_end().to_owned();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.push((name.trim().to_owned(), value.trim().to_owned()));
                }
            }
            let length = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.parse::<usize>().ok())
                .unwrap_or(0);
            let mut read = vec![0_u8; length];
            let _ = reader.read_exact(&mut read);
            let _ = sending.send(Captured {
                request_line: request_line.trim_end().to_owned(),
                headers,
                body: String::from_utf8(read).unwrap_or_default(),
            });
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (address, received)
}

fn secret() -> ClientSecret {
    ClientSecret::from_bytes(b"p&q:secret".to_vec())
}

fn redemption<'a>(
    issuer: &'a Issuer,
    token_endpoint: &'a str,
    client_id: &'a ClientId,
    client_secret: &'a ClientSecret,
    code: &'a CredentialProof,
    verifier: &'a CredentialProof,
) -> CodeRedemption<'a> {
    CodeRedemption {
        issuer,
        token_endpoint,
        allowed_hosts: &[],
        client_id,
        client_secret,
        code,
        redirect_uri: "https://mandate.example/v1/federation/callback",
        code_verifier: verifier,
    }
}

#[test]
fn basic_authentication_form_encodes_both_halves_before_it_is_base64_encoded() {
    // RFC 6749 section 2.3.1: the client identifier and the password are each encoded with
    // `application/x-www-form-urlencoded` and then joined by `:` — so a `:` inside either
    // half is not the separator.
    assert_eq!(
        basic_authorization(&ClientId::new("a:b"), &secret()),
        format!("Basic {}", encode_base64(b"a%3Ab:p%26q%3Asecret"))
    );
}

#[test]
fn a_code_is_redeemed_with_http_basic_and_the_verifier_and_the_id_token_is_answered() {
    let (address, received) = listener(200, r#"{"id_token":"aaa.bbb.ccc","token_type":"Bearer"}"#);
    let issuer = Issuer::new(format!("http://{address}"));
    let endpoint = format!("http://{address}/token");
    let client = ClientId::new("platform-rp");
    let secret = secret();
    let code = CredentialProof::from_bytes(b"the-code".to_vec());
    let verifier = CredentialProof::from_bytes(b"v".repeat(43));

    let answered = UreqIdpToken::new()
        .redeem(&redemption(
            &issuer, &endpoint, &client, &secret, &code, &verifier,
        ))
        .expect("the endpoint answered an ID token");
    assert_eq!(answered.expose_bytes(), b"aaa.bbb.ccc");

    let captured = received
        .recv_timeout(Duration::from_secs(5))
        .expect("the endpoint was reached");
    assert_eq!(captured.request_line, "POST /token HTTP/1.1");
    assert_eq!(
        captured.header("Authorization"),
        Some(basic_authorization(&client, &secret).as_str())
    );
    let body: Vec<&str> = captured.body.split('&').collect();
    assert!(body.contains(&"grant_type=authorization_code"), "{body:?}");
    assert!(body.contains(&"code=the-code"), "{body:?}");
    assert!(
        body.contains(&format!("code_verifier={}", "v".repeat(43)).as_str()),
        "{body:?}"
    );
    assert!(
        body.iter()
            .any(|pair| pair.starts_with("redirect_uri=https")),
        "{body:?}"
    );
    assert!(
        !captured.body.contains("client_secret") && !captured.body.contains("secret"),
        "the secret travels in the header alone: {}",
        captured.body
    );
}

#[test]
fn a_refused_client_authentication_is_a_refusal_and_no_id_token() {
    let (address, _received) = listener(401, r#"{"error":"invalid_client"}"#);
    let issuer = Issuer::new(format!("http://{address}"));
    let endpoint = format!("http://{address}/token");
    let client = ClientId::new("platform-rp");
    let secret = secret();
    let code = CredentialProof::from_bytes(b"c".to_vec());
    let verifier = CredentialProof::from_bytes(b"v".repeat(43));
    assert_eq!(
        UreqIdpToken::new()
            .redeem(&redemption(
                &issuer, &endpoint, &client, &secret, &code, &verifier
            ))
            .err(),
        Some(TokenRefusal::Refused)
    );
}

#[test]
fn an_answer_carrying_no_id_token_is_refused() {
    let (address, _received) = listener(200, r#"{"access_token":"x","token_type":"Bearer"}"#);
    let issuer = Issuer::new(format!("http://{address}"));
    let endpoint = format!("http://{address}/token");
    let client = ClientId::new("platform-rp");
    let secret = secret();
    let code = CredentialProof::from_bytes(b"c".to_vec());
    let verifier = CredentialProof::from_bytes(b"v".repeat(43));
    assert_eq!(
        UreqIdpToken::new()
            .redeem(&redemption(
                &issuer, &endpoint, &client, &secret, &code, &verifier
            ))
            .err(),
        Some(TokenRefusal::IdTokenAbsent)
    );
}

#[test]
fn a_token_endpoint_off_the_issuers_origin_is_never_reached() {
    let (address, received) = listener(200, r#"{"id_token":"aaa.bbb.ccc"}"#);
    // The issuer is another loopback port: the endpoint is neither its origin nor listed.
    let issuer = Issuer::new("http://127.0.0.1:1");
    let endpoint = format!("http://{address}/token");
    let client = ClientId::new("platform-rp");
    let secret = secret();
    let code = CredentialProof::from_bytes(b"c".to_vec());
    let verifier = CredentialProof::from_bytes(b"v".repeat(43));
    assert_eq!(
        UreqIdpToken::new()
            .redeem(&redemption(
                &issuer, &endpoint, &client, &secret, &code, &verifier
            ))
            .err(),
        Some(TokenRefusal::EndpointNotAdmitted)
    );
    assert!(
        received.recv_timeout(Duration::from_millis(300)).is_err(),
        "nothing was sent to a destination the guard refused"
    );
}

#[test]
fn the_endpoints_are_read_from_a_discovery_document_that_names_this_issuer() {
    let issuer = Issuer::new("https://idp.example");
    let document = serde_json::json!({
        "issuer": "https://idp.example",
        "authorization_endpoint": "https://idp.example/oauth2/authorize",
        "token_endpoint": "https://idp.example/oauth2/token",
    });
    let found = endpoints(&issuer, &document, &[]).expect("both endpoints");
    assert_eq!(
        found.authorization_endpoint,
        "https://idp.example/oauth2/authorize"
    );
    assert_eq!(found.token_endpoint, "https://idp.example/oauth2/token");

    let mut foreign = document.clone();
    foreign["issuer"] = "https://another.example".into();
    assert_eq!(
        endpoints(&issuer, &foreign, &[]).err(),
        Some(TokenRefusal::DiscoveryIssuerMismatch)
    );
    let mut absent = document.clone();
    absent
        .as_object_mut()
        .expect("an object")
        .remove("token_endpoint");
    assert_eq!(
        endpoints(&issuer, &absent, &[]).err(),
        Some(TokenRefusal::EndpointAbsent)
    );
    let mut elsewhere = document.clone();
    elsewhere["token_endpoint"] = "https://tokens.idp.example/token".into();
    assert_eq!(
        endpoints(&issuer, &elsewhere, &[]).err(),
        Some(TokenRefusal::EndpointNotAdmitted)
    );
    assert!(
        endpoints(&issuer, &elsewhere, &["tokens.idp.example".to_owned()]).is_ok(),
        "a host the deployment listed is admitted"
    );
    let mut downgraded = document;
    downgraded["authorization_endpoint"] = "http://idp.example/oauth2/authorize".into();
    assert_eq!(
        endpoints(&issuer, &downgraded, &[]).err(),
        Some(TokenRefusal::EndpointNotAdmitted)
    );
}

#[test]
fn the_authorization_request_carries_state_nonce_and_an_s256_challenge() {
    let url = authorization_request(
        "https://idp.example/oauth2/authorize",
        &ClientId::new("platform-rp"),
        "https://mandate.example/v1/federation/callback",
        "the-state",
        "the-nonce",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    let (endpoint, query) = url.split_once('?').expect("a query");
    assert_eq!(endpoint, "https://idp.example/oauth2/authorize");
    let pairs: Vec<&str> = query.split('&').collect();
    for expected in [
        "response_type=code",
        "client_id=platform-rp",
        "redirect_uri=https%3A%2F%2Fmandate.example%2Fv1%2Ffederation%2Fcallback",
        "scope=openid",
        "state=the-state",
        "nonce=the-nonce",
        "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method=S256",
    ] {
        assert!(pairs.contains(&expected), "{expected} in {pairs:?}");
    }
    // An endpoint that already carries a query keeps it, and gains `&`, not a second `?`.
    let kept = authorization_request(
        "https://idp.example/authorize?tenant=common",
        &ClientId::new("c"),
        "https://r.example/cb",
        "s",
        "n",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    assert!(
        kept.starts_with("https://idp.example/authorize?tenant=common&"),
        "{kept}"
    );
    assert_eq!(kept.matches('?').count(), 1, "{kept}");
}

#[test]
fn the_nonce_is_matched_against_the_validated_claim_and_nothing_else() {
    let proof = || {
        VerifiedProof::new(
            Issuer::new("https://idp.example"),
            ExternalSubject::new("pairwise-sub"),
            ClientId::new("platform-rp"),
        )
    };
    assert!(nonce_matches(
        &proof().with_verified_claim("nonce", "n-1"),
        "n-1"
    ));
    assert!(!nonce_matches(
        &proof().with_verified_claim("nonce", "n-2"),
        "n-1"
    ));
    assert!(
        !nonce_matches(&proof(), "n-1"),
        "an absent nonce matches nothing"
    );
    assert!(
        !nonce_matches(&proof().with_unverified_hint("nonce", "n-1"), "n-1"),
        "an unvalidated value is not the nonce"
    );
    assert!(!nonce_matches(
        &proof().with_verified_claim("nonce", ""),
        ""
    ));
}

#[test]
fn a_client_secret_never_renders_and_is_read_from_a_file_without_its_line_end() {
    let rendered = format!("{:?}", ClientSecret::from_bytes(b"hunter2".to_vec()));
    assert!(!rendered.contains("hunter2"), "{rendered}");

    let directory = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("idp-token")
        .join(format!("run-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    let path = directory.join("secret");
    std::fs::write(&path, "hunter2\n").expect("the secret file");
    let read = ClientSecret::read(&path).expect("a readable secret");
    assert_eq!(read.expose_bytes(), b"hunter2");
    std::fs::write(&path, "\n").expect("an empty secret file");
    assert!(
        ClientSecret::read(&path).is_err(),
        "an empty secret is no secret"
    );
    let _ = std::fs::remove_dir_all(&directory);
}
