//! Adversary pass 1 on `story:sts-lifetime-bounds`, at `0817c1e`.
//!
//! - [`a_profile_the_registration_refuses_issues_readably_until_9999_minus_its_bound`] drives
//!   the sentence `services/sts/src/registry.rs` writes over `admits_profile`, as corrected
//!   in I3 round 1: the issuance refuses as `ExpiryUnbounded` exactly the request instants
//!   after `9999-12-31T23:59:59Z` minus `max_ttl`. The bound is decided from `3000-01-01`, so
//!   a `max_ttl` of about 7 118 years is refused at registration and still issues a readable
//!   credential from a request in 2026. (The pass-1 case asserted the uncorrected sentence,
//!   "every issuance under it would be refused", which was false.)
//! - [`the_registration_bound_is_the_last_readable_second_from_the_year_3000`] pins the
//!   bound to the second. The shipped suite admits `P36500D` and refuses `P3650000D`, which
//!   leaves `LATEST_CHECKED_REQUEST_INSTANT` free anywhere from the year 0 to the year 9899.

use mandate_sts::issue::issue_reference_credential;
use mandate_sts::issue::{IssueReferenceCredential, ReferenceParts, Sha256Digest};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause, Denied, Projection};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, DenialReason, Duration,
    OrganizationId, PrincipalId, ResourceServerId, RevocationGuarantee, Timestamp, Uuid,
    VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-lifetime-bounds-1"),
    }
}

fn profile(max_ttl: &str) -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new(max_ttl),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

fn register(max_ttl: &str) -> Result<(), Denied> {
    register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-a"),
            profile: profile(max_ttl),
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut SequentialAllocator::new(),
    )
    .map(|_| ())
}

/// A reference issuance under `servers`' target at `at`: the expiry, and the secrets minted.
fn issue_at(
    servers: &Projection,
    id: ResourceServerId,
    at: &str,
) -> (Result<Timestamp, Denied>, u32) {
    let mut secrets = CountingSecrets::new();
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(),
            target: id,
            requested_scope: AuthorityScope {
                actions: Vec::new(),
                resources: Vec::new(),
                space: None,
            },
        },
        &RequestContext {
            correlation: CorrelationId::new("adversary-lifetime-bounds-1"),
            at: Timestamp::new(at),
            epochs: None,
        },
        servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut SequentialAllocator::new(),
        },
    );
    (
        issued.map(|outcome| outcome.descriptor.expires_at),
        secrets.minted(),
    )
}

/// Corrected by I3 correction round 1 (coordinator ruling on F1): the registry doc now says
/// the issuance refuses exactly the request instants after `9999-12-31T23:59:59Z` minus
/// `max_ttl`, under a refused bound as under an admitted one — so a refused bound still
/// issues a readable expiry from an early enough request, and is refused from a late one.
#[test]
fn a_profile_the_registration_refuses_issues_readably_until_9999_minus_its_bound() {
    // About 7 118 years: past the year 9999 from 3000-01-01, inside it from 2026.
    let max_ttl = "P2600000D";
    assert_eq!(
        register(max_ttl),
        Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProfileUnadmitted
        )),
        "premise: the registration handler refuses this profile"
    );

    let id = ResourceServerId::new(uuid(0x40));
    let log = vec![CredentialEvent::ResourceServerRegistered {
        context: context(),
        id,
        audience: Audience::new("api-a"),
        credential_profile: profile(max_ttl),
        allowed_exchange_sources: Vec::new(),
    }];
    let servers = Projection::fold(&log).expect("one creation");

    assert_eq!(
        issue_at(&servers, id, "2026-09-23T00:00:00Z"),
        (Ok(Timestamp::new("9145-04-15T00:00:00Z")), 1),
        "a 2026 request under a refused bound issues a readable expiry"
    );
    // 253_402_300_799 (9999-12-31T23:59:59Z) minus 224_640_000_000 (P2600000D).
    assert_eq!(
        issue_at(&servers, id, "2881-06-09T23:59:59Z"),
        (Ok(Timestamp::new("9999-12-31T23:59:59Z")), 1),
        "the last request instant whose expiry is readable issues"
    );
    assert_eq!(
        issue_at(&servers, id, "2881-06-10T00:00:00Z"),
        (
            Err(Denied::new(
                DenialReason::Denied,
                DenialClause::ExpiryUnbounded
            )),
            0
        ),
        "one second later the expiry is 10000-01-01T00:00:00Z: refused, nothing minted"
    );
}

#[test]
fn the_registration_bound_is_the_last_readable_second_from_the_year_3000() {
    // 9999-12-31T23:59:59Z (253_402_300_799) minus 3000-01-01T00:00:00Z (32_503_680_000).
    assert_eq!(
        register("PT220898620799S"),
        Ok(()),
        "lands on 9999-12-31T23:59:59Z"
    );
    assert_eq!(
        register("PT220898620800S"),
        Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProfileUnadmitted
        )),
        "lands on 10000-01-01T00:00:00Z"
    );
}
