//! Adversary pass 1 on `story:sts-lifetime-bounds`, at `0817c1e`.
//!
//! - [`a_profile_the_registration_refuses_issues_nothing_as_its_doc_says`] drives the
//!   sentence `services/sts/src/registry.rs` writes over `admits_profile`: "A bound past the
//!   last four-digit year promises an expiry this crate cannot write in a form it reads back,
//!   so every issuance under it would be refused as `ExpiryUnbounded`." The bound is decided
//!   from `3000-01-01`, so a `max_ttl` of about 7 118 years is refused at registration and
//!   still issues a readable credential from a request in 2026.
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

#[test]
fn a_profile_the_registration_refuses_issues_nothing_as_its_doc_says() {
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
            at: Timestamp::new("2026-09-23T00:00:00Z"),
            epochs: None,
        },
        &servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut CountingSecrets::new(),
            allocator: &mut SequentialAllocator::new(),
        },
    );
    assert_eq!(
        issued.map(|outcome| outcome.descriptor.expires_at),
        Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ExpiryUnbounded
        )),
        "registry.rs: a bound `admits_profile` refuses is one under which \
         `every issuance under it would be refused as ExpiryUnbounded`"
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
