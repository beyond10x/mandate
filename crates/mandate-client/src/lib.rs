//! Rust PEP client and middleware.
//!
//! The token guard's library form (`docs/adr/0013-token-guard.md`): [`verify::Verifier`]
//! checks a bearer token against an issuer's JWK Set and a [`GuardPolicy`], and answers
//! with a typed [`Identity`] or a typed [`Refusal`]. The policy, the identity and the
//! refusal are the generated shapes of `mandate.guard` in `systems/mandate`, so the
//! library and the guard sidecar answer the same token with the same reason.

pub mod verify;

/// The guard policy: issuer, audiences, the allow rule and the limits (`mandate.guard.GuardPolicy`).
pub type GuardPolicy = mandate_contract::types::MandateGuardGuardPolicy;
/// The allow rule of a [`GuardPolicy`] (`mandate.guard.AllowRule`).
pub type AllowRule = mandate_contract::types::MandateGuardAllowRule;
/// The per-identity limits of a [`GuardPolicy`] (`mandate.guard.GuardLimits`).
pub type GuardLimits = mandate_contract::types::MandateGuardGuardLimits;
/// The verified identity an admitted token carries (`mandate.guard.AdmitRequest`'s response).
pub type Identity = mandate_contract::commands::MandateGuardAdmitRequestResponse;
/// A typed refusal (`mandate.guard.Refused`).
pub type Refusal = mandate_contract::commands::MandateGuardRefused;
/// The clause that refused a token (`mandate.guard.RefusalReason`).
pub type RefusalReason = mandate_contract::types::MandateGuardRefusalReason;
