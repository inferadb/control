#![deny(unsafe_code)]

//! # InferaDB Control Core
//!
//! Core business logic for the InferaDB Control Plane.
//!
//! Handlers call the Ledger SDK directly and use [`SdkResultExt`] for error
//! mapping. The remaining modules handle local concerns: email delivery,
//! ID generation, logging, and rate limiting.

pub mod clock;
pub mod crypto;
pub mod email;
pub mod email_hmac;
pub mod id;
pub mod logging;
pub mod metrics;
pub mod ratelimit;
pub mod ratelimit_ledger;
pub mod sdk_error;
pub mod startup;
pub mod webauthn;

pub use clock::{ClockStatus, ClockValidator, SkewSeverity};
pub use crypto::{MasterKey, PrivateKeyEncryptor, keypair};
pub use email::{
    EmailSender, EmailService, EmailTemplate, InvitationAcceptedEmailTemplate,
    InvitationEmailTemplate, MockEmailSender, OrganizationDeletionWarningEmailTemplate,
    PasswordResetEmailTemplate, RoleChangeEmailTemplate, SmtpEmailService,
    VerificationEmailTemplate,
};
pub use email_hmac::{EmailBlindingKey, compute_email_hmac, normalize_email, parse_blinding_key};
pub use id::IdGenerator;
pub use ratelimit::{
    InMemoryRateLimiter, LedgerRateLimiter, RateLimit, RateLimitResponse, RateLimitResult,
    RateLimiter, categories, in_memory_rate_limiter, limits,
};
pub use ratelimit_ledger::LedgerStorageBackend;
pub use sdk_error::{SdkResultExt, sdk_error_to_control};
