#![deny(unsafe_code)]

//! # InferaDB Control Core
//!
//! Core business logic for the InferaDB Control Plane.
//!
//! All domain operations delegate to Ledger via the [`service`] module.
//! The remaining modules handle local concerns: email delivery, JWT signing,
//! ID generation, logging, and rate limiting.

pub mod auth;
pub mod clock;
pub mod crypto;
pub mod email;
pub mod email_hmac;
pub mod id;
pub mod jwt;
pub mod logging;
pub mod metrics;
pub mod ratelimit;
pub mod service;
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
    RateLimit, RateLimitResponse, RateLimitResult, RateLimiter, categories, limits,
};
