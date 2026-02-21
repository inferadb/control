#![deny(unsafe_code)]

//! # InferaDB Control Core
//!
//! Core business logic for the InferaDB Control Plane.
//!
//! ## Imports
//!
//! Import types from their source crates:
//! - Entity types: `inferadb_control_types::entities`
//! - DTOs: `inferadb_control_types::dto`
//! - Errors: `inferadb_control_types::Error`
//! - Config: `inferadb_control_config::Config`

pub mod auth;
pub mod clock;
pub mod crypto;
pub mod email;
pub mod id;
pub mod jobs;
pub mod jwt;
pub mod leader;
pub mod logging;
pub mod metrics;
pub mod ratelimit;
pub mod repository;
pub mod repository_context;
pub mod startup;

pub use auth::{PasswordHasher, hash_password, verify_password};
pub use clock::{ClockStatus, ClockValidator, SkewSeverity};
pub use crypto::{MasterKey, PrivateKeyEncryptor, keypair};
pub use email::{
    EmailSender, EmailService, EmailTemplate, InvitationAcceptedEmailTemplate,
    InvitationEmailTemplate, MockEmailSender, OrganizationDeletionWarningEmailTemplate,
    PasswordResetEmailTemplate, RoleChangeEmailTemplate, SmtpEmailService,
    VerificationEmailTemplate,
};
pub use id::{IdGenerator, WorkerRegistry, acquire_worker_id};
pub use jobs::BackgroundJobs;
pub use jwt::{JwtSigner, VaultTokenClaims};
pub use leader::LeaderElection;
pub use ratelimit::{RateLimit, RateLimitResult, RateLimiter, categories, limits};
pub use repository::{
    AuditLogFilters, AuditLogRepository, AuthorizationCodeRepository, ClientCertificateRepository,
    ClientRepository, JtiReplayProtectionRepository, OrganizationInvitationRepository,
    OrganizationMemberRepository, OrganizationRepository, OrganizationTeamMemberRepository,
    OrganizationTeamPermissionRepository, OrganizationTeamRepository, PasskeyCredentialRepository,
    SecureTokenRepository, UserEmailRepository, UserEmailVerificationTokenRepository,
    UserPasswordResetTokenRepository, UserRepository, UserSessionRepository,
    VaultRefreshTokenRepository, VaultRepository, VaultTeamGrantRepository,
    VaultUserGrantRepository,
};
pub use repository_context::RepositoryContext;
