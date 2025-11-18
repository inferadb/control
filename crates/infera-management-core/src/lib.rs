pub mod auth;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod email;
pub mod entities;
pub mod error;
pub mod id;
pub mod jobs;
pub mod jwt;
pub mod leader;
pub mod logging;
pub mod metrics;
pub mod ratelimit;
pub mod repository;

pub use auth::{hash_password, verify_password, PasswordHasher};
pub use clock::{ClockStatus, ClockValidator};
pub use config::ManagementConfig;
pub use crypto::{keypair, PrivateKeyEncryptor};
pub use email::{EmailSender, EmailService, SmtpEmailService};
pub use entities::{
    AuthorizationCode, Client, ClientCertificate, Organization, OrganizationInvitation,
    OrganizationMember, OrganizationPermission, OrganizationRole, OrganizationTeam,
    OrganizationTeamMember, OrganizationTeamPermission, OrganizationTier, SessionType, User,
    UserEmail, UserEmailVerificationToken, UserPasswordResetToken, UserSession, Vault,
    VaultRefreshToken, VaultRole, VaultSyncStatus, VaultTeamGrant, VaultUserGrant,
};
pub use error::{Error, Result};
pub use id::{IdGenerator, WorkerRegistry};
pub use jobs::BackgroundJobs;
pub use jwt::{JwtSigner, VaultTokenClaims};
pub use leader::LeaderElection;
pub use ratelimit::{categories, limits, RateLimit, RateLimitResult, RateLimiter};
pub use repository::{
    AuthorizationCodeRepository, ClientCertificateRepository, ClientRepository,
    JtiReplayProtectionRepository, OrganizationInvitationRepository, OrganizationMemberRepository,
    OrganizationRepository, OrganizationTeamMemberRepository, OrganizationTeamPermissionRepository,
    OrganizationTeamRepository, UserEmailRepository, UserEmailVerificationTokenRepository,
    UserPasswordResetTokenRepository, UserRepository, UserSessionRepository,
    VaultRefreshTokenRepository, VaultRepository, VaultTeamGrantRepository,
    VaultUserGrantRepository,
};
