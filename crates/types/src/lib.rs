//! # InferaDB Control Types
//!
//! Shared type definitions for InferaDB Control.
//!
//! This crate provides all core types used across the Control ecosystem,
//! ensuring a single source of truth and preventing circular dependencies.
//!
//! ## Builder Patterns
//!
//! All entity types in this crate use the [`bon`](https://docs.rs/bon) crate for builder
//! pattern generation. There are two patterns used:
//!
//! ### Derived Builders (Struct-level)
//!
//! Types without validation use `#[derive(bon::Builder)]` directly on the struct.
//! Optional fields get `.maybe_*()` methods for passing `Option<T>` values:
//!
//! ```ignore
//! use inferadb_control_types::entities::AuditLog;
//! use inferadb_control_types::entities::{AuditEventType, AuditResourceType};
//!
//! // Required fields use direct setters, optional fields use maybe_* methods
//! let log = AuditLog::builder()
//!     .event_type(AuditEventType::UserLogin)
//!     .maybe_organization_id(Some(123))
//!     .maybe_user_id(Some(456))
//!     .build();
//! ```
//!
//! ### Fallible Builders (Constructor-level)
//!
//! Types with validation use `#[builder]` on the `new()` function. These return
//! `Result<Self>` and require `.build()?.unwrap()` or error handling:
//!
//! ```ignore
//! use inferadb_control_types::entities::User;
//!
//! // Fallible builder returns Result
//! let user = User::builder()
//!     .id(12345)
//!     .name("alice".to_string())
//!     .maybe_password_hash(Some("hash".to_string()))
//!     .build()
//!     .expect("valid user");
//! ```
//!
//! ### Common Patterns
//!
//! - **Required fields**: Call `.field(value)` - build fails at compile time if missing
//! - **Optional fields**: Either omit (defaults to `None`) or use `.maybe_field(Some(value))`
//! - **String fields**: Pass `&str` directly when `#[builder(on(String, into))]` is set
//! - **Default values**: Some fields like `id` and `created_at` have defaults via
//!   `#[builder(default = expr)]`

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

// ============================================================================
// ID Generation
// ============================================================================

pub mod id;

pub use id::IdGenerator;

// ============================================================================
// Error Types
// ============================================================================

pub mod error;

pub use error::{Error, Result};

// ============================================================================
// Control Identity (for webhook authentication)
// ============================================================================

pub mod identity;

pub use identity::{ControlIdentity, SharedControlIdentity};

// ============================================================================
// Pagination Types
// ============================================================================

/// Pagination metadata for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    /// Total number of items (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    /// Number of items in this page
    pub count: usize,

    /// Current offset
    pub offset: usize,

    /// Items per page
    pub limit: usize,

    /// Whether there are more items
    pub has_more: bool,
}

impl PaginationMeta {
    /// Create pagination metadata from total count
    pub fn from_total(total: usize, offset: usize, limit: usize, count: usize) -> Self {
        Self { total: Some(total), count, offset, limit, has_more: offset + count < total }
    }

    /// Create pagination metadata without total count (streaming pagination)
    pub fn from_count(count: usize, offset: usize, limit: usize) -> Self {
        // If we got exactly limit items, there might be more
        let has_more = count == limit;
        Self { total: None, count, offset, limit, has_more }
    }
}

// ============================================================================
// Entity Types
// ============================================================================

pub mod entities;

pub use entities::{
    AuditEventType, AuditLog, AuditResourceType, AuthorizationCode, Client, ClientCertificate,
    Organization, OrganizationInvitation, OrganizationMember, OrganizationPermission,
    OrganizationRole, OrganizationTeam, OrganizationTeamMember, OrganizationTeamPermission,
    OrganizationTier, PasskeyCredential, SessionType, User, UserEmail, UserEmailVerificationToken,
    UserPasswordResetToken, UserSession, Vault, VaultRefreshToken, VaultRole, VaultSyncStatus,
    VaultTeamGrant, VaultUserGrant,
};

// ============================================================================
// Request/Response Types
// ============================================================================

pub mod dto;

pub use dto::{
    // Organizations
    AcceptInvitationRequest,
    AcceptInvitationResponse,
    // Emails
    AddEmailRequest,
    AddEmailResponse,
    // Teams
    AddTeamMemberRequest,
    AddTeamMemberResponse,
    // Audit Logs
    AuditLogInfo,
    // Auth
    AuthVerifyEmailRequest,
    AuthVerifyEmailResponse,
    // Clients
    CertificateDetail,
    CertificateInfo,
    // CLI Auth
    CliAuthorizeRequest,
    CliAuthorizeResponse,
    CliTokenRequest,
    CliTokenResponse,
    // Tokens
    ClientAssertionRequest,
    ClientAssertionResponse,
    ClientDetail,
    ClientInfo,
    CreateAuditLogRequest,
    CreateAuditLogResponse,
    CreateCertificateRequest,
    CreateCertificateResponse,
    CreateClientRequest,
    CreateClientResponse,
    CreateInvitationRequest,
    CreateInvitationResponse,
    CreateOrganizationRequest,
    CreateOrganizationResponse,
    // Vaults
    CreateTeamGrantRequest,
    CreateTeamGrantResponse,
    CreateTeamRequest,
    CreateTeamResponse,
    CreateUserGrantRequest,
    CreateUserGrantResponse,
    CreateVaultRequest,
    CreateVaultResponse,
    DeleteCertificateResponse,
    DeleteClientResponse,
    DeleteInvitationResponse,
    DeleteOrganizationResponse,
    DeleteTeamGrantResponse,
    DeleteTeamResponse,
    DeleteUserGrantResponse,
    // Users
    DeleteUserResponse,
    DeleteVaultResponse,
    EmailOperationResponse,

    ErrorResponse,
    GenerateVaultTokenRequest,
    GenerateVaultTokenResponse,
    GetCertificateResponse,
    GetClientResponse,
    GetOrganizationResponse,
    GetUserProfileResponse,
    GrantTeamPermissionRequest,
    GrantTeamPermissionResponse,
    InvitationResponse,
    ListAuditLogsQuery,
    ListAuditLogsResponse,
    ListCertificatesResponse,
    ListClientsResponse,
    ListEmailsResponse,
    ListInvitationsResponse,
    ListMembersResponse,
    ListOrganizationsResponse,
    // Sessions
    ListSessionsResponse,
    ListTeamGrantsResponse,
    ListTeamMembersResponse,
    ListTeamPermissionsResponse,
    ListTeamsResponse,
    ListUserGrantsResponse,
    ListVaultsResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    OrganizationMemberResponse,
    OrganizationResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetRequestRequest,
    PasswordResetRequestResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    RemoveMemberResponse,
    RemoveTeamMemberResponse,
    ResendVerificationResponse,
    RevokeCertificateResponse,
    RevokeSessionResponse,
    RevokeTeamPermissionResponse,
    RevokeTokensResponse,
    SessionInfo,
    SetPrimaryEmailRequest,
    TeamGrantInfo,
    TeamGrantResponse,
    TeamInfo,
    TeamMemberInfo,
    TeamMemberResponse,
    TeamPermissionInfo,
    TeamPermissionResponse,
    TeamResponse,
    TransferOwnershipRequest,
    TransferOwnershipResponse,
    UpdateClientRequest,
    UpdateClientResponse,
    UpdateMemberRoleRequest,
    UpdateMemberRoleResponse,
    UpdateOrganizationRequest,
    UpdateOrganizationResponse,
    UpdateProfileRequest,
    UpdateProfileResponse,
    UpdateTeamGrantRequest,
    UpdateTeamGrantResponse,
    UpdateTeamMemberRequest,
    UpdateTeamMemberResponse,
    UpdateTeamRequest,
    UpdateTeamResponse,
    UpdateUserGrantRequest,
    UpdateUserGrantResponse,
    UpdateVaultRequest,
    UpdateVaultResponse,
    UserEmailInfo,
    UserGrantInfo,
    UserGrantResponse,
    UserProfile,
    VaultDetail,
    VaultInfo,
    VaultResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
};
