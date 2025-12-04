// Request/Response DTOs for Management API

pub mod audit_logs;
pub mod auth;
pub mod cli_auth;
pub mod clients;
pub mod emails;
pub mod organizations;
pub mod sessions;
pub mod teams;
pub mod tokens;
pub mod users;
pub mod vaults;

pub use audit_logs::{
    AuditLogInfo, CreateAuditLogRequest, CreateAuditLogResponse, ListAuditLogsQuery,
    ListAuditLogsResponse,
};
pub use auth::{
    ErrorResponse, LoginRequest, LoginResponse, LogoutResponse, PasswordResetConfirmRequest,
    PasswordResetConfirmResponse, PasswordResetRequestRequest, PasswordResetRequestResponse,
    RegisterRequest, RegisterResponse, VerifyEmailRequest as AuthVerifyEmailRequest,
    VerifyEmailResponse as AuthVerifyEmailResponse,
};
pub use cli_auth::{CliAuthorizeRequest, CliAuthorizeResponse, CliTokenRequest, CliTokenResponse};
pub use clients::{
    CertificateDetail, CertificateInfo, ClientDetail, ClientInfo, CreateCertificateRequest,
    CreateCertificateResponse, CreateClientRequest, CreateClientResponse,
    DeleteCertificateResponse, DeleteClientResponse, GetCertificateResponse, GetClientResponse,
    ListCertificatesResponse, ListClientsResponse, RevokeCertificateResponse, UpdateClientRequest,
    UpdateClientResponse,
};
pub use emails::{
    AddEmailRequest, AddEmailResponse, EmailOperationResponse, ListEmailsResponse,
    ResendVerificationResponse, SetPrimaryEmailRequest, UserEmailInfo, VerifyEmailRequest,
    VerifyEmailResponse,
};
pub use organizations::{
    AcceptInvitationRequest, AcceptInvitationResponse, CreateInvitationRequest,
    CreateInvitationResponse, CreateOrganizationRequest, CreateOrganizationResponse,
    DeleteInvitationResponse, DeleteOrganizationResponse, GetOrganizationResponse,
    InvitationResponse, ListInvitationsResponse, ListMembersResponse, ListOrganizationsResponse,
    OrganizationMemberResponse, OrganizationResponse, OrganizationServerResponse,
    OrganizationStatus, RemoveMemberResponse, ResumeOrganizationResponse,
    SuspendOrganizationResponse, TransferOwnershipRequest, TransferOwnershipResponse,
    UpdateMemberRoleRequest, UpdateMemberRoleResponse, UpdateOrganizationRequest,
    UpdateOrganizationResponse,
};
pub use sessions::{ListSessionsResponse, RevokeSessionResponse, SessionInfo};
pub use teams::{
    AddTeamMemberRequest, AddTeamMemberResponse, CreateTeamRequest, CreateTeamResponse,
    DeleteTeamResponse, GrantTeamPermissionRequest, GrantTeamPermissionResponse,
    ListTeamMembersResponse, ListTeamPermissionsResponse, ListTeamsResponse,
    RemoveTeamMemberResponse, RevokeTeamPermissionResponse, TeamInfo, TeamMemberInfo,
    TeamMemberResponse, TeamPermissionInfo, TeamPermissionResponse, TeamResponse,
    UpdateTeamMemberRequest, UpdateTeamMemberResponse, UpdateTeamRequest, UpdateTeamResponse,
};
pub use tokens::{
    ClientAssertionRequest, ClientAssertionResponse, GenerateVaultTokenRequest,
    GenerateVaultTokenResponse, RefreshTokenRequest, RefreshTokenResponse, RevokeTokensResponse,
};
pub use users::{
    DeleteUserResponse, GetUserProfileResponse, UpdateProfileRequest, UpdateProfileResponse,
    UserProfile,
};
pub use vaults::{
    CreateTeamGrantRequest, CreateTeamGrantResponse, CreateUserGrantRequest,
    CreateUserGrantResponse, CreateVaultRequest, CreateVaultResponse, DeleteTeamGrantResponse,
    DeleteUserGrantResponse, DeleteVaultResponse, ListTeamGrantsResponse, ListUserGrantsResponse,
    ListVaultsResponse, TeamGrantInfo, TeamGrantResponse, UpdateTeamGrantRequest,
    UpdateTeamGrantResponse, UpdateUserGrantRequest, UpdateUserGrantResponse, UpdateVaultRequest,
    UpdateVaultResponse, UserGrantInfo, UserGrantResponse, VaultDetail, VaultInfo, VaultResponse,
};
