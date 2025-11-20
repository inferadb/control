use crate::repository::*;
use infera_management_storage::StorageBackend;

/// Consolidated repository context to reduce boilerplate in handlers.
///
/// Instead of manually instantiating repositories in every handler:
/// ```rust,ignore
/// let org_repo = OrganizationRepository::new((*state.storage).clone());
/// let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
/// let team_repo = OrganizationTeamRepository::new((*state.storage).clone());
/// // ... repeated 10-20 times
/// ```
///
/// You can now use:
/// ```rust,ignore
/// let repos = RepositoryContext::new(state.storage.clone());
/// repos.org.create(...).await?;
/// repos.member.list(...).await?;
/// ```
pub struct RepositoryContext<S: StorageBackend> {
    // User management
    pub user: UserRepository<S>,
    pub user_email: UserEmailRepository<S>,
    pub user_session: UserSessionRepository<S>,
    pub user_email_verification_token: UserEmailVerificationTokenRepository<S>,
    pub user_password_reset_token: UserPasswordResetTokenRepository<S>,
    pub passkey_credential: PasskeyCredentialRepository<S>,

    // Organization management
    pub org: OrganizationRepository<S>,
    pub org_member: OrganizationMemberRepository<S>,
    pub org_invitation: OrganizationInvitationRepository<S>,
    pub org_team: OrganizationTeamRepository<S>,
    pub org_team_member: OrganizationTeamMemberRepository<S>,
    pub org_team_permission: OrganizationTeamPermissionRepository<S>,

    // Vault management
    pub vault: VaultRepository<S>,
    pub vault_user_grant: VaultUserGrantRepository<S>,
    pub vault_team_grant: VaultTeamGrantRepository<S>,
    pub vault_refresh_token: VaultRefreshTokenRepository<S>,

    // Client management
    pub client: ClientRepository<S>,
    pub client_certificate: ClientCertificateRepository<S>,

    // OAuth2/Authorization
    pub authorization_code: AuthorizationCodeRepository<S>,
    pub jti_replay_protection: JtiReplayProtectionRepository<S>,

    // Audit
    pub audit_log: AuditLogRepository<S>,
}

impl<S: StorageBackend + Clone> RepositoryContext<S> {
    /// Create a new repository context with all repositories initialized.
    ///
    /// # Arguments
    /// * `storage` - The storage backend to use for all repositories
    ///
    /// # Example
    /// ```rust,ignore
    /// let repos = RepositoryContext::new((*state.storage).clone());
    /// let user = repos.user.get(user_id).await?;
    /// ```
    pub fn new(storage: S) -> Self {
        Self {
            // User management
            user: UserRepository::new(storage.clone()),
            user_email: UserEmailRepository::new(storage.clone()),
            user_session: UserSessionRepository::new(storage.clone()),
            user_email_verification_token: UserEmailVerificationTokenRepository::new(
                storage.clone(),
            ),
            user_password_reset_token: UserPasswordResetTokenRepository::new(storage.clone()),
            passkey_credential: PasskeyCredentialRepository::new(storage.clone()),

            // Organization management
            org: OrganizationRepository::new(storage.clone()),
            org_member: OrganizationMemberRepository::new(storage.clone()),
            org_invitation: OrganizationInvitationRepository::new(storage.clone()),
            org_team: OrganizationTeamRepository::new(storage.clone()),
            org_team_member: OrganizationTeamMemberRepository::new(storage.clone()),
            org_team_permission: OrganizationTeamPermissionRepository::new(storage.clone()),

            // Vault management
            vault: VaultRepository::new(storage.clone()),
            vault_user_grant: VaultUserGrantRepository::new(storage.clone()),
            vault_team_grant: VaultTeamGrantRepository::new(storage.clone()),
            vault_refresh_token: VaultRefreshTokenRepository::new(storage.clone()),

            // Client management
            client: ClientRepository::new(storage.clone()),
            client_certificate: ClientCertificateRepository::new(storage.clone()),

            // OAuth2/Authorization
            authorization_code: AuthorizationCodeRepository::new(storage.clone()),
            jti_replay_protection: JtiReplayProtectionRepository::new(storage.clone()),

            // Audit
            audit_log: AuditLogRepository::new(storage),
        }
    }
}
