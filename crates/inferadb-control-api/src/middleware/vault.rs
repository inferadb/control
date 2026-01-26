use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use inferadb_control_core::{VaultRepository, VaultUserGrantRepository};
use inferadb_control_types::{Error as CoreError, entities::VaultRole};

use crate::{
    handlers::auth::{ApiError, AppState},
    middleware::OrganizationContext,
};

/// Context for vault-scoped requests
#[derive(Debug, Clone)]
pub struct VaultContext {
    /// Vault ID from the path
    pub vault_id: i64,
    /// Organization ID (from organization context)
    pub organization_id: i64,
    /// User's role in the vault (resolved from grants)
    pub role: VaultRole,
}

impl VaultContext {
    /// Check if the user has at least the specified role
    pub fn has_permission(&self, required: VaultRole) -> bool {
        self.role >= required
    }

    /// Check if the user is a reader or higher
    pub fn is_reader(&self) -> bool {
        self.has_permission(VaultRole::Reader)
    }

    /// Check if the user is a writer or higher
    pub fn is_writer(&self) -> bool {
        self.has_permission(VaultRole::Writer)
    }

    /// Check if the user is a manager or higher
    pub fn is_manager(&self) -> bool {
        self.has_permission(VaultRole::Manager)
    }

    /// Check if the user is an admin
    pub fn is_admin(&self) -> bool {
        self.has_permission(VaultRole::Admin)
    }
}

/// Vault authorization middleware
///
/// Extracts vault ID from path, resolves user's vault role via grants,
/// and attaches vault context to the request.
///
/// This middleware should be applied to routes with `{vault}` path parameter.
/// It requires OrganizationContext to be set by require_organization_member middleware.
pub async fn require_vault_access(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Get organization context (should be set by require_organization_member middleware)
    let org_ctx = request.extensions().get::<OrganizationContext>().cloned().ok_or_else(|| {
        CoreError::internal("Organization context not found in request extensions".to_string())
    })?;

    // Extract vault_id from the URI path manually
    // Routes are of the form /control/v1/organizations/{org}/vaults/{vault}/... where {vault} is
    // the 7th segment
    let uri_path = request.uri().path();
    let segments: Vec<&str> = uri_path.split('/').collect();

    let vault_id = if segments.len() >= 7
        && segments[1] == "control"
        && segments[2] == "v1"
        && segments[3] == "organizations"
        && segments[5] == "vaults"
    {
        segments[6]
            .parse::<i64>()
            .map_err(|_| CoreError::validation("Invalid vault ID in path".to_string()))?
    } else {
        return Err(
            CoreError::internal("Vault middleware applied to invalid route".to_string()).into()
        );
    };

    // Verify vault exists and belongs to the organization
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault = vault_repo
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::not_found("Vault not found".to_string()))?;

    if vault.is_deleted() {
        return Err(CoreError::not_found("Vault not found".to_string()).into());
    }

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::not_found("Vault not found".to_string()).into());
    }

    // Resolve user's vault role
    let role = get_user_vault_role(&state, vault_id, org_ctx.member.user_id).await?;

    let role =
        role.ok_or_else(|| CoreError::authz("You do not have access to this vault".to_string()))?;

    // Attach vault context to request extensions
    request.extensions_mut().insert(VaultContext {
        vault_id,
        organization_id: org_ctx.organization_id,
        role,
    });

    Ok(next.run(request).await)
}

/// Get user's effective vault role by resolving user grants and team grants
///
/// Returns the highest role the user has, either directly or through team membership.
/// Returns None if the user has no access to the vault.
pub async fn get_user_vault_role(
    state: &AppState,
    vault_id: i64,
    user_id: i64,
) -> Result<Option<VaultRole>, ApiError> {
    use inferadb_control_core::{OrganizationTeamMemberRepository, VaultTeamGrantRepository};

    // Check direct user grant first
    let user_grant_repo = VaultUserGrantRepository::new((*state.storage).clone());
    if let Some(grant) = user_grant_repo.get_by_vault_and_user(vault_id, user_id).await? {
        return Ok(Some(grant.role));
    }

    // Check team grants
    let team_member_repo = OrganizationTeamMemberRepository::new((*state.storage).clone());
    let team_grant_repo = VaultTeamGrantRepository::new((*state.storage).clone());

    // Get all teams the user is a member of
    let user_teams = team_member_repo.list_by_user(user_id).await?;

    // Find the highest role from team grants
    let mut highest_role: Option<VaultRole> = None;

    for membership in user_teams {
        if let Some(team_grant) =
            team_grant_repo.get_by_vault_and_team(vault_id, membership.team_id).await?
        {
            match highest_role {
                None => highest_role = Some(team_grant.role),
                Some(current_role) => {
                    if team_grant.role > current_role {
                        highest_role = Some(team_grant.role);
                    }
                },
            }
        }
    }

    Ok(highest_role)
}

/// Require user to be a reader or higher
pub fn require_reader(vault_ctx: &VaultContext) -> Result<(), ApiError> {
    if !vault_ctx.is_reader() {
        return Err(CoreError::authz("Reader role or higher required".to_string()).into());
    }
    Ok(())
}

/// Require user to be a writer or higher
pub fn require_writer(vault_ctx: &VaultContext) -> Result<(), ApiError> {
    if !vault_ctx.is_writer() {
        return Err(CoreError::authz("Writer role or higher required".to_string()).into());
    }
    Ok(())
}

/// Require user to be a manager or higher
pub fn require_manager(vault_ctx: &VaultContext) -> Result<(), ApiError> {
    if !vault_ctx.is_manager() {
        return Err(CoreError::authz("Manager role or higher required".to_string()).into());
    }
    Ok(())
}

/// Require user to be an admin
pub fn require_admin(vault_ctx: &VaultContext) -> Result<(), ApiError> {
    if !vault_ctx.is_admin() {
        return Err(CoreError::authz("Admin role required".to_string()).into());
    }
    Ok(())
}
