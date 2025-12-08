use inferadb_control_core::{
    Error as CoreError, OrganizationPermission, OrganizationRole, OrganizationTeamMemberRepository,
    OrganizationTeamPermissionRepository,
};

use crate::{AppState, handlers::auth::ApiError, middleware::OrganizationContext};

/// Check if the current user has the specified permission in the organization
///
/// Permission resolution rules:
/// - OWNER: has all permissions automatically
/// - ADMIN: has all permissions except ORG_PERM_OWNER_ACTIONS
/// - MEMBER: check team permissions
pub async fn has_organization_permission(
    state: &AppState,
    org_ctx: &OrganizationContext,
    required_permission: OrganizationPermission,
) -> Result<bool, ApiError> {
    // Check direct organization role permissions
    match org_ctx.member.role {
        OrganizationRole::Owner => {
            // Owners have all permissions
            return Ok(true);
        },
        OrganizationRole::Admin => {
            // Admins have all permissions except owner actions
            if required_permission == OrganizationPermission::OrgPermOwnerActions {
                return Ok(false);
            }
            return Ok(true);
        },
        OrganizationRole::Member => {
            // Members need to check team permissions
        },
    }

    // Get user's team memberships
    let team_member_repo = OrganizationTeamMemberRepository::new((*state.storage).clone());
    let memberships = team_member_repo.list_by_user(org_ctx.member.user_id).await?;

    // For each team, check if the team has the required permission
    let team_permission_repo = OrganizationTeamPermissionRepository::new((*state.storage).clone());

    for membership in memberships {
        let team_permissions = team_permission_repo.list_by_team(membership.team_id).await?;

        for perm in team_permissions {
            // Check if this permission grants the required permission
            if perm.permission.grants(required_permission) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Require the user to have a specific organization permission
pub async fn require_organization_permission(
    state: &AppState,
    org_ctx: &OrganizationContext,
    required_permission: OrganizationPermission,
) -> Result<(), ApiError> {
    if !has_organization_permission(state, org_ctx, required_permission).await? {
        return Err(CoreError::Authz(format!(
            "Missing required permission: {:?}",
            required_permission
        ))
        .into());
    }
    Ok(())
}

/// Get all effective permissions for the current user in the organization
///
/// This returns the union of all permissions the user has, either directly
/// through their role or through team memberships.
pub async fn get_user_permissions(
    state: &AppState,
    org_ctx: &OrganizationContext,
) -> Result<Vec<OrganizationPermission>, ApiError> {
    let mut permissions = Vec::new();

    // Add role-based permissions
    match org_ctx.member.role {
        OrganizationRole::Owner => {
            // Owners have all permissions
            use OrganizationPermission::*;
            permissions.extend_from_slice(&[
                OrgPermClientCreate,
                OrgPermClientRead,
                OrgPermClientRevoke,
                OrgPermClientDelete,
                OrgPermClientManage,
                OrgPermVaultCreate,
                OrgPermVaultDelete,
                OrgPermTeamCreate,
                OrgPermTeamDelete,
                OrgPermTeamManageMembers,
                OrgPermInviteUsers,
                OrgPermRevokeInvitations,
                OrgPermOwnerActions,
            ]);
            return Ok(permissions);
        },
        OrganizationRole::Admin => {
            // Admins have all permissions except owner actions
            use OrganizationPermission::*;
            permissions.extend_from_slice(&[
                OrgPermClientCreate,
                OrgPermClientRead,
                OrgPermClientRevoke,
                OrgPermClientDelete,
                OrgPermClientManage,
                OrgPermVaultCreate,
                OrgPermVaultDelete,
                OrgPermTeamCreate,
                OrgPermTeamDelete,
                OrgPermTeamManageMembers,
                OrgPermInviteUsers,
                OrgPermRevokeInvitations,
            ]);
            return Ok(permissions);
        },
        OrganizationRole::Member => {
            // Members get permissions from teams
        },
    }

    // Get user's team memberships
    let team_member_repo = OrganizationTeamMemberRepository::new((*state.storage).clone());
    let memberships = team_member_repo.list_by_user(org_ctx.member.user_id).await?;

    // Collect all unique permissions from all teams
    let team_permission_repo = OrganizationTeamPermissionRepository::new((*state.storage).clone());
    let mut seen = std::collections::HashSet::new();

    for membership in memberships {
        let team_permissions = team_permission_repo.list_by_team(membership.team_id).await?;

        for perm in team_permissions {
            // Add the permission and all permissions it grants
            for granted_perm in perm.permission.expanded() {
                if seen.insert(granted_perm) {
                    permissions.push(granted_perm);
                }
            }
        }
    }

    Ok(permissions)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use inferadb_control_core::{
        OrganizationMember, OrganizationPermission, OrganizationRole, OrganizationTeam,
        OrganizationTeamMember, OrganizationTeamMemberRepository, OrganizationTeamPermission,
        OrganizationTeamPermissionRepository, OrganizationTeamRepository,
    };
    use inferadb_control_storage::Backend;

    use super::*;
    use crate::{handlers::auth::AppState, middleware::OrganizationContext};

    #[tokio::test]
    async fn test_owner_has_all_permissions() {
        use inferadb_control_storage::MemoryBackend;
        let backend = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = AppState::new_test(backend);

        let org_ctx = OrganizationContext {
            organization_id: 1,
            member: OrganizationMember::new(1, 1, 100, OrganizationRole::Owner),
        };

        // Owner should have all permissions
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientCreate
            )
            .await
            .unwrap()
        );
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermOwnerActions
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_admin_no_owner_actions() {
        use inferadb_control_storage::MemoryBackend;
        let backend = Arc::new(Backend::Memory(MemoryBackend::new()));
        let state = AppState::new_test(backend);

        let org_ctx = OrganizationContext {
            organization_id: 1,
            member: OrganizationMember::new(1, 1, 100, OrganizationRole::Admin),
        };

        // Admin should have most permissions
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientCreate
            )
            .await
            .unwrap()
        );

        // But not owner actions
        assert!(
            !has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermOwnerActions
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_member_team_permissions() {
        use inferadb_control_storage::MemoryBackend;
        let memory = MemoryBackend::new();
        let backend = Arc::new(Backend::Memory(memory.clone()));
        let state = AppState::new_test(backend);

        let org_ctx = OrganizationContext {
            organization_id: 1,
            member: OrganizationMember::new(1, 1, 100, OrganizationRole::Member),
        };

        // Create a team with a permission
        let team_repo = OrganizationTeamRepository::new(memory.clone());
        let team = OrganizationTeam::new(1, 1, "Test Team".to_string()).unwrap();
        team_repo.create(team).await.unwrap();

        // Add user to team
        let member_repo = OrganizationTeamMemberRepository::new(memory.clone());
        let member = OrganizationTeamMember::new(1, 1, 100, false);
        member_repo.create(member).await.unwrap();

        // Grant permission to team
        let perm_repo = OrganizationTeamPermissionRepository::new(memory.clone());
        let permission =
            OrganizationTeamPermission::new(1, 1, OrganizationPermission::OrgPermClientCreate, 999);
        perm_repo.create(permission).await.unwrap();

        // Member should now have the permission
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientCreate
            )
            .await
            .unwrap()
        );

        // But not other permissions
        assert!(
            !has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermVaultCreate
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_composite_permission() {
        use inferadb_control_storage::MemoryBackend;
        let memory = MemoryBackend::new();
        let backend = Arc::new(Backend::Memory(memory.clone()));
        let state = AppState::new_test(backend);

        let org_ctx = OrganizationContext {
            organization_id: 1,
            member: OrganizationMember::new(1, 1, 100, OrganizationRole::Member),
        };

        // Create a team with CLIENT_MANAGE permission
        let team_repo = OrganizationTeamRepository::new(memory.clone());
        let team = OrganizationTeam::new(1, 1, "Test Team".to_string()).unwrap();
        team_repo.create(team).await.unwrap();

        let member_repo = OrganizationTeamMemberRepository::new(memory.clone());
        let member = OrganizationTeamMember::new(1, 1, 100, false);
        member_repo.create(member).await.unwrap();

        let perm_repo = OrganizationTeamPermissionRepository::new(memory.clone());
        let permission =
            OrganizationTeamPermission::new(1, 1, OrganizationPermission::OrgPermClientManage, 999);
        perm_repo.create(permission).await.unwrap();

        // CLIENT_MANAGE should grant all client permissions
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientCreate
            )
            .await
            .unwrap()
        );
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientRead
            )
            .await
            .unwrap()
        );
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientRevoke
            )
            .await
            .unwrap()
        );
        assert!(
            has_organization_permission(
                &state,
                &org_ctx,
                OrganizationPermission::OrgPermClientDelete
            )
            .await
            .unwrap()
        );
    }
}
