use std::collections::HashMap;

use axum::{
    RequestExt,
    extract::{Path, Request, State},
    middleware::Next,
    response::Response,
};
use inferadb_control_core::{OrganizationMemberRepository, OrganizationRepository};
use inferadb_control_types::{
    Error as CoreError,
    entities::{OrganizationMember, OrganizationRole},
};

use crate::{
    handlers::auth::{ApiError, AppState},
    middleware::SessionContext,
};

/// Context for organization-scoped requests
#[derive(Debug, Clone)]
pub struct OrganizationContext {
    /// Organization ID from the path
    pub organization_id: i64,
    /// User's membership in the organization
    pub member: OrganizationMember,
}

impl OrganizationContext {
    /// Check if the user has at least the specified role
    pub fn has_permission(&self, required: OrganizationRole) -> bool {
        self.member.has_permission(required)
    }

    /// Check if the user is a member (any role)
    pub fn is_member(&self) -> bool {
        self.has_permission(OrganizationRole::Member)
    }

    /// Check if the user is an admin or owner
    pub fn is_admin_or_owner(&self) -> bool {
        self.has_permission(OrganizationRole::Admin)
    }

    /// Check if the user is an owner
    pub fn is_owner(&self) -> bool {
        self.has_permission(OrganizationRole::Owner)
    }
}

/// Organization authorization middleware
///
/// Extracts organization ID from the `{org}` path parameter, validates user is a member,
/// and attaches organization context to the request.
///
/// This middleware must be applied as a `route_layer` (not `layer`) so that
/// axum's path parameters are available after route matching.
pub async fn require_organization_member(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract org_id from the named {org} path parameter set by axum's router
    let Path(params): Path<HashMap<String, String>> =
        request.extract_parts().await.map_err(|_| {
            CoreError::internal(
                "Organization middleware applied to route without path parameters".to_string(),
            )
        })?;

    let org_id = params
        .get("org")
        .ok_or_else(|| {
            CoreError::internal(
                "Organization middleware applied to route without {org} parameter".to_string(),
            )
        })?
        .parse::<i64>()
        .map_err(|_| CoreError::validation("Invalid organization ID in path".to_string()))?;

    // Get session context (should be set by require_session middleware)
    let session_ctx = request.extensions().get::<SessionContext>().cloned().ok_or_else(|| {
        CoreError::internal("Session context not found in request extensions".to_string())
    })?;

    // Check if user is a member of the organization
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let member = member_repo
        .get_by_org_and_user(org_id, session_ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::authz("You are not a member of this organization".to_string()))?;

    // Verify organization exists and is not deleted
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    let org = org_repo
        .get(org_id)
        .await?
        .ok_or_else(|| CoreError::not_found("Organization not found".to_string()))?;

    if org.is_deleted() {
        return Err(CoreError::not_found("Organization not found".to_string()).into());
    }

    // Block access to suspended organizations
    // Allow owners through for suspend/resume endpoints so they can manage suspension state
    if org.is_suspended() {
        let is_owner = member.has_permission(OrganizationRole::Owner);
        let path = request.uri().path().to_string();
        let is_suspension_mgmt = path.ends_with("/suspend") || path.ends_with("/resume");

        if !is_owner || !is_suspension_mgmt {
            return Err(CoreError::authz("Organization is suspended".to_string()).into());
        }
    }

    // Attach organization context to request extensions
    request.extensions_mut().insert(OrganizationContext { organization_id: org_id, member });

    Ok(next.run(request).await)
}

/// Require user to be a member of the organization
///
/// Returns the organization context if the user is a member, otherwise returns an error.
pub fn require_member(org_ctx: &OrganizationContext) -> Result<(), ApiError> {
    if !org_ctx.is_member() {
        return Err(CoreError::authz("Member role required".to_string()).into());
    }
    Ok(())
}

/// Require user to be an admin or owner of the organization
///
/// Returns the organization context if the user has admin permissions, otherwise returns an error.
pub fn require_admin_or_owner(org_ctx: &OrganizationContext) -> Result<(), ApiError> {
    if !org_ctx.is_admin_or_owner() {
        return Err(CoreError::authz("Admin or owner role required".to_string()).into());
    }
    Ok(())
}

/// Require user to be an owner of the organization
///
/// Returns the organization context if the user is an owner, otherwise returns an error.
pub fn require_owner(org_ctx: &OrganizationContext) -> Result<(), ApiError> {
    if !org_ctx.is_owner() {
        return Err(CoreError::authz("Owner role required".to_string()).into());
    }
    Ok(())
}
