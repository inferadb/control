use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use inferadb_control_core::{
    OrganizationMemberRepository, OrganizationRepository,
    entities::{OrganizationMember, OrganizationRole},
    error::Error as CoreError,
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
/// Extracts organization ID from path, validates user is a member,
/// and attaches organization context to the request.
///
/// This middleware should be applied to routes with `{org}` path parameter.
pub async fn require_organization_member(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract org_id from the URI path manually
    // Routes are of the form /v1/organizations/{org}/... where {org} is always the 3rd segment
    let uri_path = request.uri().path();
    let segments: Vec<&str> = uri_path.split('/').collect();

    let org_id = if segments.len() >= 4 && segments[1] == "v1" && segments[2] == "organizations" {
        segments[3]
            .parse::<i64>()
            .map_err(|_| CoreError::Validation("Invalid organization ID in path".to_string()))?
    } else {
        return Err(CoreError::Internal(
            "Organization middleware applied to invalid route".to_string(),
        )
        .into());
    };

    // Get session context (should be set by require_session middleware)
    let session_ctx = request.extensions().get::<SessionContext>().cloned().ok_or_else(|| {
        CoreError::Internal("Session context not found in request extensions".to_string())
    })?;

    // Check if user is a member of the organization
    let member_repo = OrganizationMemberRepository::new((*state.storage).clone());
    let member = member_repo
        .get_by_org_and_user(org_id, session_ctx.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You are not a member of this organization".to_string()))?;

    // Verify organization exists and is not deleted
    let org_repo = OrganizationRepository::new((*state.storage).clone());
    let org = org_repo
        .get(org_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Organization not found".to_string()))?;

    if org.is_deleted() {
        return Err(CoreError::NotFound("Organization not found".to_string()).into());
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
        return Err(CoreError::Authz("Member role required".to_string()).into());
    }
    Ok(())
}

/// Require user to be an admin or owner of the organization
///
/// Returns the organization context if the user has admin permissions, otherwise returns an error.
pub fn require_admin_or_owner(org_ctx: &OrganizationContext) -> Result<(), ApiError> {
    if !org_ctx.is_admin_or_owner() {
        return Err(CoreError::Authz("Admin or owner role required".to_string()).into());
    }
    Ok(())
}

/// Require user to be an owner of the organization
///
/// Returns the organization context if the user is an owner, otherwise returns an error.
pub fn require_owner(org_ctx: &OrganizationContext) -> Result<(), ApiError> {
    if !org_ctx.is_owner() {
        return Err(CoreError::Authz("Owner role required".to_string()).into());
    }
    Ok(())
}
