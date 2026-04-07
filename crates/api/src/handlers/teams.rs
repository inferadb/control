//! Team and team member management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Team state (members, roles) is owned by Ledger.

use std::time::Instant;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use inferadb_control_core::SdkResultExt;
use inferadb_ledger_sdk::{TeamMemberRole, TeamSlug};
use inferadb_ledger_types::{OrganizationSlug, UserSlug};
use serde::{Deserialize, Serialize};

use super::common::{
    CursorPaginationQuery, MessageResponse, encode_page_token, require_ledger,
    system_time_to_rfc3339, validate_name,
};
use crate::{
    handlers::state::{AppState, Result},
    middleware::UserClaims,
};

// ── Request Types ─────────────────────────────────────────────────────

/// Request body for creating a team.
#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
}

/// Request body for updating a team.
#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: Option<String>,
}

/// Request body for deleting a team.
#[derive(Debug, Deserialize)]
pub struct DeleteTeamRequest {
    /// Optional team slug to move members to before deletion.
    pub move_members_to: Option<u64>,
}

/// Team member role input.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeamRoleInput {
    /// Team management access.
    Manager,
    /// Standard team member.
    #[default]
    Member,
}

impl TeamRoleInput {
    /// Converts to the Ledger SDK role type.
    fn to_sdk_role(&self) -> TeamMemberRole {
        match self {
            Self::Manager => TeamMemberRole::Manager,
            Self::Member => TeamMemberRole::Member,
        }
    }
}

/// Request body for adding a team member.
#[derive(Debug, Deserialize)]
pub struct AddTeamMemberRequest {
    pub user: u64,
    #[serde(default)]
    pub role: TeamRoleInput,
}

/// Request body for updating a team member's role.
#[derive(Debug, Deserialize)]
pub struct UpdateTeamMemberRequest {
    pub role: TeamRoleInput,
}

// ── Response Types ────────────────────────────────────────────────────

/// Team member summary.
#[derive(Debug, Serialize)]
pub struct TeamMemberResponse {
    /// User slug identifier.
    pub user: u64,
    /// Member role (e.g., `"manager"`, `"member"`).
    pub role: String,
    /// RFC 3339 timestamp of when the user joined the team.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
}

/// Team summary with members.
#[derive(Debug, Serialize)]
pub struct TeamResponse {
    /// Team slug identifier.
    pub slug: u64,
    /// Owning organization slug.
    pub organization: u64,
    /// Team display name.
    pub name: String,
    /// Current team members.
    pub members: Vec<TeamMemberResponse>,
    /// RFC 3339 creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// RFC 3339 last-update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Wrapper for a single team.
#[derive(Debug, Serialize)]
pub struct SingleTeamResponse {
    pub team: TeamResponse,
}

/// Paginated list of teams.
#[derive(Debug, Serialize)]
pub struct ListTeamsResponse {
    pub teams: Vec<TeamResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Response containing team members.
#[derive(Debug, Serialize)]
pub struct ListTeamMembersResponse {
    pub members: Vec<TeamMemberResponse>,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Converts a Ledger [`TeamMemberInfo`](inferadb_ledger_sdk::TeamMemberInfo) to an API response.
fn team_member_to_response(info: &inferadb_ledger_sdk::TeamMemberInfo) -> TeamMemberResponse {
    TeamMemberResponse {
        user: info.user.value(),
        role: info.role.to_string(),
        joined_at: system_time_to_rfc3339(&info.joined_at),
    }
}

/// Converts a Ledger [`TeamInfo`](inferadb_ledger_sdk::TeamInfo) to an API response.
fn team_info_to_response(info: &inferadb_ledger_sdk::TeamInfo) -> TeamResponse {
    TeamResponse {
        slug: info.slug.value(),
        organization: info.organization.value(),
        name: info.name.clone(),
        members: info.members.iter().map(team_member_to_response).collect(),
        created_at: system_time_to_rfc3339(&info.created_at),
        updated_at: system_time_to_rfc3339(&info.updated_at),
    }
}

// ── Team Handlers ─────────────────────────────────────────────────────

/// POST /control/v1/organizations/{org}/teams
///
/// Creates a new team within the organization.
pub async fn create_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<CreateTeamRequest>,
) -> Result<(StatusCode, Json<SingleTeamResponse>)> {
    validate_name(&payload.name)?;
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .create_organization_team(OrganizationSlug::new(org), &payload.name, claims.user_slug)
        .await
        .map_sdk_err_instrumented("create_team", start)?;

    Ok((StatusCode::CREATED, Json(SingleTeamResponse { team: team_info_to_response(&info) })))
}

/// GET /control/v1/organizations/{org}/teams
///
/// Lists teams in the organization with cursor-based pagination.
pub async fn list_teams(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListTeamsResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let (teams, next_token) = ledger
        .list_organization_teams(
            OrganizationSlug::new(org),
            claims.user_slug,
            pagination.validated_page_size(),
            pagination.decoded_page_token(),
        )
        .await
        .map_sdk_err_instrumented("list_teams", start)?;

    Ok(Json(ListTeamsResponse {
        teams: teams.iter().map(team_info_to_response).collect(),
        next_page_token: encode_page_token(&next_token),
    }))
}

/// GET /control/v1/organizations/{org}/teams/{team}
///
/// Returns details of a specific team. Caller must have visibility.
pub async fn get_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .get_organization_team(TeamSlug::new(team), claims.user_slug)
        .await
        .map_sdk_err_instrumented("get_team", start)?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// PATCH /control/v1/organizations/{org}/teams/{team}
///
/// Updates team details. Ledger enforces role requirements.
pub async fn update_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
    Json(payload): Json<UpdateTeamRequest>,
) -> Result<Json<SingleTeamResponse>> {
    if let Some(ref name) = payload.name {
        validate_name(name)?;
    }
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .update_organization_team(TeamSlug::new(team), claims.user_slug, payload.name.as_deref())
        .await
        .map_sdk_err_instrumented("update_team", start)?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// DELETE /control/v1/organizations/{org}/teams/{team}
///
/// Deletes a team. If a request body with `move_members_to` is provided,
/// members are transferred to that team before deletion.
/// Ledger enforces permission checks.
pub async fn delete_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
    payload: Option<Json<DeleteTeamRequest>>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    let move_members_to = payload.and_then(|p| p.0.move_members_to.map(TeamSlug::new));

    let start = Instant::now();
    ledger
        .delete_organization_team(TeamSlug::new(team), claims.user_slug, move_members_to)
        .await
        .map_sdk_err_instrumented("delete_team", start)?;

    Ok(Json(MessageResponse { message: "Team deleted successfully".to_string() }))
}

// ── Team Member Handlers ──────────────────────────────────────────────

/// POST /control/v1/organizations/{org}/teams/{team}/members
///
/// Adds a member to the team. Ledger enforces permission checks.
pub async fn add_team_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
    Json(payload): Json<AddTeamMemberRequest>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger = require_ledger(&state)?;

    let role = payload.role.to_sdk_role();

    let start = Instant::now();
    let info = ledger
        .add_team_member(TeamSlug::new(team), UserSlug::new(payload.user), role, claims.user_slug)
        .await
        .map_sdk_err_instrumented("add_team_member", start)?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// GET /control/v1/organizations/{org}/teams/{team}/members
///
/// Lists members of a team.
pub async fn list_team_members(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
) -> Result<Json<ListTeamMembersResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    let info = ledger
        .get_organization_team(TeamSlug::new(team), claims.user_slug)
        .await
        .map_sdk_err_instrumented("get_team", start)?;

    Ok(Json(ListTeamMembersResponse {
        members: info.members.iter().map(team_member_to_response).collect(),
    }))
}

/// PATCH /control/v1/organizations/{org}/teams/{team}/members/{member}
///
/// Updates a team member's role.
pub async fn update_team_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team, member)): Path<(u64, u64, u64)>,
    Json(payload): Json<UpdateTeamMemberRequest>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger = require_ledger(&state)?;

    let role = payload.role.to_sdk_role();

    let start = Instant::now();
    let info = ledger
        .update_team_member_role(TeamSlug::new(team), UserSlug::new(member), role, claims.user_slug)
        .await
        .map_sdk_err_instrumented("update_team_member_role", start)?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// DELETE /control/v1/organizations/{org}/teams/{team}/members/{member}
///
/// Removes a member from the team. Ledger enforces permission checks.
pub async fn remove_team_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team, member)): Path<(u64, u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger = require_ledger(&state)?;

    let start = Instant::now();
    ledger
        .remove_team_member(TeamSlug::new(team), UserSlug::new(member), claims.user_slug)
        .await
        .map_sdk_err_instrumented("remove_team_member", start)?;

    Ok(Json(MessageResponse { message: "Team member removed successfully".to_string() }))
}
