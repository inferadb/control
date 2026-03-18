//! Team and team member management handlers.
//!
//! All operations delegate to Ledger SDK via the service layer.
//! Team state (members, roles) is owned by Ledger.

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use inferadb_control_core::service;
use inferadb_control_types::Error as CoreError;
use inferadb_ledger_sdk::{TeamMemberRole, TeamSlug};
use inferadb_ledger_types::{OrganizationSlug, UserSlug};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::auth::{AppState, Result},
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

/// Request body for adding a team member.
#[derive(Debug, Deserialize)]
pub struct AddTeamMemberRequest {
    pub user: u64,
    #[serde(default = "default_member_role")]
    pub role: String,
}

fn default_member_role() -> String {
    "member".to_string()
}

/// Request body for updating a team member's role.
#[derive(Debug, Deserialize)]
pub struct UpdateTeamMemberRequest {
    pub role: String,
}

/// Pagination query for cursor-based pagination.
#[derive(Debug, Deserialize)]
pub struct CursorPaginationQuery {
    /// Number of items per page (default 50, max 100).
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Opaque cursor for the next page (base64-encoded).
    pub page_token: Option<String>,
}

fn default_page_size() -> u32 {
    50
}

impl CursorPaginationQuery {
    fn validated_page_size(&self) -> u32 {
        self.page_size.clamp(1, 100)
    }

    fn decoded_page_token(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        self.page_token
            .as_deref()
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
    }
}

// ── Response Types ────────────────────────────────────────────────────

/// Team member response.
#[derive(Debug, Serialize)]
pub struct TeamMemberResponse {
    pub user: u64,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
}

/// Team summary response.
#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub slug: u64,
    pub organization: u64,
    pub name: String,
    pub members: Vec<TeamMemberResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
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

/// List of team members.
#[derive(Debug, Serialize)]
pub struct ListTeamMembersResponse {
    pub members: Vec<TeamMemberResponse>,
}

/// Simple message response.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ── Helpers ───────────────────────────────────────────────────────────

fn encode_page_token(token: &Option<Vec<u8>>) -> Option<String> {
    use base64::Engine;
    token.as_ref().map(|t| base64::engine::general_purpose::STANDARD.encode(t))
}

fn system_time_to_rfc3339(t: &Option<std::time::SystemTime>) -> Option<String> {
    t.map(|st| DateTime::<Utc>::from(st).to_rfc3339())
}

fn parse_team_member_role(s: &str) -> std::result::Result<TeamMemberRole, CoreError> {
    match s.to_lowercase().as_str() {
        "manager" => Ok(TeamMemberRole::Manager),
        "member" => Ok(TeamMemberRole::Member),
        _ => {
            Err(CoreError::validation(format!("Invalid role '{s}'. Must be 'manager' or 'member'")))
        },
    }
}

fn team_member_to_response(info: &inferadb_ledger_sdk::TeamMemberInfo) -> TeamMemberResponse {
    TeamMemberResponse {
        user: info.user.value(),
        role: format!("{:?}", info.role),
        joined_at: system_time_to_rfc3339(&info.joined_at),
    }
}

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

/// POST /v1/organizations/:org/teams
///
/// Creates a new team within the organization.
pub async fn create_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Json(payload): Json<CreateTeamRequest>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let info = service::team::create_team(
        ledger,
        OrganizationSlug::new(org),
        &payload.name,
        claims.user_slug,
    )
    .await?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// GET /v1/organizations/:org/teams
///
/// Lists teams in the organization with cursor-based pagination.
pub async fn list_teams(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path(org): Path<u64>,
    Query(pagination): Query<CursorPaginationQuery>,
) -> Result<Json<ListTeamsResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let (teams, next_token) = service::team::list_teams(
        ledger,
        OrganizationSlug::new(org),
        claims.user_slug,
        pagination.validated_page_size(),
        pagination.decoded_page_token(),
    )
    .await?;

    Ok(Json(ListTeamsResponse {
        teams: teams.iter().map(team_info_to_response).collect(),
        next_page_token: encode_page_token(&next_token),
    }))
}

/// GET /v1/organizations/:org/teams/:team
///
/// Returns details of a specific team. Caller must have visibility.
pub async fn get_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let info = service::team::get_team(ledger, TeamSlug::new(team), claims.user_slug).await?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// PATCH /v1/organizations/:org/teams/:team
///
/// Updates team details. Ledger enforces role requirements.
pub async fn update_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
    Json(payload): Json<UpdateTeamRequest>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let info = service::team::update_team(
        ledger,
        TeamSlug::new(team),
        claims.user_slug,
        payload.name.as_deref(),
    )
    .await?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// DELETE /v1/organizations/:org/teams/:team
///
/// Deletes a team. Optionally moves members to another team.
/// Ledger enforces permission checks.
pub async fn delete_team(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
    payload: Option<Json<DeleteTeamRequest>>,
) -> Result<Json<MessageResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let move_members_to = payload.and_then(|p| p.0.move_members_to.map(TeamSlug::new));

    service::team::delete_team(ledger, TeamSlug::new(team), claims.user_slug, move_members_to)
        .await?;

    Ok(Json(MessageResponse { message: "Team deleted successfully".to_string() }))
}

// ── Team Member Handlers ──────────────────────────────────────────────

/// POST /v1/organizations/:org/teams/:team/members
///
/// Adds a member to the team. Ledger enforces permission checks.
pub async fn add_team_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
    Json(payload): Json<AddTeamMemberRequest>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let role = parse_team_member_role(&payload.role)?;

    let info = service::team::add_team_member(
        ledger,
        TeamSlug::new(team),
        UserSlug::new(payload.user),
        role,
        claims.user_slug,
    )
    .await?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// GET /v1/organizations/:org/teams/:team/members
///
/// Lists members of a team by fetching team info and extracting members.
pub async fn list_team_members(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team)): Path<(u64, u64)>,
) -> Result<Json<ListTeamMembersResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let info = service::team::get_team(ledger, TeamSlug::new(team), claims.user_slug).await?;

    Ok(Json(ListTeamMembersResponse {
        members: info.members.iter().map(team_member_to_response).collect(),
    }))
}

/// PATCH /v1/organizations/:org/teams/:team/members/:member
///
/// Updates a team member's role. Implemented as remove + add with the new role.
pub async fn update_team_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team, member)): Path<(u64, u64, u64)>,
    Json(payload): Json<UpdateTeamMemberRequest>,
) -> Result<Json<SingleTeamResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    let role = parse_team_member_role(&payload.role)?;
    let team_slug = TeamSlug::new(team);
    let member_slug = UserSlug::new(member);

    service::team::remove_team_member(ledger, team_slug, member_slug, claims.user_slug).await?;

    let info =
        service::team::add_team_member(ledger, team_slug, member_slug, role, claims.user_slug)
            .await?;

    Ok(Json(SingleTeamResponse { team: team_info_to_response(&info) }))
}

/// DELETE /v1/organizations/:org/teams/:team/members/:member
///
/// Removes a member from the team. Ledger enforces permission checks.
pub async fn remove_team_member(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Path((_org, team, member)): Path<(u64, u64, u64)>,
) -> Result<Json<MessageResponse>> {
    let ledger =
        state.ledger.as_ref().ok_or_else(|| CoreError::internal("Ledger client not configured"))?;

    service::team::remove_team_member(
        ledger,
        TeamSlug::new(team),
        UserSlug::new(member),
        claims.user_slug,
    )
    .await?;

    Ok(Json(MessageResponse { message: "Team member removed successfully".to_string() }))
}
