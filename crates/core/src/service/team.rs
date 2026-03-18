//! Team management service wrapping Ledger SDK team operations.

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{LedgerClient, TeamInfo, TeamMemberRole};
use inferadb_ledger_types::{OrganizationSlug, TeamSlug, UserSlug};

use super::error::SdkResultExt;

/// Creates a new team within an organization.
pub async fn create_team(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    name: &str,
    initiator: UserSlug,
) -> Result<TeamInfo> {
    ledger.create_organization_team(organization, name, initiator).await.map_sdk_err()
}

/// Lists teams in an organization with cursor-based pagination.
pub async fn list_teams(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    caller: UserSlug,
    page_size: u32,
    page_token: Option<Vec<u8>>,
) -> Result<(Vec<TeamInfo>, Option<Vec<u8>>)> {
    ledger.list_organization_teams(organization, caller, page_size, page_token).await.map_sdk_err()
}

/// Gets team details by slug. The caller must have visibility.
pub async fn get_team(ledger: &LedgerClient, team: TeamSlug, caller: UserSlug) -> Result<TeamInfo> {
    ledger.get_organization_team(team, caller).await.map_sdk_err()
}

/// Updates a team's mutable fields. Currently supports renaming.
pub async fn update_team(
    ledger: &LedgerClient,
    team: TeamSlug,
    initiator: UserSlug,
    name: Option<&str>,
) -> Result<TeamInfo> {
    ledger.update_organization_team(team, initiator, name).await.map_sdk_err()
}

/// Deletes a team, optionally moving members to another team.
pub async fn delete_team(
    ledger: &LedgerClient,
    team: TeamSlug,
    initiator: UserSlug,
    move_members_to: Option<TeamSlug>,
) -> Result<()> {
    ledger.delete_organization_team(team, initiator, move_members_to).await.map_sdk_err()
}

/// Adds a member to a team with the specified role.
pub async fn add_team_member(
    ledger: &LedgerClient,
    team: TeamSlug,
    user: UserSlug,
    role: TeamMemberRole,
    initiator: UserSlug,
) -> Result<TeamInfo> {
    ledger.add_team_member(team, user, role, initiator).await.map_sdk_err()
}

/// Removes a member from a team.
pub async fn remove_team_member(
    ledger: &LedgerClient,
    team: TeamSlug,
    user: UserSlug,
    initiator: UserSlug,
) -> Result<()> {
    ledger.remove_team_member(team, user, initiator).await.map_sdk_err()
}
