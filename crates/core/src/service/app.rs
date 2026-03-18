//! Organization app management service wrapping Ledger SDK app operations.

use std::time::SystemTime;

use inferadb_control_types::error::Result;
use inferadb_ledger_sdk::{
    AppClientAssertionInfo, AppClientSecretStatus, AppCredentialType, AppInfo, ClientAssertionId,
    CreateAppClientAssertionResult, LedgerClient,
};
use inferadb_ledger_types::{AppSlug, OrganizationSlug, UserSlug};

use super::error::SdkResultExt;

/// Creates a new app in an organization.
pub async fn create_app(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    name: &str,
    description: Option<String>,
) -> Result<AppInfo> {
    ledger.create_app(organization, user, name, description).await.map_sdk_err()
}

/// Gets an app by slug.
pub async fn get_app(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<AppInfo> {
    ledger.get_app(organization, user, app).await.map_sdk_err()
}

/// Lists all apps in an organization.
pub async fn list_apps(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
) -> Result<Vec<AppInfo>> {
    ledger.list_apps(organization, user).await.map_sdk_err()
}

/// Updates an app's name and/or description.
pub async fn update_app(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
    name: Option<String>,
    description: Option<String>,
) -> Result<AppInfo> {
    ledger.update_app(organization, user, app, name, description).await.map_sdk_err()
}

/// Deletes an app.
pub async fn delete_app(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<()> {
    ledger.delete_app(organization, user, app).await.map_sdk_err()
}

/// Enables an app.
pub async fn enable_app(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<AppInfo> {
    ledger.enable_app(organization, user, app).await.map_sdk_err()
}

/// Disables an app.
pub async fn disable_app(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<AppInfo> {
    ledger.disable_app(organization, user, app).await.map_sdk_err()
}

/// Enables or disables a credential type for an app.
pub async fn set_app_credential_enabled(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
    credential_type: AppCredentialType,
    enabled: bool,
) -> Result<AppInfo> {
    ledger
        .set_app_credential_enabled(organization, user, app, credential_type, enabled)
        .await
        .map_sdk_err()
}

/// Gets the client secret status for an app.
pub async fn get_app_client_secret(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<AppClientSecretStatus> {
    ledger.get_app_client_secret(organization, user, app).await.map_sdk_err()
}

/// Rotates the client secret for an app. Returns the new plaintext secret.
pub async fn rotate_app_client_secret(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<String> {
    ledger.rotate_app_client_secret(organization, user, app).await.map_sdk_err()
}

/// Lists client assertions for an app.
pub async fn list_app_client_assertions(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
) -> Result<Vec<AppClientAssertionInfo>> {
    ledger.list_app_client_assertions(organization, user, app).await.map_sdk_err()
}

/// Creates a client assertion for an app. Returns the assertion metadata and private key PEM.
pub async fn create_app_client_assertion(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
    name: &str,
    expires_at: SystemTime,
) -> Result<CreateAppClientAssertionResult> {
    ledger
        .create_app_client_assertion(organization, user, app, name, expires_at)
        .await
        .map_sdk_err()
}

/// Deletes a client assertion for an app.
pub async fn delete_app_client_assertion(
    ledger: &LedgerClient,
    organization: OrganizationSlug,
    user: UserSlug,
    app: AppSlug,
    assertion_id: ClientAssertionId,
) -> Result<()> {
    ledger.delete_app_client_assertion(organization, user, app, assertion_id).await.map_sdk_err()
}
