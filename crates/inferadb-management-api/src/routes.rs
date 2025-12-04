use axum::{
    Router, middleware,
    routing::{delete, get, patch, post},
};

use crate::{
    handlers::{
        AppState, audit_logs, auth, cli_auth, clients, emails, health, jwks,
        metrics as metrics_handler, organizations, sessions, teams, tokens, users, vaults,
    },
    middleware::{
        logging_middleware, require_organization_member, require_server_jwt, require_session,
    },
};

/// Create router with state and middleware applied
///
/// Applies session middleware only to protected routes, leaving public routes (like register/login)
/// accessible without authentication.
pub fn create_router_with_state(state: AppState) -> axum::Router {
    // Routes that need organization context (session + org membership)
    let org_scoped = Router::new()
        // Organization management routes
        .route(
            "/v1/organizations/{org}",
            get(organizations::get_organization)
                .patch(organizations::update_organization)
                .delete(organizations::delete_organization),
        )
        // Organization member management routes
        .route("/v1/organizations/{org}/members", get(organizations::list_members))
        .route("/v1/organizations/{org}/members/{member}", patch(organizations::update_member_role))
        .route("/v1/organizations/{org}/members/{member}", delete(organizations::remove_member))
        // Organization invitation routes
        .route("/v1/organizations/{org}/invitations", post(organizations::create_invitation))
        .route("/v1/organizations/{org}/invitations", get(organizations::list_invitations))
        .route(
            "/v1/organizations/{org}/invitations/{invitation}",
            delete(organizations::delete_invitation),
        )
        // Ownership transfer route
        .route(
            "/v1/organizations/{org}/transfer-ownership",
            post(organizations::transfer_ownership),
        )
        // Organization suspension routes
        .route("/v1/organizations/{org}/suspend", post(organizations::suspend_organization))
        .route("/v1/organizations/{org}/resume", post(organizations::resume_organization))
        // Client management routes
        .route("/v1/organizations/{org}/clients", post(clients::create_client))
        .route("/v1/organizations/{org}/clients", get(clients::list_clients))
        .route("/v1/organizations/{org}/clients/{client}", get(clients::get_client))
        .route("/v1/organizations/{org}/clients/{client}", patch(clients::update_client))
        .route("/v1/organizations/{org}/clients/{client}", delete(clients::delete_client))
        .route(
            "/v1/organizations/{org}/clients/{client}/deactivate",
            post(clients::deactivate_client),
        )
        // Certificate management routes
        .route(
            "/v1/organizations/{org}/clients/{client}/certificates",
            post(clients::create_certificate),
        )
        .route(
            "/v1/organizations/{org}/clients/{client}/certificates",
            get(clients::list_certificates),
        )
        .route(
            "/v1/organizations/{org}/clients/{client}/certificates/{cert}/revoke",
            post(clients::revoke_certificate),
        )
        .route(
            "/v1/organizations/{org}/clients/{client}/certificates/{cert}",
            get(clients::get_certificate).delete(clients::delete_certificate),
        )
        // Vault management routes
        .route("/v1/organizations/{org}/vaults", post(vaults::create_vault))
        .route("/v1/organizations/{org}/vaults", get(vaults::list_vaults))
        .route(
            "/v1/organizations/{org}/vaults/{vault}",
            get(vaults::get_vault).patch(vaults::update_vault).delete(vaults::delete_vault),
        )
        // Vault user grant routes
        .route(
            "/v1/organizations/{org}/vaults/{vault}/user-grants",
            post(vaults::create_user_grant),
        )
        .route("/v1/organizations/{org}/vaults/{vault}/user-grants", get(vaults::list_user_grants))
        .route(
            "/v1/organizations/{org}/vaults/{vault}/user-grants/{grant}",
            patch(vaults::update_user_grant),
        )
        .route(
            "/v1/organizations/{org}/vaults/{vault}/user-grants/{grant}",
            delete(vaults::delete_user_grant),
        )
        // Vault team grant routes
        .route(
            "/v1/organizations/{org}/vaults/{vault}/team-grants",
            post(vaults::create_team_grant),
        )
        .route("/v1/organizations/{org}/vaults/{vault}/team-grants", get(vaults::list_team_grants))
        .route(
            "/v1/organizations/{org}/vaults/{vault}/team-grants/{grant}",
            patch(vaults::update_team_grant),
        )
        .route(
            "/v1/organizations/{org}/vaults/{vault}/team-grants/{grant}",
            delete(vaults::delete_team_grant),
        )
        // Vault token generation route
        .route("/v1/organizations/{org}/vaults/{vault}/tokens", post(tokens::generate_vault_token))
        // Audit log routes (OWNER only)
        .route("/v1/organizations/{org}/audit-logs", get(audit_logs::list_audit_logs))
        // Team management routes
        .route("/v1/organizations/{org}/teams", post(teams::create_team))
        .route("/v1/organizations/{org}/teams", get(teams::list_teams))
        .route("/v1/organizations/{org}/teams/{team}", get(teams::get_team))
        .route("/v1/organizations/{org}/teams/{team}", patch(teams::update_team))
        .route("/v1/organizations/{org}/teams/{team}", delete(teams::delete_team))
        // Team member routes
        .route("/v1/organizations/{org}/teams/{team}/members", post(teams::add_team_member))
        .route("/v1/organizations/{org}/teams/{team}/members", get(teams::list_team_members))
        .route(
            "/v1/organizations/{org}/teams/{team}/members/{member}",
            patch(teams::update_team_member),
        )
        .route(
            "/v1/organizations/{org}/teams/{team}/members/{member}",
            delete(teams::remove_team_member),
        )
        // Team permission routes
        .route(
            "/v1/organizations/{org}/teams/{team}/permissions",
            post(teams::grant_team_permission),
        )
        .route(
            "/v1/organizations/{org}/teams/{team}/permissions",
            get(teams::list_team_permissions),
        )
        .route(
            "/v1/organizations/{org}/teams/{team}/permissions/{permission}",
            delete(teams::revoke_team_permission),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), require_organization_member))
        .layer(middleware::from_fn_with_state(state.clone(), require_session));

    // Create router with protected routes that need session middleware only
    let protected = Router::new()
        // Protected session management routes
        .route("/v1/users/sessions", get(sessions::list_sessions))
        .route("/v1/users/sessions/{id}", delete(sessions::revoke_session))
        .route("/v1/users/sessions/revoke-others", post(sessions::revoke_other_sessions))
        // Token revocation routes
        .route("/v1/tokens/revoke/vault/{vault}", post(tokens::revoke_vault_tokens))
        // User profile management routes
        .route("/v1/users/me", get(users::get_profile))
        .route("/v1/users/me", patch(users::update_profile))
        .route("/v1/users/me", delete(users::delete_user))
        .route("/v1/auth/me", get(users::get_profile))
        // Email management routes
        .route("/v1/users/emails", post(emails::add_email))
        .route("/v1/users/emails", get(emails::list_emails))
        .route("/v1/users/emails/{id}", patch(emails::update_email))
        .route("/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization management routes (non-scoped)
        .route("/v1/organizations", post(organizations::create_organization))
        .route("/v1/organizations", get(organizations::list_organizations))
        // Accept invitation route (protected, needs session)
        .route("/v1/organizations/invitations/accept", post(organizations::accept_invitation))
        // CLI authentication routes (protected, needs session for authorize)
        .route("/v1/auth/cli/authorize", post(cli_auth::cli_authorize))
        // Vault GET by ID route (session-protected, no org membership required)
        .route("/v1/vaults/{vault}", get(vaults::get_vault_by_id))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), require_session));

    // Combine public, protected, and org-scoped routes
    Router::new()
        // Health check endpoints (no authentication)
        .route("/v1/health", get(health::health_detailed))
        .route("/v1/health/live", get(health::health_live))
        .route("/v1/health/ready", get(health::health_ready))
        .route("/v1/health/startup", get(health::health_startup))
        // Legacy health check endpoint
        .route("/health", get(health_check))
        // Metrics endpoint (no authentication)
        .route("/metrics", get(metrics_handler::metrics_handler))
        // Internal audit logging endpoint (no authentication, for internal use)
        .route("/internal/audit", post(audit_logs::create_audit_log))
        // Authentication endpoints
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login/password", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/verify-email", post(auth::verify_email))
        .route("/v1/auth/password-reset/request", post(auth::request_password_reset))
        .route("/v1/auth/password-reset/confirm", post(auth::confirm_password_reset))
        // Token refresh endpoint (public, refresh token provides authentication)
        .route("/v1/tokens/refresh", post(tokens::refresh_vault_token))
        // Client assertion authentication endpoint (public, OAuth 2.0 JWT Bearer)
        .route("/v1/token", post(tokens::client_assertion_authenticate))
        // CLI token exchange endpoint (public, authorization code provides authentication)
        .route("/v1/auth/cli/token", post(cli_auth::cli_token_exchange))
        // JWKS endpoints (public, no authentication required)
        .route("/.well-known/jwks.json", get(jwks::get_global_jwks))
        .route("/v1/organizations/{org}/jwks.json", get(jwks::get_org_jwks))
        .route("/v1/organizations/{org}/.well-known/jwks.json", get(jwks::get_org_jwks))
        .with_state(state)
        .merge(org_scoped)
        .merge(protected)
        // Add logging middleware to log all requests
        .layer(middleware::from_fn(logging_middleware))
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Create public routes (client-facing)
/// All user-facing endpoints including auth, organizations, vaults, etc.
pub fn public_routes(state: AppState) -> Router {
    // Wrapper around existing create_router_with_state
    // The existing function already has all client-facing routes
    create_router_with_state(state)
}

/// Create internal routes (server-to-server communication)
/// Exposes JWKS endpoints (no auth) and privileged /internal/v1/* endpoints (server JWT auth)
pub fn internal_routes(state: AppState) -> Router {
    // Public JWKS endpoints (no authentication required)
    let jwks_routes = Router::new()
        .route("/internal/management-jwks.json", get(jwks::get_management_jwks))
        .with_state(state.clone());

    // Privileged internal routes (require server JWT authentication)
    let privileged_routes = Router::new()
        // Organization GET endpoint - for server-to-server org verification
        .route("/internal/organizations/{org}", get(organizations::get_organization_privileged))
        // Vault GET endpoint - for server-to-server vault ownership verification
        .route("/internal/vaults/{vault}", get(vaults::get_vault_by_id_privileged))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), require_server_jwt));

    // Combine JWKS (no auth) and privileged routes (server JWT auth)
    jwks_routes
        .merge(privileged_routes)
        // Add logging middleware to log all internal requests
        .layer(middleware::from_fn(logging_middleware))
}
