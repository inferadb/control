use axum::{
    Router, middleware,
    routing::{delete, get, patch, post},
};

use crate::{
    handlers::{
        AppState, audit_logs, auth_v2, clients, email_auth, emails, health,
        metrics as metrics_handler, mfa_auth, organizations, schemas, teams, tokens, users, vaults,
    },
    middleware::{logging_middleware, require_jwt},
};

/// Create router with state and middleware applied.
///
/// All protected routes use JWT middleware. Session-based middleware has been removed.
pub fn create_router_with_state(state: AppState) -> axum::Router {
    // JWT-protected routes (Ledger-backed auth)
    let jwt_protected = Router::new()
        .route("/control/v1/auth/revoke-all", post(auth_v2::revoke_all))
        // User profile management
        .route("/control/v1/users/me", get(users::get_profile))
        .route("/control/v1/users/me", patch(users::update_profile))
        .route("/control/v1/users/me", delete(users::delete_user))
        // Email management
        .route("/control/v1/users/emails", post(emails::add_email))
        .route("/control/v1/users/emails", get(emails::list_emails))
        .route("/control/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization CRUD
        .route("/control/v1/organizations", post(organizations::create_organization))
        .route("/control/v1/organizations", get(organizations::list_organizations))
        .route(
            "/control/v1/organizations/{org}",
            get(organizations::get_organization)
                .patch(organizations::update_organization)
                .delete(organizations::delete_organization),
        )
        // Organization membership
        .route("/control/v1/organizations/{org}/members", get(organizations::list_members))
        .route(
            "/control/v1/organizations/{org}/members/self",
            delete(organizations::leave_organization),
        )
        .route(
            "/control/v1/organizations/{org}/members/{member}",
            patch(organizations::update_member_role),
        )
        .route(
            "/control/v1/organizations/{org}/members/{member}",
            delete(organizations::remove_member),
        )
        // Organization invitations (admin)
        .route(
            "/control/v1/organizations/{org}/invitations",
            post(organizations::create_invitation).get(organizations::list_invitations),
        )
        .route(
            "/control/v1/organizations/{org}/invitations/{invitation}",
            delete(organizations::delete_invitation),
        )
        // User invitations
        .route("/control/v1/users/me/invitations", get(organizations::list_received_invitations))
        .route(
            "/control/v1/users/me/invitations/{invitation}/accept",
            post(organizations::accept_invitation),
        )
        .route(
            "/control/v1/users/me/invitations/{invitation}/decline",
            post(organizations::decline_invitation),
        )
        // Team management
        .route("/control/v1/organizations/{org}/teams", post(teams::create_team))
        .route("/control/v1/organizations/{org}/teams", get(teams::list_teams))
        .route("/control/v1/organizations/{org}/teams/{team}", get(teams::get_team))
        .route("/control/v1/organizations/{org}/teams/{team}", patch(teams::update_team))
        .route("/control/v1/organizations/{org}/teams/{team}", delete(teams::delete_team))
        // Team members
        .route("/control/v1/organizations/{org}/teams/{team}/members", post(teams::add_team_member))
        .route(
            "/control/v1/organizations/{org}/teams/{team}/members",
            get(teams::list_team_members),
        )
        .route(
            "/control/v1/organizations/{org}/teams/{team}/members/{member}",
            patch(teams::update_team_member),
        )
        .route(
            "/control/v1/organizations/{org}/teams/{team}/members/{member}",
            delete(teams::remove_team_member),
        )
        // Client/App management
        .route("/control/v1/organizations/{org}/clients", post(clients::create_client))
        .route("/control/v1/organizations/{org}/clients", get(clients::list_clients))
        .route("/control/v1/organizations/{org}/clients/{client}", get(clients::get_client))
        .route("/control/v1/organizations/{org}/clients/{client}", patch(clients::update_client))
        .route("/control/v1/organizations/{org}/clients/{client}", delete(clients::delete_client))
        // Certificate/Assertion management
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates",
            post(clients::create_certificate).get(clients::list_certificates),
        )
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates/{cert}",
            get(clients::get_certificate).delete(clients::revoke_certificate),
        )
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates/{cert}/rotate",
            post(clients::rotate_certificate),
        )
        // Vault management
        .route("/control/v1/organizations/{org}/vaults", post(vaults::create_vault))
        .route("/control/v1/organizations/{org}/vaults", get(vaults::list_vaults))
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}",
            get(vaults::get_vault).patch(vaults::update_vault).delete(vaults::delete_vault),
        )
        // Vault token generation and revocation
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/tokens",
            post(tokens::generate_vault_token).delete(tokens::revoke_vault_tokens),
        )
        // Schema management (stubs)
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas",
            post(schemas::deploy_schema).get(schemas::list_schemas),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/current",
            get(schemas::get_current_schema),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/diff",
            get(schemas::diff_schemas),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/rollback",
            post(schemas::rollback_schema),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/{version}",
            get(schemas::get_schema),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/{version}/activate",
            post(schemas::activate_schema),
        )
        // Audit logs (stub, JWT-protected)
        .route("/control/v1/organizations/{org}/audit-logs", get(audit_logs::list_audit_logs))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_jwt))
        .with_state(state.clone());

    // Combine public and JWT-protected routes
    Router::new()
        // Health check endpoints
        // Follow Kubernetes API server conventions (/livez, /readyz, /startupz, /healthz)
        .route("/livez", get(health::livez_handler))
        .route("/readyz", get(health::readyz_handler))
        .route("/startupz", get(health::startupz_handler))
        .route("/healthz", get(health::healthz_handler))
        // Metrics endpoint (no authentication)
        .route("/metrics", get(metrics_handler::metrics_handler))
        // Internal audit logging endpoint (stub, no authentication, for internal use)
        .route("/internal/audit", post(audit_logs::create_audit_log))
        // Ledger-backed auth endpoints (v2)
        .route("/control/v1/auth/refresh", post(auth_v2::refresh))
        .route("/control/v1/auth/v2/logout", post(auth_v2::logout))
        // Email-code authentication flow
        .route("/control/v1/auth/email/initiate", post(email_auth::initiate))
        .route("/control/v1/auth/email/verify", post(email_auth::verify))
        .route("/control/v1/auth/email/complete", post(email_auth::complete))
        // TOTP and recovery code verification
        .route("/control/v1/auth/totp/verify", post(mfa_auth::verify_totp))
        .route("/control/v1/auth/recovery", post(mfa_auth::consume_recovery))
        // Passkey authentication
        .route("/control/v1/auth/passkey/begin", post(mfa_auth::passkey_begin))
        .route("/control/v1/auth/passkey/finish", post(mfa_auth::passkey_finish))
        // Email verification (public, token provides authentication)
        .route("/control/v1/auth/verify-email", post(emails::verify_email))
        // Token refresh endpoint (public, refresh token provides authentication)
        .route("/control/v1/tokens/refresh", post(tokens::refresh_vault_token))
        // Client assertion authentication endpoint (public, OAuth 2.0 JWT Bearer)
        .route("/control/v1/token", post(tokens::client_assertion_authenticate))
        .with_state(state)
        .merge(jwt_protected)
        // Add logging middleware to log all requests
        .layer(middleware::from_fn(logging_middleware))
}
