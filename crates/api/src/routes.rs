use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, patch, post},
};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;

use crate::{
    handlers::{
        AppState, audit_logs, auth_v2, clients, email_auth, emails, health,
        metrics as metrics_handler, mfa_auth, organizations, schemas, teams, tokens, users, vaults,
    },
    middleware::{
        logging_middleware, ratelimit, request_id_middleware, require_jwt, require_jwt_local,
        security_headers_middleware,
    },
};

/// Create router with state and middleware applied.
///
/// Read routes (GET) use local JWT validation (cached Ed25519 public keys).
/// Write routes (POST/PATCH/DELETE) use Ledger-validated JWT validation.
pub fn create_router_with_state(state: AppState) -> axum::Router {
    // Read routes: local JWT validation (no Ledger round-trip)
    let jwt_read_routes = Router::new()
        // User profile (read)
        .route("/control/v1/users/me", get(users::get_profile))
        // Email management (read)
        .route("/control/v1/users/emails", get(emails::list_emails))
        // Organization (read)
        .route("/control/v1/organizations", get(organizations::list_organizations))
        .route("/control/v1/organizations/{org}", get(organizations::get_organization))
        // Organization membership (read)
        .route("/control/v1/organizations/{org}/members", get(organizations::list_members))
        // Organization invitations (read)
        .route("/control/v1/organizations/{org}/invitations", get(organizations::list_invitations))
        // User invitations (read)
        .route("/control/v1/users/me/invitations", get(organizations::list_received_invitations))
        // Team management (read)
        .route("/control/v1/organizations/{org}/teams", get(teams::list_teams))
        .route("/control/v1/organizations/{org}/teams/{team}", get(teams::get_team))
        // Team members (read)
        .route(
            "/control/v1/organizations/{org}/teams/{team}/members",
            get(teams::list_team_members),
        )
        // Client/App management (read)
        .route("/control/v1/organizations/{org}/clients", get(clients::list_clients))
        .route("/control/v1/organizations/{org}/clients/{client}", get(clients::get_client))
        // Certificate management (read)
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates",
            get(clients::list_certificates),
        )
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates/{cert}",
            get(clients::get_certificate),
        )
        // Vault management (read)
        .route("/control/v1/organizations/{org}/vaults", get(vaults::list_vaults))
        .route("/control/v1/organizations/{org}/vaults/{vault}", get(vaults::get_vault))
        // Schema management (read)
        .route("/control/v1/organizations/{org}/vaults/{vault}/schemas", get(schemas::list_schemas))
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/current",
            get(schemas::get_current_schema),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/diff",
            get(schemas::diff_schemas),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/{version}",
            get(schemas::get_schema),
        )
        // Audit logs (read)
        .route("/control/v1/organizations/{org}/audit-logs", get(audit_logs::list_audit_logs))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_jwt_local))
        .with_state(state.clone());

    // Write routes: Ledger-validated JWT (full round-trip)
    let jwt_write_routes = Router::new()
        // Auth write operations
        .route("/control/v1/auth/revoke-all", post(auth_v2::revoke_all))
        // User profile (write)
        .route("/control/v1/users/me", patch(users::update_profile))
        .route("/control/v1/users/me", delete(users::delete_user))
        // Email management (write)
        .route("/control/v1/users/emails", post(emails::add_email))
        .route("/control/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization (write)
        .route("/control/v1/organizations", post(organizations::create_organization))
        .route("/control/v1/organizations/{org}", patch(organizations::update_organization))
        .route("/control/v1/organizations/{org}", delete(organizations::delete_organization))
        // Organization membership (write)
        .route(
            "/control/v1/organizations/{org}/members/me",
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
        // Organization invitations (write)
        .route(
            "/control/v1/organizations/{org}/invitations",
            post(organizations::create_invitation),
        )
        .route(
            "/control/v1/organizations/{org}/invitations/{invitation}",
            delete(organizations::delete_invitation),
        )
        // User invitations (write)
        .route(
            "/control/v1/users/me/invitations/{invitation}/accept",
            post(organizations::accept_invitation),
        )
        .route(
            "/control/v1/users/me/invitations/{invitation}/decline",
            post(organizations::decline_invitation),
        )
        // Team management (write)
        .route("/control/v1/organizations/{org}/teams", post(teams::create_team))
        .route("/control/v1/organizations/{org}/teams/{team}", patch(teams::update_team))
        .route("/control/v1/organizations/{org}/teams/{team}", delete(teams::delete_team))
        // Team members (write)
        .route("/control/v1/organizations/{org}/teams/{team}/members", post(teams::add_team_member))
        .route(
            "/control/v1/organizations/{org}/teams/{team}/members/{member}",
            patch(teams::update_team_member),
        )
        .route(
            "/control/v1/organizations/{org}/teams/{team}/members/{member}",
            delete(teams::remove_team_member),
        )
        // Client/App management (write)
        .route("/control/v1/organizations/{org}/clients", post(clients::create_client))
        .route("/control/v1/organizations/{org}/clients/{client}", patch(clients::update_client))
        .route("/control/v1/organizations/{org}/clients/{client}", delete(clients::delete_client))
        // Certificate management (write)
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates",
            post(clients::create_certificate),
        )
        .route(
            "/control/v1/organizations/{org}/clients/{client}/certificates/{cert}",
            delete(clients::revoke_certificate),
        )
        .route(
            "/control/v1/organizations/{org}/clients/{client}/secret/rotate",
            post(clients::rotate_certificate),
        )
        // Vault management (write)
        .route("/control/v1/organizations/{org}/vaults", post(vaults::create_vault))
        .route("/control/v1/organizations/{org}/vaults/{vault}", patch(vaults::update_vault))
        .route("/control/v1/organizations/{org}/vaults/{vault}", delete(vaults::delete_vault))
        // Vault token generation and revocation
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/tokens",
            post(tokens::generate_vault_token),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/tokens",
            delete(tokens::revoke_vault_tokens),
        )
        // Schema management (write) — higher body limit for schema definitions
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas",
            post(schemas::deploy_schema).route_layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/rollback",
            post(schemas::rollback_schema),
        )
        .route(
            "/control/v1/organizations/{org}/vaults/{vault}/schemas/{version}/activate",
            post(schemas::activate_schema),
        )
        // Passkey credential management
        .route(
            "/control/v1/users/me/credentials/passkeys/begin",
            post(mfa_auth::passkey_register_begin),
        )
        .route(
            "/control/v1/users/me/credentials/passkeys/finish",
            post(mfa_auth::passkey_register_finish),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), require_jwt))
        .with_state(state.clone());

    // Combine public, read, and write routes
    Router::new()
        // Health check endpoints
        .route("/livez", get(health::livez_handler))
        .route("/readyz", get(health::readyz_handler))
        .route("/startupz", get(health::startupz_handler))
        .route("/healthz", get(health::healthz_handler))
        // Metrics endpoint (JWT-protected via local validation)
        .route(
            "/metrics",
            get(metrics_handler::metrics_handler)
                .route_layer(middleware::from_fn_with_state(state.clone(), require_jwt_local)),
        )
        // Auth endpoints (rate-limited: 100/hour per IP)
        .route("/control/v1/auth/refresh", post(auth_v2::refresh))
        .route("/control/v1/auth/logout", post(auth_v2::logout))
        .route("/control/v1/auth/email/initiate", post(email_auth::initiate))
        .route("/control/v1/auth/email/verify", post(email_auth::verify))
        .route("/control/v1/auth/totp/verify", post(mfa_auth::verify_totp))
        .route("/control/v1/auth/recovery", post(mfa_auth::consume_recovery))
        .route("/control/v1/auth/passkey/begin", post(mfa_auth::passkey_begin))
        .route("/control/v1/auth/passkey/finish", post(mfa_auth::passkey_finish))
        .route("/control/v1/auth/verify-email", post(emails::verify_email))
        .route("/control/v1/tokens/refresh", post(tokens::refresh_vault_token))
        .route("/control/v1/token", post(tokens::client_assertion_authenticate))
        .route_layer(middleware::from_fn_with_state(state.clone(), ratelimit::login_rate_limit))
        // Registration endpoint (rate-limited: 5/day per IP)
        .route(
            "/control/v1/auth/email/complete",
            post(email_auth::complete).route_layer(middleware::from_fn_with_state(
                state.clone(),
                ratelimit::registration_rate_limit,
            )),
        )
        .with_state(state.clone())
        .merge(jwt_read_routes)
        .merge(jwt_write_routes)
        // Default body size limit (256 KiB) — prevents memory exhaustion
        .layer(DefaultBodyLimit::max(256 * 1024))
        // Concurrency limit — prevents resource exhaustion under load
        .layer(ConcurrencyLimitLayer::new(10_000))
        // CORS — must be inside security headers so preflight responses get headers too
        .layer(build_cors_layer(&state.config.frontend_url))
        // Security response headers (nosniff, DENY, no-store, HSTS) — outermost service layer
        .layer(middleware::from_fn(security_headers_middleware))
        // Add logging middleware to log all requests
        .layer(middleware::from_fn(logging_middleware))
        // Add request ID middleware (outermost — runs first)
        .layer(middleware::from_fn(request_id_middleware))
}

/// Builds a CORS layer configured for the given frontend origin.
fn build_cors_layer(frontend_url: &str) -> CorsLayer {
    use axum::http::{HeaderName, Method};

    // Config.validate() already checks frontend_url format, so this should not fail.
    // Panic on invalid value to surface misconfiguration immediately at startup.
    #[allow(clippy::expect_used)]
    let origin = frontend_url
        .parse::<axum::http::HeaderValue>()
        .expect("frontend_url must be a valid HTTP header value (checked by Config::validate)");

    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600))
}
