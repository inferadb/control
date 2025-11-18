use crate::handlers::{auth, clients, emails, jwks, organizations, sessions, users, AppState};
use crate::middleware::{require_organization_member, require_session};
use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Router,
};

/// Create the Axum router with all API routes
pub fn create_router() -> Router<AppState> {
    Router::new()
        // Public routes (no authentication required)
        .route("/health", get(health_check))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login/password", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/verify-email", post(auth::verify_email))
        .route(
            "/v1/auth/password-reset/request",
            post(auth::request_password_reset),
        )
        .route(
            "/v1/auth/password-reset/confirm",
            post(auth::confirm_password_reset),
        )
        // Protected session management routes
        .route("/v1/users/sessions", get(sessions::list_sessions))
        .route("/v1/users/sessions/{id}", delete(sessions::revoke_session))
        .route(
            "/v1/users/sessions/revoke-others",
            post(sessions::revoke_other_sessions),
        )
        // User profile management routes
        .route("/v1/users/me", get(users::get_profile))
        .route("/v1/users/me", patch(users::update_profile))
        .route("/v1/users/me", delete(users::delete_user))
        // Email management routes
        .route("/v1/users/emails", post(emails::add_email))
        .route("/v1/users/emails", get(emails::list_emails))
        .route("/v1/users/emails/{id}", patch(emails::update_email))
        .route("/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization management routes
        .route(
            "/v1/organizations",
            post(organizations::create_organization),
        )
        .route("/v1/organizations", get(organizations::list_organizations))
        .route(
            "/v1/organizations/{org}",
            get(organizations::get_organization),
        )
        .route(
            "/v1/organizations/{org}",
            patch(organizations::update_organization),
        )
        .route(
            "/v1/organizations/{org}",
            delete(organizations::delete_organization),
        )
        // Organization member management routes
        .route(
            "/v1/organizations/{org}/members",
            get(organizations::list_members),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            patch(organizations::update_member_role),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            delete(organizations::remove_member),
        )
        // Organization invitation routes
        .route(
            "/v1/organizations/{org}/invitations",
            post(organizations::create_invitation),
        )
        .route(
            "/v1/organizations/{org}/invitations",
            get(organizations::list_invitations),
        )
        .route(
            "/v1/organizations/{org}/invitations/{invitation}",
            delete(organizations::delete_invitation),
        )
}

/// Create router with state and middleware applied
///
/// Applies session middleware only to protected routes, leaving public routes (like register/login)
/// accessible without authentication.
pub fn create_router_with_state(state: AppState) -> axum::Router {
    // Routes that need organization context (session + org membership)
    let org_scoped = Router::new()
        .route(
            "/v1/organizations/{org}",
            get(organizations::get_organization),
        )
        .route(
            "/v1/organizations/{org}",
            patch(organizations::update_organization),
        )
        .route(
            "/v1/organizations/{org}",
            delete(organizations::delete_organization),
        )
        // Organization member management routes
        .route(
            "/v1/organizations/{org}/members",
            get(organizations::list_members),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            patch(organizations::update_member_role),
        )
        .route(
            "/v1/organizations/{org}/members/{member}",
            delete(organizations::remove_member),
        )
        // Organization invitation routes
        .route(
            "/v1/organizations/{org}/invitations",
            post(organizations::create_invitation),
        )
        .route(
            "/v1/organizations/{org}/invitations",
            get(organizations::list_invitations),
        )
        .route(
            "/v1/organizations/{org}/invitations/{invitation}",
            delete(organizations::delete_invitation),
        )
        // Ownership transfer route
        .route(
            "/v1/organizations/{org}/transfer-ownership",
            post(organizations::transfer_ownership),
        )
        // Client management routes
        .route(
            "/v1/organizations/{org}/clients",
            post(clients::create_client),
        )
        .route(
            "/v1/organizations/{org}/clients",
            get(clients::list_clients),
        )
        .route(
            "/v1/organizations/{org}/clients/{client}",
            get(clients::get_client),
        )
        .route(
            "/v1/organizations/{org}/clients/{client}",
            patch(clients::update_client),
        )
        .route(
            "/v1/organizations/{org}/clients/{client}",
            delete(clients::delete_client),
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
            delete(clients::delete_certificate),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_organization_member,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    // Create router with protected routes that need session middleware only
    let protected = Router::new()
        // Protected session management routes
        .route("/v1/users/sessions", get(sessions::list_sessions))
        .route("/v1/users/sessions/{id}", delete(sessions::revoke_session))
        .route(
            "/v1/users/sessions/revoke-others",
            post(sessions::revoke_other_sessions),
        )
        // User profile management routes
        .route("/v1/users/me", get(users::get_profile))
        .route("/v1/users/me", patch(users::update_profile))
        .route("/v1/users/me", delete(users::delete_user))
        // Email management routes
        .route("/v1/users/emails", post(emails::add_email))
        .route("/v1/users/emails", get(emails::list_emails))
        .route("/v1/users/emails/{id}", patch(emails::update_email))
        .route("/v1/users/emails/{id}", delete(emails::delete_email))
        // Organization management routes (non-scoped)
        .route(
            "/v1/organizations",
            post(organizations::create_organization),
        )
        .route("/v1/organizations", get(organizations::list_organizations))
        // Accept invitation route (protected, needs session)
        .route(
            "/v1/organizations/invitations/accept",
            post(organizations::accept_invitation),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    // Combine public, protected, and org-scoped routes
    Router::new()
        .route("/health", get(health_check))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login/password", post(auth::login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/verify-email", post(auth::verify_email))
        .route(
            "/v1/auth/password-reset/request",
            post(auth::request_password_reset),
        )
        .route(
            "/v1/auth/password-reset/confirm",
            post(auth::confirm_password_reset),
        )
        // JWKS endpoints (public, no authentication required)
        .route("/.well-known/jwks.json", get(jwks::get_global_jwks))
        .route("/v1/organizations/{org}/jwks.json", get(jwks::get_org_jwks))
        .with_state(state)
        .merge(protected)
        .merge(org_scoped)
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
