// REST API handlers and routes

pub mod handlers;
pub mod middleware;
pub mod pagination;
pub mod routes;

pub use handlers::{AppState, ErrorResponse};
pub use middleware::{
    extract_session_context, get_user_vault_role, require_admin, require_admin_or_owner,
    require_manager, require_member, require_organization_member, require_owner, require_reader,
    require_session, require_vault_access, require_writer, OrganizationContext, SessionContext,
    VaultContext,
};
pub use pagination::{Paginated, PaginationMeta, PaginationParams, PaginationQuery};
pub use routes::create_router_with_state;
