pub mod dual_auth;
pub mod logging;
pub mod organization;
pub mod permission;
pub mod ratelimit;
pub mod server_auth;
pub mod session;
pub mod vault;

pub use logging::logging_middleware;
pub use organization::{
    OrganizationContext, require_admin_or_owner, require_member, require_organization_member,
    require_owner,
};
pub use permission::{
    get_user_permissions, has_organization_permission, require_organization_permission,
};
pub use ratelimit::{login_rate_limit, registration_rate_limit};
pub use server_auth::{ServerContext, extract_server_context, require_server_jwt};
pub use session::{SessionContext, extract_session_context, require_session};
pub use vault::{
    VaultContext, get_user_vault_role, require_admin, require_manager, require_reader,
    require_vault_access, require_writer,
};
