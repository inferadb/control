//! Middleware layers for the Control API.
//!
//! Provides cross-cutting concerns applied to routes: JWT authentication
//! (both Ledger-validated and local), rate limiting, request ID propagation,
//! structured logging, and security response headers.

pub mod jwt;
pub mod jwt_local;
pub mod logging;
pub mod ratelimit;
pub mod request_id;
pub mod security_headers;

pub use jwt::{UserClaims, require_jwt};
pub use jwt_local::{JwksCache, require_jwt_local};
pub use logging::logging_middleware;
pub use ratelimit::{RateLimitConfig, login_rate_limit, registration_rate_limit};
pub use request_id::{RequestId, request_id_middleware};
pub use security_headers::security_headers_middleware;
