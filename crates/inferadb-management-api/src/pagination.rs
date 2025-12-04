use axum::extract::Query;
use serde::{Deserialize, Serialize};

/// Pagination parameters for list endpoints
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationParams {
    /// Page size (default: 50, max: 100)
    #[serde(default = "default_limit")]
    pub limit: usize,

    /// Offset for pagination (default: 0)
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

impl PaginationParams {
    /// Validate and normalize pagination parameters
    pub fn validate(self) -> Self {
        let limit = self.limit.clamp(1, 100);
        Self { limit, offset: self.offset }
    }
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self { limit: default_limit(), offset: 0 }
    }
}

/// Pagination metadata for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    /// Total number of items (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    /// Number of items in this page
    pub count: usize,

    /// Current offset
    pub offset: usize,

    /// Items per page
    pub limit: usize,

    /// Whether there are more items
    pub has_more: bool,
}

impl PaginationMeta {
    /// Create pagination metadata from total count
    pub fn from_total(total: usize, offset: usize, limit: usize, count: usize) -> Self {
        Self { total: Some(total), count, offset, limit, has_more: offset + count < total }
    }

    /// Create pagination metadata without total count (streaming pagination)
    pub fn from_count(count: usize, offset: usize, limit: usize) -> Self {
        // If we got exactly limit items, there might be more
        let has_more = count == limit;
        Self { total: None, count, offset, limit, has_more }
    }
}

/// Paginated response wrapper
#[derive(Debug, Clone, Serialize)]
pub struct Paginated<T> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

impl<T> Paginated<T> {
    /// Create a paginated response with known total
    pub fn with_total(data: Vec<T>, total: usize, params: &PaginationParams) -> Self {
        let count = data.len();
        Self {
            data,
            pagination: PaginationMeta::from_total(total, params.offset, params.limit, count),
        }
    }

    /// Create a paginated response without total (streaming pagination)
    pub fn from_data(data: Vec<T>, params: &PaginationParams) -> Self {
        let count = data.len();
        Self { data, pagination: PaginationMeta::from_count(count, params.offset, params.limit) }
    }
}

/// Extract pagination query parameters
pub type PaginationQuery = Query<PaginationParams>;
