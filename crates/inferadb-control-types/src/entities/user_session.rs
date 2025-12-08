use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Session type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionType {
    /// Web browser session
    Web,
    /// CLI tool session
    Cli,
    /// SDK/programmatic session
    Sdk,
}

impl SessionType {
    /// Get the TTL for this session type in seconds
    pub fn ttl_seconds(&self) -> i64 {
        match self {
            SessionType::Web => 24 * 60 * 60,      // 24 hours
            SessionType::Cli => 7 * 24 * 60 * 60,  // 7 days
            SessionType::Sdk => 30 * 24 * 60 * 60, // 30 days
        }
    }

    /// Get the TTL as a chrono::Duration
    pub fn ttl_duration(&self) -> Duration {
        Duration::seconds(self.ttl_seconds())
    }
}

/// UserSession entity representing an active user session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSession {
    /// Unique session ID (Snowflake ID)
    pub id: i64,

    /// User ID this session belongs to
    pub user_id: i64,

    /// Type of session
    pub session_type: SessionType,

    /// When the session was created
    pub created_at: DateTime<Utc>,

    /// When the session expires
    pub expires_at: DateTime<Utc>,

    /// Last activity timestamp (for sliding window)
    pub last_activity_at: DateTime<Utc>,

    /// IP address of the client
    pub ip_address: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// When the session was soft-deleted/revoked
    pub deleted_at: Option<DateTime<Utc>>,
}

impl UserSession {
    /// Create a new session
    ///
    /// # Arguments
    ///
    /// * `id` - Snowflake ID for the session
    /// * `user_id` - ID of the user
    /// * `session_type` - Type of session
    /// * `ip_address` - Optional IP address
    /// * `user_agent` - Optional user agent string
    ///
    /// # Returns
    ///
    /// A new UserSession instance
    pub fn new(
        id: i64,
        user_id: i64,
        session_type: SessionType,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + session_type.ttl_duration();

        Self {
            id,
            user_id,
            session_type,
            created_at: now,
            expires_at,
            last_activity_at: now,
            ip_address,
            user_agent,
            deleted_at: None,
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if session is active (not deleted and not expired)
    pub fn is_active(&self) -> bool {
        !self.is_deleted() && !self.is_expired()
    }

    /// Check if session is deleted/revoked
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Update last activity (sliding window)
    ///
    /// Updates both last_activity_at and extends expires_at
    pub fn update_activity(&mut self) {
        let now = Utc::now();
        self.last_activity_at = now;
        self.expires_at = now + self.session_type.ttl_duration();
    }

    /// Revoke the session (soft delete)
    pub fn revoke(&mut self) {
        if self.deleted_at.is_none() {
            self.deleted_at = Some(Utc::now());
        }
    }

    /// Get time until expiration
    pub fn time_until_expiry(&self) -> Option<Duration> {
        let now = Utc::now();
        if now < self.expires_at { Some(self.expires_at - now) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_type_ttl() {
        assert_eq!(SessionType::Web.ttl_seconds(), 24 * 60 * 60);
        assert_eq!(SessionType::Cli.ttl_seconds(), 7 * 24 * 60 * 60);
        assert_eq!(SessionType::Sdk.ttl_seconds(), 30 * 24 * 60 * 60);
    }

    #[test]
    fn test_create_session() {
        let session = UserSession::new(
            1,
            100,
            SessionType::Web,
            Some("127.0.0.1".to_string()),
            Some("Mozilla/5.0".to_string()),
        );

        assert_eq!(session.id, 1);
        assert_eq!(session.user_id, 100);
        assert_eq!(session.session_type, SessionType::Web);
        assert!(!session.is_expired());
        assert!(session.is_active());
        assert!(!session.is_deleted());
    }

    #[test]
    fn test_session_expiry() {
        let mut session = UserSession::new(1, 100, SessionType::Web, None, None);

        // Manually set expiry to the past
        session.expires_at = Utc::now() - Duration::seconds(1);

        assert!(session.is_expired());
        assert!(!session.is_active());
    }

    #[test]
    fn test_update_activity() {
        let mut session = UserSession::new(1, 100, SessionType::Web, None, None);
        let original_expires_at = session.expires_at;

        // Wait a bit and update activity
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.update_activity();

        // Expiry should be extended
        assert!(session.expires_at > original_expires_at);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_revoke_session() {
        let mut session = UserSession::new(1, 100, SessionType::Web, None, None);
        assert!(!session.is_deleted());
        assert!(session.is_active());

        session.revoke();
        assert!(session.is_deleted());
        assert!(!session.is_active());
    }

    #[test]
    fn test_time_until_expiry() {
        let session = UserSession::new(1, 100, SessionType::Web, None, None);
        let time_left = session.time_until_expiry();
        assert!(time_left.is_some());

        let mut expired_session = UserSession::new(1, 100, SessionType::Web, None, None);
        expired_session.expires_at = Utc::now() - Duration::seconds(1);
        assert!(expired_session.time_until_expiry().is_none());
    }
}
