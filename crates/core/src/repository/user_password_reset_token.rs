use inferadb_control_storage::StorageBackend;
use inferadb_control_types::entities::UserPasswordResetToken;

use super::secure_token::SecureTokenRepository;

/// Repository for password reset token operations
///
/// Type alias over the generic [`SecureTokenRepository`] parameterized
/// with [`UserPasswordResetToken`]. Key schema:
/// - `password_reset_token:{id}` → serialized token
/// - `password_reset_token:token:{token}` → token ID
/// - `password_reset_token:user:{user_id}:{id}` → token ID
pub type UserPasswordResetTokenRepository<S> = SecureTokenRepository<S, UserPasswordResetToken>;

/// Extension methods specific to password reset tokens
impl<S: StorageBackend> UserPasswordResetTokenRepository<S> {
    /// Get all tokens for a specific user
    ///
    /// Returns all tokens (used and unused) for the user.
    pub async fn get_by_user(
        &self,
        user_id: i64,
    ) -> inferadb_control_types::error::Result<Vec<UserPasswordResetToken>> {
        self.get_by_foreign_key(user_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::Backend;
    use inferadb_control_types::entities::UserPasswordResetToken;

    use super::*;
    use crate::IdGenerator;

    async fn create_test_repo() -> UserPasswordResetTokenRepository<Backend> {
        let storage = Backend::memory();
        UserPasswordResetTokenRepository::new(storage)
    }

    #[tokio::test]
    async fn test_create_and_get_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserPasswordResetToken::generate_token();
        let token = UserPasswordResetToken::builder()
            .id(100)
            .user_id(1)
            .token(token_string)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get(100).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), token);
    }

    #[tokio::test]
    async fn test_get_by_token_string() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserPasswordResetToken::generate_token();
        let token = UserPasswordResetToken::builder()
            .id(100)
            .user_id(1)
            .token(token_string.clone())
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get_by_token(&token_string).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), token);
    }

    #[tokio::test]
    async fn test_get_by_user() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token1_string = UserPasswordResetToken::generate_token();
        let token1 = UserPasswordResetToken::builder()
            .id(100)
            .user_id(1)
            .token(token1_string)
            .create()
            .unwrap();

        let token2_string = UserPasswordResetToken::generate_token();
        let token2 = UserPasswordResetToken::builder()
            .id(101)
            .user_id(1)
            .token(token2_string)
            .create()
            .unwrap();

        let token3_string = UserPasswordResetToken::generate_token();
        let token3 = UserPasswordResetToken::builder()
            .id(102)
            .user_id(2)
            .token(token3_string)
            .create()
            .unwrap();

        repo.create(token1.clone()).await.unwrap();
        repo.create(token2.clone()).await.unwrap();
        repo.create(token3.clone()).await.unwrap();

        let user1_tokens = repo.get_by_user(1).await.unwrap();
        assert_eq!(user1_tokens.len(), 2);

        let user2_tokens = repo.get_by_user(2).await.unwrap();
        assert_eq!(user2_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_update_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserPasswordResetToken::generate_token();
        let mut token = UserPasswordResetToken::builder()
            .id(100)
            .user_id(1)
            .token(token_string)
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        // Mark as used
        token.mark_used();
        repo.update(token.clone()).await.unwrap();

        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert!(retrieved.is_used());
    }

    #[tokio::test]
    async fn test_delete_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserPasswordResetToken::generate_token();
        let token = UserPasswordResetToken::builder()
            .id(100)
            .user_id(1)
            .token(token_string.clone())
            .create()
            .unwrap();

        repo.create(token).await.unwrap();

        // Verify it exists
        assert!(repo.get(100).await.unwrap().is_some());

        // Delete it
        repo.delete(100).await.unwrap();

        // Verify it's gone
        assert!(repo.get(100).await.unwrap().is_none());
        assert!(repo.get_by_token(&token_string).await.unwrap().is_none());
    }
}
