use inferadb_control_storage::StorageBackend;
use inferadb_control_types::entities::UserEmailVerificationToken;

use super::secure_token::SecureTokenRepository;

/// Repository for email verification token operations
///
/// Type alias over the generic [`SecureTokenRepository`] parameterized
/// with [`UserEmailVerificationToken`]. Key schema:
/// - `email_verify_token:{id}` → serialized token
/// - `email_verify_token:token:{token}` → token ID
/// - `email_verify_token:email:{user_email_id}:{id}` → token ID
pub type UserEmailVerificationTokenRepository<S> =
    SecureTokenRepository<S, UserEmailVerificationToken>;

/// Extension methods specific to email verification tokens
impl<S: StorageBackend> UserEmailVerificationTokenRepository<S> {
    /// Get all tokens for a specific email
    ///
    /// Returns all tokens (used and unused) for the email.
    pub async fn get_by_email(
        &self,
        user_email_id: i64,
    ) -> inferadb_control_types::error::Result<Vec<UserEmailVerificationToken>> {
        self.get_by_foreign_key(user_email_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_control_storage::Backend;
    use inferadb_control_types::entities::UserEmailVerificationToken;

    use super::*;
    use crate::IdGenerator;

    async fn create_test_repo() -> UserEmailVerificationTokenRepository<Backend> {
        let storage = Backend::memory();
        UserEmailVerificationTokenRepository::new(storage)
    }

    #[tokio::test]
    async fn test_create_and_get_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserEmailVerificationToken::generate_token();
        let token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
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

        let token_string = UserEmailVerificationToken::generate_token();
        let token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token_string.clone())
            .create()
            .unwrap();

        repo.create(token.clone()).await.unwrap();

        let retrieved = repo.get_by_token(&token_string).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), token);
    }

    #[tokio::test]
    async fn test_get_by_email() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token1_string = UserEmailVerificationToken::generate_token();
        let token1 = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
            .token(token1_string)
            .create()
            .unwrap();

        let token2_string = UserEmailVerificationToken::generate_token();
        let token2 = UserEmailVerificationToken::builder()
            .id(101)
            .user_email_id(1)
            .token(token2_string)
            .create()
            .unwrap();

        let token3_string = UserEmailVerificationToken::generate_token();
        let token3 = UserEmailVerificationToken::builder()
            .id(102)
            .user_email_id(2)
            .token(token3_string)
            .create()
            .unwrap();

        repo.create(token1.clone()).await.unwrap();
        repo.create(token2.clone()).await.unwrap();
        repo.create(token3.clone()).await.unwrap();

        let email1_tokens = repo.get_by_email(1).await.unwrap();
        assert_eq!(email1_tokens.len(), 2);

        let email2_tokens = repo.get_by_email(2).await.unwrap();
        assert_eq!(email2_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_update_token() {
        let _ = IdGenerator::init(1);
        let repo = create_test_repo().await;

        let token_string = UserEmailVerificationToken::generate_token();
        let mut token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
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

        let token_string = UserEmailVerificationToken::generate_token();
        let token = UserEmailVerificationToken::builder()
            .id(100)
            .user_email_id(1)
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
