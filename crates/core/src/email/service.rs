//! Email sending service with SMTP and mock backends.
//!
//! Provides the [`EmailSender`] trait for async email delivery, with
//! [`SmtpEmailService`] for production SMTP/STARTTLS and [`MockEmailSender`]
//! for testing. [`EmailService`] wraps a boxed sender for dynamic dispatch.

use async_trait::async_trait;
use inferadb_control_types::error::{Error, Result};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
};

/// Trait for sending emails with HTML and plain text bodies.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Sends an email.
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `subject` - Email subject line
    /// * `body_html` - HTML body content
    /// * `body_text` - Plain text body content (fallback)
    ///
    /// # Errors
    ///
    /// Returns an error if the email cannot be delivered.
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()>;
}

/// [`EmailSender`] implementation that delivers mail via SMTP/STARTTLS.
pub struct SmtpEmailService {
    from_address: String,
    from_name: String,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpEmailService {
    /// Creates a new SMTP email service.
    ///
    /// Connects to the given SMTP server with optional authentication.
    /// Pass empty strings for `username` and `password` to skip auth;
    /// providing only one of the two returns an error.
    ///
    /// Set `insecure` to `true` for unencrypted SMTP (local development only).
    ///
    /// # Errors
    ///
    /// Returns an error if the SMTP transport cannot be created, or if only
    /// one of username/password is provided.
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        from_address: String,
        from_name: String,
        insecure: bool,
    ) -> Result<Self> {
        let transport = if insecure {
            tracing::warn!(
                host = %host,
                port = port,
                "Using insecure (unencrypted) SMTP transport - only use for local development!"
            );
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port).build()
        } else {
            let builder = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| Error::internal(format!("Failed to create SMTP transport: {e}")))?
                .port(port);

            let has_username = !username.is_empty();
            let has_password = !password.is_empty();

            if has_username != has_password {
                return Err(Error::validation(
                    "SMTP username and password must both be provided or both be empty",
                ));
            }

            if has_username {
                builder
                    .credentials(Credentials::new(username.to_owned(), password.to_owned()))
                    .build()
            } else {
                builder.build()
            }
        };

        Ok(Self { from_address, from_name, transport })
    }

    /// Builds the sender `Mailbox` from the configured name and address.
    fn get_from_mailbox(&self) -> Result<Mailbox> {
        format!("{} <{}>", self.from_name, self.from_address)
            .parse()
            .map_err(|e| Error::internal(format!("Invalid from address: {e}")))
    }
}

#[async_trait]
impl EmailSender for SmtpEmailService {
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()> {
        let from = self.get_from_mailbox()?;
        let to_mailbox: Mailbox =
            to.parse().map_err(|e| Error::validation(format!("Invalid recipient email: {e}")))?;

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject(subject)
            .multipart(MultiPart::alternative_plain_html(
                body_text.to_owned(),
                body_html.to_owned(),
            ))
            .map_err(|e| Error::internal(format!("Failed to build email message: {e}")))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| Error::internal(format!("Failed to send email: {e}")))?;

        tracing::info!("Email sent to {} with subject: {}", to, subject);
        Ok(())
    }
}

/// Owned container for a dynamically dispatched [`EmailSender`].
pub struct EmailService {
    sender: Box<dyn EmailSender>,
}

impl EmailService {
    /// Creates an email service wrapping the given sender implementation.
    pub fn new(sender: Box<dyn EmailSender>) -> Self {
        Self { sender }
    }

    /// Delegates to the underlying [`EmailSender`] implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying sender fails to deliver the email.
    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()> {
        self.sender.send_email(to, subject, body_html, body_text).await
    }
}

/// Mock email sender for testing.
///
/// Logs emails to tracing without sending them. Can be configured to
/// simulate failures for error handling tests.
pub struct MockEmailSender {
    should_fail: bool,
}

impl MockEmailSender {
    /// Creates a new mock email sender that always succeeds.
    pub fn new() -> Self {
        Self { should_fail: false }
    }

    /// Creates a new mock email sender that always fails.
    pub fn new_failing() -> Self {
        Self { should_fail: true }
    }
}

impl Default for MockEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailSender for MockEmailSender {
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()> {
        if self.should_fail {
            tracing::warn!(
                to = to,
                subject = subject,
                "MockEmailSender: Simulating email send failure"
            );
            Err(Error::internal("Mock email send failure".to_string()))
        } else {
            tracing::info!(
                to = to,
                subject = subject,
                html_length = body_html.len(),
                text_length = body_text.len(),
                "MockEmailSender: Email logged (not sent)"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── MockEmailSender ─────────────────────────────────────────

    #[tokio::test]
    async fn test_mock_sender_send_succeeds() {
        let sender = MockEmailSender::new();

        let result = sender.send_email("test@example.com", "Subject", "<p>HTML</p>", "Text").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_sender_failing_returns_error() {
        let sender = MockEmailSender::new_failing();

        let result = sender.send_email("test@example.com", "Subject", "<p>HTML</p>", "Text").await;

        let err = result.unwrap_err();
        assert!(err.to_string().contains("Mock email send failure"));
    }

    #[test]
    fn test_mock_sender_default_does_not_fail() {
        let sender = MockEmailSender::default();

        assert!(!sender.should_fail);
    }

    // ── EmailService (dynamic dispatch wrapper) ─────────────────

    #[tokio::test]
    async fn test_email_service_delegates_success_to_sender() {
        let service = EmailService::new(Box::new(MockEmailSender::new()));

        let result =
            service.send_email("test@example.com", "Test Subject", "<h1>Test</h1>", "Test").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_email_service_delegates_failure_to_sender() {
        let service = EmailService::new(Box::new(MockEmailSender::new_failing()));

        let result =
            service.send_email("test@example.com", "Test Subject", "<h1>Test</h1>", "Test").await;

        assert!(result.is_err());
    }

    // ── SmtpEmailService construction ───────────────────────────

    #[test]
    fn test_smtp_new_credential_combinations_return_expected() {
        // (username, password, insecure, expect_ok)
        let cases: &[(&str, &str, bool, bool)] = &[
            ("user", "", false, false),     // username without password
            ("", "password", false, false), // password without username
            ("", "", false, true),          // no credentials
            ("user", "pass", false, true),  // both credentials
            ("", "", true, true),           // insecure mode, no credentials
        ];

        for (username, password, insecure, expect_ok) in cases {
            let host = if *insecure { "localhost" } else { "smtp.example.com" };
            let port = if *insecure { 1025 } else { 587 };

            let result = SmtpEmailService::new(
                host,
                port,
                username,
                password,
                "from@example.com".to_string(),
                "Sender".to_string(),
                *insecure,
            );

            assert_eq!(
                result.is_ok(),
                *expect_ok,
                "SmtpEmailService::new(username={username:?}, password={password:?}, insecure={insecure})"
            );
        }
    }

    #[test]
    fn test_smtp_get_from_mailbox_valid_address_returns_ok() {
        let service = SmtpEmailService::new(
            "smtp.example.com",
            587,
            "",
            "",
            "noreply@example.com".to_string(),
            "InferaDB".to_string(),
            false,
        )
        .unwrap();

        let mailbox = service.get_from_mailbox();

        assert!(mailbox.is_ok());
    }
}
