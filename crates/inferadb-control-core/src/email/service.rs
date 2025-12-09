use async_trait::async_trait;
use inferadb_control_types::error::{Error, Result};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

/// Email sender abstraction
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send an email
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient email address
    /// * `subject` - Email subject line
    /// * `body_html` - HTML body content
    /// * `body_text` - Plain text body content (fallback)
    ///
    /// # Returns
    ///
    /// Ok(()) if email was sent successfully, or an error
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body_html: &str,
        body_text: &str,
    ) -> Result<()>;
}

/// SMTP configuration
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server host
    pub host: String,
    /// SMTP server port
    pub port: u16,
    /// SMTP username
    pub username: String,
    /// SMTP password
    pub password: String,
    /// From email address
    pub address: String,
    /// From display name
    pub name: String,
}

/// SMTP-based email service implementation
pub struct SmtpEmailService {
    config: SmtpConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpEmailService {
    /// Create a new SMTP email service
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
            .map_err(|e| Error::Internal(format!("Failed to create SMTP transport: {}", e)))?
            .port(config.port)
            .credentials(creds)
            .build();

        Ok(Self { config, transport })
    }

    /// Get the from mailbox
    fn get_from_mailbox(&self) -> Result<Mailbox> {
        format!("{} <{}>", self.config.name, self.config.address)
            .parse()
            .map_err(|e| Error::Internal(format!("Invalid from address: {}", e)))
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
            to.parse().map_err(|e| Error::Validation(format!("Invalid recipient email: {}", e)))?;

        let email = Message::builder()
            .from(from)
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(format!("{}\n\n---\n\n{}", body_html, body_text))
            .map_err(|e| Error::Internal(format!("Failed to build email message: {}", e)))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| Error::Internal(format!("Failed to send email: {}", e)))?;

        tracing::info!("Email sent to {} with subject: {}", to, subject);
        Ok(())
    }
}

/// Email service facade
pub struct EmailService {
    sender: Box<dyn EmailSender>,
}

impl EmailService {
    /// Create a new email service
    pub fn new(sender: Box<dyn EmailSender>) -> Self {
        Self { sender }
    }

    /// Send an email
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

/// Mock email sender for testing
///
/// This sender logs emails to tracing but doesn't actually send them.
/// Optionally can be configured to fail for testing error handling.
pub struct MockEmailSender {
    should_fail: bool,
}

impl MockEmailSender {
    /// Create a new mock email sender that always succeeds
    pub fn new() -> Self {
        Self { should_fail: false }
    }

    /// Create a new mock email sender that always fails
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
            Err(Error::Internal("Mock email send failure".to_string()))
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_email_service_success() {
        let sender = Box::new(MockEmailSender::new());
        let service = EmailService::new(sender);

        let result =
            service.send_email("test@example.com", "Test Subject", "<h1>Test</h1>", "Test").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_email_service_failure() {
        let sender = Box::new(MockEmailSender::new_failing());
        let service = EmailService::new(sender);

        let result =
            service.send_email("test@example.com", "Test Subject", "<h1>Test</h1>", "Test").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_email_sender() {
        let sender = MockEmailSender::new();
        let result = sender.send_email("test@example.com", "Test", "<p>HTML</p>", "Text").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_email_sender_failure() {
        let sender = MockEmailSender::new_failing();
        let result = sender.send_email("test@example.com", "Test", "<p>HTML</p>", "Text").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_smtp_config() {
        let config = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: "pass".to_string(),
            address: "noreply@example.com".to_string(),
            name: "Example App".to_string(),
        };

        assert_eq!(config.host, "smtp.example.com");
        assert_eq!(config.port, 587);
    }
}
