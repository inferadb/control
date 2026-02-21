use async_trait::async_trait;
use inferadb_control_types::error::{Error, Result};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart},
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

/// SMTP-based email service implementation
pub struct SmtpEmailService {
    from_address: String,
    from_name: String,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpEmailService {
    /// Create a new SMTP email service from individual configuration fields.
    ///
    /// # Arguments
    ///
    /// * `host` - SMTP server hostname
    /// * `port` - SMTP server port
    /// * `username` - SMTP username (empty string for no auth)
    /// * `password` - SMTP password (empty string for no auth)
    /// * `from_address` - Sender email address
    /// * `from_name` - Sender display name
    /// * `insecure` - Use unencrypted SMTP (development only)
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
    fn test_email_uses_multipart_alternative() {
        let email = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to("recipient@example.com".parse::<Mailbox>().unwrap())
            .subject("Test Subject")
            .multipart(MultiPart::alternative_plain_html(
                String::from("Plain text body"),
                String::from("<p>HTML body</p>"),
            ))
            .unwrap();

        let formatted = String::from_utf8(email.formatted()).unwrap();
        assert!(
            formatted.contains("multipart/alternative"),
            "Email should have multipart/alternative Content-Type"
        );
    }

    #[test]
    fn test_email_html_part_has_correct_content_type() {
        let email = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to("recipient@example.com".parse::<Mailbox>().unwrap())
            .subject("Test Subject")
            .multipart(MultiPart::alternative_plain_html(
                String::from("Plain text body"),
                String::from("<p>HTML body</p>"),
            ))
            .unwrap();

        let formatted = String::from_utf8(email.formatted()).unwrap();
        assert!(
            formatted.contains("Content-Type: text/html"),
            "Email should contain text/html Content-Type for HTML part"
        );
    }

    #[test]
    fn test_email_text_part_has_correct_content_type() {
        let email = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to("recipient@example.com".parse::<Mailbox>().unwrap())
            .subject("Test Subject")
            .multipart(MultiPart::alternative_plain_html(
                String::from("Plain text body"),
                String::from("<p>HTML body</p>"),
            ))
            .unwrap();

        let formatted = String::from_utf8(email.formatted()).unwrap();
        assert!(
            formatted.contains("Content-Type: text/plain"),
            "Email should contain text/plain Content-Type for text part"
        );
    }

    #[test]
    fn test_email_no_separator_concatenation() {
        let email = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to("recipient@example.com".parse::<Mailbox>().unwrap())
            .subject("Test Subject")
            .multipart(MultiPart::alternative_plain_html(
                String::from("Plain text body"),
                String::from("<p>HTML body</p>"),
            ))
            .unwrap();

        let formatted = String::from_utf8(email.formatted()).unwrap();
        assert!(!formatted.contains("\n---\n"), "Email should not contain the old --- separator");
    }

    #[test]
    fn test_email_plain_text_before_html() {
        let email = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to("recipient@example.com".parse::<Mailbox>().unwrap())
            .subject("Test Subject")
            .multipart(MultiPart::alternative_plain_html(
                String::from("Plain text body"),
                String::from("<p>HTML body</p>"),
            ))
            .unwrap();

        let formatted = String::from_utf8(email.formatted()).unwrap();

        // Per RFC 2046 Section 5.1.4, the preferred format (HTML) should be
        // the last part in a multipart/alternative message
        let text_pos = formatted.find("Content-Type: text/plain").unwrap();
        let html_pos = formatted.find("Content-Type: text/html").unwrap();
        assert!(text_pos < html_pos, "Plain text part should appear before HTML part (RFC 2046)");
    }
}
