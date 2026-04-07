//! Email delivery and templating.
//!
//! Provides [`EmailSender`] trait with SMTP and mock implementations,
//! plus HTML email templates for verification, password reset, invitations,
//! role changes, and organization deletion warnings.

/// Email sending backends (SMTP and mock).
pub mod service;
/// HTML and plain text email template definitions.
pub mod templates;

pub use service::{EmailSender, EmailService, MockEmailSender, SmtpEmailService};
pub use templates::{
    EmailTemplate, InvitationAcceptedEmailTemplate, InvitationEmailTemplate,
    OrganizationDeletionWarningEmailTemplate, PasswordResetEmailTemplate, RoleChangeEmailTemplate,
    VerificationEmailTemplate,
};

/// Escapes HTML special characters to prevent XSS in email templates.
///
/// Replaces `&`, `<`, `>`, `"`, and `'` with their HTML entity equivalents.
///
/// ```no_run
/// use inferadb_control_core::email::html_escape;
/// assert_eq!(html_escape("<script>"), "&lt;script&gt;");
/// ```
pub fn html_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            _ => output.push(c),
        }
    }
    output
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape_input_returns_expected() {
        let cases: &[(&str, &str)] = &[
            // Empty and safe strings pass through unchanged
            ("", ""),
            ("Hello World 123", "Hello World 123"),
            // Each special character is escaped
            ("&<>\"'", "&amp;&lt;&gt;&quot;&#x27;"),
            // Pre-escaped entities are double-escaped (no special treatment)
            ("&amp;", "&amp;amp;"),
            ("&lt;", "&amp;lt;"),
            // XSS vectors are fully neutralized
            (
                "<script>alert('xss')</script>",
                "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
            ),
            (
                r#"<img onerror=alert(document.cookie) src=x>"#,
                "&lt;img onerror=alert(document.cookie) src=x&gt;",
            ),
            (r#""onload=alert(1)""#, "&quot;onload=alert(1)&quot;"),
        ];

        for (input, expected) in cases {
            assert_eq!(html_escape(input), *expected, "html_escape({input:?})");
        }
    }
}
