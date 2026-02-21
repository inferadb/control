pub mod service;
pub mod templates;

pub use service::{EmailSender, EmailService, MockEmailSender, SmtpConfig, SmtpEmailService};
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
    fn test_html_escape_script_tag() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_html_escape_img_onerror() {
        assert_eq!(
            html_escape(r#"<img onerror=alert(document.cookie) src=x>"#),
            "&lt;img onerror=alert(document.cookie) src=x&gt;"
        );
    }

    #[test]
    fn test_html_escape_attribute_injection() {
        assert_eq!(html_escape(r#""onload=alert(1)""#), "&quot;onload=alert(1)&quot;");
    }

    #[test]
    fn test_html_escape_ampersand_no_double_escape() {
        assert_eq!(html_escape("&amp;"), "&amp;amp;");
        assert_eq!(html_escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn test_html_escape_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_html_escape_no_special_characters() {
        assert_eq!(html_escape("Hello World 123"), "Hello World 123");
    }

    #[test]
    fn test_html_escape_all_special_characters() {
        assert_eq!(html_escape("&<>\"'"), "&amp;&lt;&gt;&quot;&#x27;");
    }
}
