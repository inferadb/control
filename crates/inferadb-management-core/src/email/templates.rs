/// Email template trait
pub trait EmailTemplate {
    /// Get the email subject
    fn subject(&self) -> String;

    /// Get the HTML body
    fn html_body(&self) -> String;

    /// Get the plain text body
    fn text_body(&self) -> String;
}

/// Email verification template
pub struct VerificationEmailTemplate {
    /// User's name
    pub user_name: String,
    /// Verification link
    pub verification_link: String,
    /// Verification code (for manual entry)
    pub verification_code: String,
}

impl EmailTemplate for VerificationEmailTemplate {
    fn subject(&self) -> String {
        "Verify your email address".to_string()
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #007bff; margin-top: 0;">Verify Your Email</h1>
        <p>Hi {},</p>
        <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Verify Email Address
            </a>
        </div>

        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; word-break: break-all;">
            <a href="{}" style="color: #007bff;">{}</a>
        </p>

        <p>If you prefer, you can also enter this verification code manually:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 18px; text-align: center; letter-spacing: 2px;">
            {}
        </p>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            This link will expire in 24 hours. If you didn't request this verification, you can safely ignore this email.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.user_name,
            self.verification_link,
            self.verification_link,
            self.verification_link,
            self.verification_code
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"Hi {},

Thanks for signing up! Please verify your email address.

Verification Link:
{}

Or enter this verification code manually:
{}

This link will expire in 24 hours. If you didn't request this verification, you can safely ignore this email.

---
This is an automated message, please do not reply.
"#,
            self.user_name, self.verification_link, self.verification_code
        )
    }
}

/// Password reset email template
pub struct PasswordResetEmailTemplate {
    /// User's name
    pub user_name: String,
    /// Reset link
    pub reset_link: String,
    /// Reset code (for manual entry)
    pub reset_code: String,
}

impl EmailTemplate for PasswordResetEmailTemplate {
    fn subject(&self) -> String {
        "Reset your password".to_string()
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #dc3545; margin-top: 0;">Reset Your Password</h1>
        <p>Hi {},</p>
        <p>We received a request to reset your password. Click the button below to choose a new password:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Reset Password
            </a>
        </div>

        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; word-break: break-all;">
            <a href="{}" style="color: #dc3545;">{}</a>
        </p>

        <p>If you prefer, you can also enter this reset code manually:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 18px; text-align: center; letter-spacing: 2px;">
            {}
        </p>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.user_name, self.reset_link, self.reset_link, self.reset_link, self.reset_code
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"Hi {},

We received a request to reset your password.

Reset Link:
{}

Or enter this reset code manually:
{}

This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.

---
This is an automated message, please do not reply.
"#,
            self.user_name, self.reset_link, self.reset_code
        )
    }
}

/// Organization invitation email template
pub struct InvitationEmailTemplate {
    /// Invitee's email (since they might not have a name yet)
    pub invitee_email: String,
    /// Organization name
    pub organization_name: String,
    /// Inviter's name
    pub inviter_name: String,
    /// Role being granted
    pub role: String,
    /// Invitation acceptance link
    pub invitation_link: String,
    /// Invitation token (for manual entry)
    pub invitation_token: String,
    /// Expiration time (human-readable)
    pub expires_in: String,
}

impl EmailTemplate for InvitationEmailTemplate {
    fn subject(&self) -> String {
        format!("You've been invited to join {}", self.organization_name)
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Organization Invitation</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #28a745; margin-top: 0;">You've Been Invited!</h1>
        <p>Hi there,</p>
        <p><strong>{}</strong> has invited you to join <strong>{}</strong> with the role of <strong>{}</strong>.</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{}"
               style="background-color: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Accept Invitation
            </a>
        </div>

        <p>Or copy and paste this link into your browser:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; word-break: break-all;">
            <a href="{}" style="color: #28a745;">{}</a>
        </p>

        <p>If you prefer, you can also enter this invitation code manually:</p>
        <p style="background-color: #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 18px; text-align: center; letter-spacing: 2px;">
            {}
        </p>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            This invitation will expire in {}. If you didn't expect this invitation, you can safely ignore this email.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.inviter_name,
            self.organization_name,
            self.role,
            self.invitation_link,
            self.invitation_link,
            self.invitation_link,
            self.invitation_token,
            self.expires_in
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"You've Been Invited!

Hi there,

{} has invited you to join {} with the role of {}.

Invitation Link:
{}

Or enter this invitation code manually:
{}

This invitation will expire in {}. If you didn't expect this invitation, you can safely ignore this email.

---
This is an automated message, please do not reply.
"#,
            self.inviter_name,
            self.organization_name,
            self.role,
            self.invitation_link,
            self.invitation_token,
            self.expires_in
        )
    }
}

/// Invitation accepted notification email template
pub struct InvitationAcceptedEmailTemplate {
    /// Organization owner's name
    pub owner_name: String,
    /// New member's name
    pub member_name: String,
    /// New member's email
    pub member_email: String,
    /// Organization name
    pub organization_name: String,
    /// Role granted
    pub role: String,
}

impl EmailTemplate for InvitationAcceptedEmailTemplate {
    fn subject(&self) -> String {
        format!("{} accepted your invitation to {}", self.member_name, self.organization_name)
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Invitation Accepted</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #28a745; margin-top: 0;">Invitation Accepted</h1>
        <p>Hi {},</p>
        <p><strong>{}</strong> ({}) has accepted your invitation and joined <strong>{}</strong> as a <strong>{}</strong>.</p>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            You can now collaborate with {} in your organization.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.owner_name,
            self.member_name,
            self.member_email,
            self.organization_name,
            self.role,
            self.member_name
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"Invitation Accepted

Hi {},

{} ({}) has accepted your invitation and joined {} as a {}.

You can now collaborate with {} in your organization.

---
This is an automated message, please do not reply.
"#,
            self.owner_name,
            self.member_name,
            self.member_email,
            self.organization_name,
            self.role,
            self.member_name
        )
    }
}

/// Role change notification email template
pub struct RoleChangeEmailTemplate {
    /// Member's name
    pub member_name: String,
    /// Organization name
    pub organization_name: String,
    /// Previous role
    pub old_role: String,
    /// New role
    pub new_role: String,
    /// Who made the change
    pub changed_by: String,
}

impl EmailTemplate for RoleChangeEmailTemplate {
    fn subject(&self) -> String {
        format!("Your role in {} has been updated", self.organization_name)
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Role Updated</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f4f4f4; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #007bff; margin-top: 0;">Role Updated</h1>
        <p>Hi {},</p>
        <p><strong>{}</strong> has updated your role in <strong>{}</strong>.</p>

        <div style="background-color: #e9ecef; padding: 15px; border-radius: 3px; margin: 20px 0;">
            <p style="margin: 0;"><strong>Previous role:</strong> {}</p>
            <p style="margin: 10px 0 0 0;"><strong>New role:</strong> {}</p>
        </div>

        <p style="color: #666; font-size: 14px;">
            This change affects your permissions within the organization.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.member_name, self.changed_by, self.organization_name, self.old_role, self.new_role
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"Role Updated

Hi {},

{} has updated your role in {}.

Previous role: {}
New role: {}

This change affects your permissions within the organization.

---
This is an automated message, please do not reply.
"#,
            self.member_name, self.changed_by, self.organization_name, self.old_role, self.new_role
        )
    }
}

/// Organization deletion warning email template
pub struct OrganizationDeletionWarningEmailTemplate {
    /// Member's name
    pub member_name: String,
    /// Organization name
    pub organization_name: String,
    /// Who initiated deletion
    pub deleted_by: String,
    /// How many days until deletion
    pub days_until_deletion: u32,
}

impl EmailTemplate for OrganizationDeletionWarningEmailTemplate {
    fn subject(&self) -> String {
        format!("{} will be deleted in {} days", self.organization_name, self.days_until_deletion)
    }

    fn html_body(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Organization Deletion Warning</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px; padding: 20px; margin-bottom: 20px;">
        <h1 style="color: #856404; margin-top: 0;">⚠️ Organization Deletion Warning</h1>
        <p>Hi {},</p>
        <p><strong>{}</strong> has initiated deletion of the organization <strong>{}</strong>.</p>

        <div style="background-color: #fff; padding: 15px; border-radius: 3px; margin: 20px 0; border: 1px solid #ffc107;">
            <p style="margin: 0; font-size: 18px; font-weight: bold; color: #856404;">
                This organization will be permanently deleted in {} days
            </p>
        </div>

        <p><strong>What this means:</strong></p>
        <ul>
            <li>All data associated with this organization will be permanently deleted</li>
            <li>All vaults, teams, and access grants will be removed</li>
            <li>This action cannot be undone</li>
        </ul>

        <p style="color: #666; font-size: 14px; margin-top: 30px;">
            If you believe this is a mistake, please contact the organization owner immediately.
        </p>
    </div>

    <p style="color: #999; font-size: 12px; text-align: center;">
        This is an automated message, please do not reply.
    </p>
</body>
</html>"#,
            self.member_name, self.deleted_by, self.organization_name, self.days_until_deletion
        )
    }

    fn text_body(&self) -> String {
        format!(
            r#"⚠️ Organization Deletion Warning

Hi {},

{} has initiated deletion of the organization {}.

This organization will be permanently deleted in {} days.

What this means:
- All data associated with this organization will be permanently deleted
- All vaults, teams, and access grants will be removed
- This action cannot be undone

If you believe this is a mistake, please contact the organization owner immediately.

---
This is an automated message, please do not reply.
"#,
            self.member_name, self.deleted_by, self.organization_name, self.days_until_deletion
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_email_template() {
        let template = VerificationEmailTemplate {
            user_name: "John Doe".to_string(),
            verification_link: "https://example.com/verify?token=abc123".to_string(),
            verification_code: "ABC123".to_string(),
        };

        assert_eq!(template.subject(), "Verify your email address");
        assert!(template.html_body().contains("John Doe"));
        assert!(template.html_body().contains("https://example.com/verify?token=abc123"));
        assert!(template.html_body().contains("ABC123"));
        assert!(template.text_body().contains("John Doe"));
        assert!(template.text_body().contains("https://example.com/verify?token=abc123"));
        assert!(template.text_body().contains("ABC123"));
    }

    #[test]
    fn test_password_reset_email_template() {
        let template = PasswordResetEmailTemplate {
            user_name: "Jane Smith".to_string(),
            reset_link: "https://example.com/reset?token=xyz789".to_string(),
            reset_code: "XYZ789".to_string(),
        };

        assert_eq!(template.subject(), "Reset your password");
        assert!(template.html_body().contains("Jane Smith"));
        assert!(template.html_body().contains("https://example.com/reset?token=xyz789"));
        assert!(template.html_body().contains("XYZ789"));
        assert!(template.text_body().contains("Jane Smith"));
        assert!(template.text_body().contains("https://example.com/reset?token=xyz789"));
        assert!(template.text_body().contains("XYZ789"));
    }
}
