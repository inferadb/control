pub mod service;
pub mod templates;

pub use service::{EmailSender, EmailService, MockEmailSender, SmtpEmailService};
pub use templates::{
    EmailTemplate, InvitationAcceptedEmailTemplate, InvitationEmailTemplate,
    OrganizationDeletionWarningEmailTemplate, PasswordResetEmailTemplate, RoleChangeEmailTemplate,
    VerificationEmailTemplate,
};
