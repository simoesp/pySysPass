"""Email Notification Service"""
from typing import List, Optional, TYPE_CHECKING
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def email_service_from_config(db: "Session") -> Optional["EmailService"]:
    """Build an EmailService from stored config. Returns None if mail is disabled."""
    from app.services.config_service import ConfigService
    cfg = ConfigService(db).get_mail_settings()
    if not cfg.mail_enabled or not cfg.mail_server:
        return None
    return EmailService(
        smtp_host=cfg.mail_server,
        smtp_port=cfg.mail_port or 25,
        username=cfg.mail_user if cfg.mail_auth_enabled else None,
        password=cfg.mail_pass if cfg.mail_auth_enabled else None,
        use_tls=(cfg.mail_security or "tls") == "tls",
        from_email=cfg.mail_from,
    )


class EmailService:
    """Email notification service for sysPass"""

    def __init__(self, smtp_host: str, smtp_port: int, username: str = None,
                 password: str = None, use_tls: bool = True, from_email: str = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_email = from_email or "syspass@example.com"

    def send_email(self, to_email: str, subject: str, body: str,
                   is_html: bool = False, cc: List[str] = None,
                   bcc: List[str] = None) -> bool:
        """Send a single email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject

            # Add body
            msg.attach(MIMEText(body, 'html' if is_html else 'plain'))

            # Add CC recipients
            if cc:
                msg['Cc'] = ', '.join(cc)

            # Connect to SMTP server
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)

            # Login if credentials provided
            if self.username and self.password:
                server.login(self.username, self.password)

            # Get all recipients
            recipients = [to_email]
            if cc:
                recipients.extend(cc)
            if bcc:
                recipients.extend(bcc)

            # Send email
            server.send_message(msg, to_addrs=recipients)
            server.quit()

            return True
        except Exception as e:
            raise Exception(f"Failed to send email: {str(e)}")

    def send_email_to_multiple(self, to_emails: List[str], subject: str,
                                body: str, is_html: bool = False) -> List[bool]:
        """Send the same email to multiple recipients"""
        results = []
        for email in to_emails:
            try:
                success = self.send_email(email, subject, body, is_html)
                results.append(success)
            except Exception:
                results.append(False)
        return results

    def send_notification(self, user_email: str, notification_type: str,
                          message: str, is_html: bool = False) -> bool:
        """Send a notification email to a user"""
        subject = f"[sysPass] {notification_type}"
        return self.send_email(user_email, subject, message, is_html)

    def send_password_reset(self, user_email: str, reset_link: str,
                            username: str) -> bool:
        """Send password reset email"""
        subject = "Password Reset Request - sysPass"
        body = f"""
        <html>
        <body>
        <h2>Password Reset Request</h2>
        <p>Hello {username},</p>
        <p>You requested a password reset for your sysPass account.</p>
        <p>Click the link below to reset your password:</p>
        <p><a href="{reset_link}">{reset_link}</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Best regards,<br/>sysPass</p>
        </body>
        </html>
        """
        return self.send_email(user_email, subject, body, is_html=True)

    def send_account_shared(self, user_email: str, account_name: str,
                            shared_by: str) -> bool:
        """Send notification when an account is shared with a user"""
        subject = "Account Shared - sysPass"
        body = f"""
        <html>
        <body>
        <h2>Account Shared with You</h2>
        <p>Hello,</p>
        <p>The account <strong>{account_name}</strong> has been shared with you by {shared_by}.</p>
        <p>Login to sysPass to view the shared account.</p>
        <p>Best regards,<br/>sysPass</p>
        </body>
        </html>
        """
        return self.send_email(user_email, subject, body, is_html=True)

    def send_password_expiry_warning(self, user_email: str, account_name: str,
                                      expiry_date: datetime) -> bool:
        """Send password expiry warning email"""
        subject = "Password Expiry Warning - sysPass"
        body = f"""
        <html>
        <body>
        <h2>Password Expiry Warning</h2>
        <p>Hello,</p>
        <p>The password for account <strong>{account_name}</strong> is expiring soon.</p>
        <p>Expiry Date: {expiry_date.strftime('%Y-%m-%d')}</p>
        <p>Please update the password before it expires.</p>
        <p>Best regards,<br/>sysPass</p>
        </body>
        </html>
        """
        return self.send_email(user_email, subject, body, is_html=True)

    def send_welcome_email(self, user_email: str, username: str,
                           login_url: str) -> bool:
        """Send welcome email to new user"""
        subject = "Welcome to sysPass"
        body = f"""
        <html>
        <body>
        <h2>Welcome to sysPass!</h2>
        <p>Hello {username},</p>
        <p>Your sysPass account has been created successfully.</p>
        <p>You can login at: <a href="{login_url}">{login_url}</a></p>
        <p>Best regards,<br/>sysPass</p>
        </body>
        </html>
        """
        return self.send_email(user_email, subject, body, is_html=True)
