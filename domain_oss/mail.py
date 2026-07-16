import smtplib
from email.message import EmailMessage

from flask import current_app


def send_email(to_address, subject, body):
    host = current_app.config.get("SMTP_HOST")
    if not host:
        current_app.logger.warning("Email not sent because SMTP_HOST is not configured: %s", subject)
        return False
    message = EmailMessage()
    message["To"] = to_address
    message["From"] = current_app.config["SMTP_FROM"]
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(host, current_app.config["SMTP_PORT"], timeout=10) as client:
            if current_app.config["SMTP_STARTTLS"]:
                client.starttls()
            if current_app.config["SMTP_USERNAME"]:
                client.login(current_app.config["SMTP_USERNAME"], current_app.config["SMTP_PASSWORD"])
            client.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        current_app.logger.error("Email delivery failed for %s: %s", to_address, exc)
        return False
