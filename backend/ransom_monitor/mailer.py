from __future__ import annotations

from email.message import EmailMessage
import smtplib
import ssl


class MailDeliveryError(RuntimeError):
    pass


def send_email(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str,
    sender: str,
    recipients: list[str],
    subject: str,
    body: str,
) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    try:
        if security == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=30, context=context) as client:
                if username:
                    client.login(username, password)
                client.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=30) as client:
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
                if username:
                    client.login(username, password)
                client.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        raise MailDeliveryError(f"SMTP delivery failed: {type(error).__name__}") from error
