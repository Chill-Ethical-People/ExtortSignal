from ransom_monitor.mailer import send_email


def test_mailer_uses_starttls_login_and_configured_recipients(monkeypatch):
    events = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            events.append(("connect", host, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def ehlo(self):
            events.append(("ehlo",))

        def starttls(self, context):
            events.append(("starttls", bool(context)))

        def login(self, username, password):
            events.append(("login", username, password))

        def send_message(self, message):
            events.append(("send", message["To"], message["Subject"]))

    monkeypatch.setattr("ransom_monitor.mailer.smtplib.SMTP", FakeSMTP)
    send_email(
        host="smtp.example.com",
        port=587,
        security="starttls",
        username="alerts@example.com",
        password="app-password",
        sender="alerts@example.com",
        recipients=["soc@example.com", "risk@example.com"],
        subject="Two new claims",
        body="Unverified public allegations.",
    )

    assert ("login", "alerts@example.com", "app-password") in events
    assert ("send", "soc@example.com, risk@example.com", "Two new claims") in events
