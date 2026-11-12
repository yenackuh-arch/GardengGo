"""Tests for the email system. No real email is ever sent: tests use a memory mailer, a fake SMTP server on this computer,
and a fake smtplib. Run:  python -m unittest discover -s tests -t . -v"""
import contextlib
import email
import io
import logging
import re
import socketserver
import threading
import time
import unittest
from decimal import Decimal
from email import policy
from unittest import mock

import emails
import mailer
from mailer import BaseMailer, ConsoleMailer, Mail, MemoryMailer, SmtpMailer, build_mailer
from tests.test_admin import AdminBase
from tests.test_customer import GOOD, Base
from werkzeug.security import generate_password_hash

logging.getLogger("gardengo.mail").setLevel(logging.CRITICAL)      # the tests break the mail server on purpose; keep the screen clean

SAMPLE = Mail("customer@example.com", "Order GG-2001", "Total: \u20B1450.00", "<p>Total: \u20B1450.00</p>")


# ---------------------------------------------------------------- a tiny SMTP server that keeps what it receives
class _Handler(socketserver.StreamRequestHandler):
    def reply(self, text):
        self.wfile.write((text + "\r\n").encode())

    def handle(self):
        self.reply("220 test ready")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode(errors="replace").strip().upper()
            if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                self.reply("250-test\r\n250 8BITMIME")
            elif cmd.startswith("DATA"):
                self.reply("354 go ahead")
                data = b""
                while not data.endswith(b"\r\n.\r\n"):
                    data += self.rfile.readline()
                self.server.received.append(data[:-5])
                self.reply("250 queued")
            elif cmd.startswith("QUIT"):
                self.reply("221 bye")
                return
            else:
                self.reply("250 OK")


class FakeSmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.received = []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]


# ---------------------------------------------------------------- the mailer classes by themselves
class TestMailerClasses(unittest.TestCase):
    def test_mail_refuses_header_injection_and_bad_addresses(self):
        for to, subject in [("a@b.com\r\nBcc: spy@evil.com", "Hi"), ("a@b.com", "Hi\nBcc: spy@evil.com"), ("not-an-address", "Hi")]:
            with self.assertRaises(ValueError, msg=(to, subject)): Mail(to, subject, "x", "<p>x</p>")

    def test_send_never_raises_and_reports_failure(self):
        self.assertFalse(MemoryMailer(fail=True).send(SAMPLE))
        good = MemoryMailer(); self.assertTrue(good.send(SAMPLE)); self.assertEqual(good.outbox, [SAMPLE])

    def test_base_mailer_cannot_be_used_directly(self):
        with self.assertRaises(TypeError): BaseMailer()

    def test_every_mailer_is_a_base_mailer(self):
        for m in (ConsoleMailer(), MemoryMailer(), SmtpMailer("h", 587, "u@x.com", "secret")): self.assertIsInstance(m, BaseMailer)

    def test_password_never_appears_in_the_printed_form_of_the_mailer(self):
        self.assertNotIn("secret-app-password", repr(SmtpMailer("smtp.gmail.com", 587, "u@gmail.com", "secret-app-password")))

    def test_console_mailer_prints_the_email(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out): self.assertTrue(ConsoleMailer().send(SAMPLE))
        self.assertIn("customer@example.com", out.getvalue()); self.assertIn("Order GG-2001", out.getvalue())

    def test_build_mailer_follows_the_settings(self):
        self.assertIsInstance(build_mailer({"MAIL_USER": "", "MAIL_PASSWORD": ""}), ConsoleMailer)
        self.assertIsInstance(build_mailer({"MAIL_USER": "me@gmail.com", "MAIL_PASSWORD": ""}), ConsoleMailer)
        m = build_mailer({"MAIL_USER": "me@gmail.com", "MAIL_PASSWORD": "abcd", "MAIL_HOST": "smtp.gmail.com", "MAIL_PORT": "587", "MAIL_FROM_NAME": "GardenGo"})
        self.assertIsInstance(m, SmtpMailer); self.assertEqual((m.host, m.port, m.security), ("smtp.gmail.com", 587, "starttls"))

    def test_message_has_text_and_html_parts_and_keeps_the_peso_sign(self):
        msg = SmtpMailer("smtp.gmail.com", 587, "garden@gmail.com", "x", "GardenGo").build_message(SAMPLE)
        self.assertEqual((msg["To"], msg["Subject"]), ("customer@example.com", "Order GG-2001"))
        self.assertIn("garden@gmail.com", msg["From"]); self.assertIn("GardenGo", msg["From"])
        self.assertEqual(msg.get_body(("plain",)).get_content().strip(), "Total: \u20B1450.00")
        self.assertIn("\u20B1450.00", msg.get_body(("html",)).get_content())

    def test_real_smtp_conversation_with_a_local_server(self):
        server = FakeSmtpServer()
        try:
            sent = SmtpMailer("127.0.0.1", server.port, "garden@example.com", "", "GardenGo", security="none").send(SAMPLE)
            self.assertTrue(sent)
            got = email.message_from_bytes(server.received[0], policy=policy.default)
            self.assertEqual((got["To"], got["Subject"]), ("customer@example.com", "Order GG-2001"))
            self.assertIn("garden@example.com", got["From"])
            self.assertIn("\u20B1450.00", got.get_body(("plain",)).get_content()); self.assertIn("\u20B1450.00", got.get_body(("html",)).get_content())
        finally:
            server.shutdown(); server.server_close()

    def test_unreachable_server_is_reported_not_raised(self):
        self.assertFalse(SmtpMailer("127.0.0.1", 1, "garden@example.com", "", security="none", timeout=2).send(SAMPLE))

    def test_gmail_style_login_order_is_encrypt_then_login_then_send(self):
        calls = []
        class FakeSMTP:
            def __init__(self, host, port, timeout=None): calls.append(("connect", host, port))
            def __enter__(self): return self
            def __exit__(self, *a): calls.append(("quit",))
            def ehlo(self): calls.append(("ehlo",))
            def starttls(self, context=None): calls.append(("starttls", context is not None))
            def login(self, user, password): calls.append(("login", user, password))
            def send_message(self, msg): calls.append(("send", msg["To"]))
        with mock.patch.object(mailer.smtplib, "SMTP", FakeSMTP):
            self.assertTrue(SmtpMailer("smtp.gmail.com", 587, "garden@gmail.com", "apppassword1234").send(SAMPLE))
        self.assertEqual(calls, [("connect", "smtp.gmail.com", 587), ("ehlo",), ("starttls", True), ("ehlo",), ("login", "garden@gmail.com", "apppassword1234"),
                                 ("send", "customer@example.com"), ("quit",)])          # the password is only sent AFTER the connection is encrypted

    def test_ssl_mode_uses_an_encrypted_connection_from_the_start(self):
        used = []
        class FakeSSL:
            def __init__(self, host, port, timeout=None, context=None): used.append(("ssl", port, context is not None))
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def ehlo(self): pass
            def login(self, u, p): pass
            def send_message(self, m): pass
        with mock.patch.object(mailer.smtplib, "SMTP_SSL", FakeSSL):
            self.assertTrue(SmtpMailer("smtp.gmail.com", 465, "g@gmail.com", "pw", security="ssl").send(SAMPLE))
        self.assertEqual(used, [("ssl", 465, True)])

    def test_send_later_does_not_make_the_page_wait(self):
        release, started = threading.Event(), threading.Event()
        class Slow(SmtpMailer):
            def deliver(self, mail): started.set(); release.wait(5)
        slow = Slow("h", 587, "u@x.com", "p"); t0 = time.time(); slow.send_later(SAMPLE)
        self.assertLess(time.time() - t0, 0.5); self.assertTrue(started.wait(2)); release.set()


# ---------------------------------------------------------------- emails sent by the website
class NotificationBase(Base):
    @property
    def outbox(self): return self.app.extensions["mailer"].outbox

    def mails_to(self, address): return [m for m in self.outbox if m.to == address]


class TestEmailsSentByTheSite(NotificationBase):
    def test_welcome_email_after_registering(self):
        self.register(self.client, "maria@example.com", "Maria Santos")
        (m,) = self.outbox
        self.assertEqual((m.to, m.subject), ("maria@example.com", "Welcome to GardenGo")); self.assertIn("Maria Santos", m.text); self.assertIn("Maria Santos", m.html)
        self.assertRegex(m.text, r"http://localhost/plants")

    def test_no_welcome_email_when_registration_fails(self):
        self.post(self.client, "/register", {"name": "M", "email": "bad", "password": "x", "confirm_password": "x"}, page="/register")
        self.assertEqual(self.outbox, [])

    def test_order_confirmation_email_has_the_order_details(self):
        c = self.customer(); self.outbox.clear()
        self.order(c, [("Monstera", 2), ("Echeveria", 3)], fulfillment="delivery")
        (m,) = self.outbox
        self.assertEqual((m.to, m.subject), ("maria@example.com", "We received your order GG-2001"))
        for part in (m.text, m.html):
            for expected in ["GG-2001", "Monstera", "Echeveria", "\u20B1900.00", "\u20B1360.00", "\u20B180.00", "\u20B11,340.00", "12 Rizal St."]: self.assertIn(expected, part)
        self.assertIn("http://localhost/track?id=GG-2001", m.text); self.assertIn("cash when you receive", m.text)

    def test_rejected_order_sends_no_email(self):
        c = self.customer(); self.outbox.clear()
        self.add_to_cart(c, "Boston Fern", 3); token = self.token(c, "/checkout")
        self.sql("UPDATE plants SET stock_quantity = 1 WHERE name = 'Boston Fern'")
        c.post("/checkout", data={**GOOD, "fulfillment": "pickup", "csrf_token": token})
        self.assertEqual(self.outbox, [])

    def test_a_broken_mail_server_never_breaks_registration_or_orders(self):
        self.app.extensions["mailer"].fail = True
        c = self.app.test_client(); self.assertEqual(self.register(c, "maria@example.com").status_code, 302)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users")[0]["n"], 1)
        r = self.order(c, [("Monstera", 1)]); self.assertEqual(r.status_code, 302)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 1)

    def test_names_with_html_are_escaped_in_the_html_email(self):
        c = self.app.test_client(); self.register(c, "x@example.com", "<script>alert(1)</script>")
        html = self.outbox[0].html
        self.assertNotIn("<script>alert(1)</script>", html); self.assertIn("&lt;script&gt;", html)


class TestPasswordReset(NotificationBase):
    def setUp(self):
        super().setUp()
        self.register(self.client, "maria@example.com"); self.client.post("/logout", data={"csrf_token": self.token(self.client, "/account")})
        self.outbox.clear()
        self.guest = self.app.test_client()

    def ask(self, address="maria@example.com", client=None):
        return self.post(client or self.guest, "/forgot-password", {"email": address}, page="/forgot-password")

    def link(self):
        return re.search(r"http://localhost(/reset-password/[\w.\-]+)", self.outbox[-1].text).group(1)

    def change(self, path, pw="NewPass123", cpw=None):
        return self.post(self.guest, path, {"password": pw, "confirm_password": cpw if cpw is not None else pw}, page="/forgot-password")   # token from a normal page (a bad link page has no form)

    def test_known_and_unknown_emails_get_the_same_answer(self):
        a = self.ask("maria@example.com"); b = self.ask("nobody@example.com", self.app.test_client())
        self.assertEqual((a.status_code, b.status_code, a.headers["Location"], b.headers["Location"]), (302, 302, "/login", "/login"))
        pages = [self.guest.get("/login").get_data(as_text=True), self.app.test_client().get("/login").get_data(as_text=True)]
        self.assertIn("If that email belongs to a GardenGo account", pages[0]); self.assertEqual(len(self.outbox), 1)      # only the real account got an email

    def test_reset_email_has_a_working_link(self):
        self.ask(); (m,) = self.outbox
        self.assertEqual((m.to, m.subject), ("maria@example.com", "Reset your GardenGo password")); self.assertIn("60 minutes", m.text)
        self.assertEqual(self.guest.get(self.link()).status_code, 200)

    def test_full_reset_flow_and_the_link_works_only_once(self):
        self.ask(); path = self.link()
        r = self.change(path); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/login"))
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "NewPass123").status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "Abcdef12").status_code, 401)             # the old password is dead
        self.assertEqual(self.mails_to("maria@example.com")[-1].subject, "Your GardenGo password was changed")
        self.assertEqual(self.guest.get(path).status_code, 400)                                                           # one use only
        self.assertEqual(self.change(path, "Another123").status_code, 400)
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "NewPass123").status_code, 302)

    def test_bad_new_passwords_are_refused_and_nothing_changes(self):
        self.ask(); path = self.link()
        for pw, cpw, msg in [("short1", "short1", "at least 8"), ("onlyletters", "onlyletters", "letters and numbers"), ("NewPass123", "Different123", "do not match"), ("Abcdef12", "Abcdef12", "not used before")]:
            r = self.change(path, pw, cpw); self.assertEqual(r.status_code, 400, pw); self.assertIn(msg, r.get_data(as_text=True), pw)
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "Abcdef12").status_code, 302)
        self.assertEqual(self.guest.get(path).status_code, 200)                                                           # link still usable

    def test_fake_and_tampered_links_are_refused(self):
        self.ask(); path = self.link(); token = path.rsplit("/", 1)[1]
        for bad in ["/reset-password/abc", "/reset-password/" + token[:-3] + "xyz", "/reset-password/" + token + "x", "/reset-password/..", "/reset-password/%27%20OR%201=1"]:
            self.assertEqual(self.guest.get(bad).status_code in (400, 404), True, bad)
        self.assertEqual(self.change("/reset-password/abc").status_code, 400)

    def test_expired_links_are_refused(self):
        self.ask(); path = self.link(); self.app.extensions["reset_tokens"].max_age = 1; time.sleep(2.1)
        r = self.guest.get(path); self.assertEqual(r.status_code, 400); self.assertIn("not valid", r.get_data(as_text=True))
        self.assertEqual(self.change(path).status_code, 400)

    def test_deactivated_and_admin_accounts_get_no_reset(self):
        self.sql("UPDATE users SET is_active = 0"); self.ask(); self.assertEqual(self.outbox, [])
        self.sql("UPDATE users SET is_active = 1"); self.ask(); path = self.link()
        self.sql("UPDATE users SET is_active = 0"); self.assertEqual(self.guest.get(path).status_code, 400)               # link dies if the account is deactivated
        self.sql("INSERT INTO users (full_name, email, password_hash, role) VALUES ('Owner', 'owner@example.com', ?, 'admin')", (generate_password_hash("AdminPass123"),))
        self.outbox.clear(); self.ask("owner@example.com", self.app.test_client()); self.assertEqual(self.outbox, [])

    def test_bad_email_input_is_refused_and_cannot_inject_headers(self):
        for bad in ["", "nope", "a@b.com\r\nBcc: spy@evil.com", "a@b.com, spy@evil.com", "a b@c.com"]:
            r = self.ask(bad, self.app.test_client()); self.assertEqual(r.status_code, 400, repr(bad))
        self.assertEqual(self.outbox, [])

    def test_the_form_needs_a_csrf_token_and_requests_are_rate_limited(self):
        self.assertEqual(self.guest.post("/forgot-password", data={"email": "maria@example.com"}).status_code, 400)
        self.assertEqual(self.guest.post("/reset-password/abc", data={"password": "x"}).status_code, 400)
        import security; security.reset_attempts_for_tests()
        for _ in range(5): self.ask("maria@example.com", self.guest)
        self.assertEqual(self.ask("maria@example.com", self.guest).status_code, 429); self.assertEqual(len(self.outbox), 5)  # no more than 5 emails

    def test_login_page_links_to_forgot_password(self):
        self.assertIn('href="/forgot-password"', self.guest.get("/login").get_data(as_text=True))
        self.assertEqual(self.guest.get("/forgot-password").status_code, 200)


class TestStatusEmails(AdminBase):
    @property
    def outbox(self): return self.app.extensions["mailer"].outbox

    def setUp(self):
        super().setUp()
        self.c = self.customer(); self.order(self.c, [("Monstera", 1)]); self.outbox.clear()

    def test_every_status_change_emails_the_customer_not_the_admin(self):
        for new, phrase in [("Confirmed", "confirmed your order"), ("Processing", "preparing your plants"), ("Ready for Pickup", "ready for pickup at Gripalda"),
                            ("Completed", "Thank you for shopping")]:
            self.outbox.clear(); self.status(2001, new); (m,) = self.outbox
            self.assertEqual(m.to, "maria@example.com"); self.assertEqual(m.subject, f"Your order GG-2001 is now: {new}")
            self.assertIn(phrase, m.text); self.assertIn("http://localhost/track?id=GG-2001", m.html); self.assertIn("\u20B1450.00", m.text)

    def test_delivery_orders_say_ready_for_delivery(self):
        self.sql("UPDATE orders SET fulfillment = 'delivery'")
        self.status(2001, "Confirmed"); self.status(2001, "Processing"); self.outbox.clear(); self.status(2001, "Ready for Pickup")
        self.assertEqual(self.outbox[0].subject, "Your order GG-2001 is now: Ready for Delivery"); self.assertIn("delivered to you", self.outbox[0].text)

    def test_cancelling_emails_the_customer(self):
        self.status(2001, "Cancelled"); self.assertIn("was cancelled", self.outbox[0].text)

    def test_refused_status_changes_send_nothing(self):
        for bad in ["Completed", "Pending", "Nonsense"]: self.status(2001, bad)
        self.assertEqual(self.outbox, [])

    def test_a_broken_mail_server_does_not_stop_the_status_change(self):
        self.app.extensions["mailer"].fail = True
        self.status(2001, "Confirmed"); self.assertEqual(self.order_status(), "Confirmed")

    def test_admin_page_tells_the_admin_that_the_customer_was_emailed(self):
        r = self.status(2001, "Confirmed"); self.assertIn("customer was emailed", self.admin.get(r.headers["Location"]).get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
