"""Tests for the 6-digit email codes (OTP): confirming a new customer's email, and the admin's 2-step login.
The tests use a fake clock, so nobody has to wait 10 minutes."""
import logging
import re
from datetime import datetime, timedelta

import otp as otp_module
from otp import OtpService
from tests.test_customer import Base
from werkzeug.security import generate_password_hash

ADMIN_PW = "AdminPass123"
logging.getLogger("gardengo.mail").setLevel(logging.CRITICAL)      # some tests break the mail server on purpose


class Clock:
    """A clock we can move forward in the tests."""
    def __init__(self):
        self.t = datetime(2026, 11, 20, 10, 0, 0)

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class OtpBase(Base):
    def app_config(self):
        self.clock = Clock()
        return {"REQUIRE_EMAIL_VERIFICATION": True, "ADMIN_2FA": True, "OTP_CLOCK": self.clock}

    @property
    def outbox(self):
        return self.app.extensions["mailer"].outbox

    def codes_for(self, address):
        return [re.search(r"is: (\d{6})", m.text).group(1) for m in self.outbox if m.to == address and "code" in m.subject.lower()]

    def last_code(self, address):
        return self.codes_for(address)[-1]

    def wrong_code(self, real):
        return "000000" if real != "000000" else "111111"

    def user_row(self, email):
        return self.sql("SELECT * FROM users WHERE email = ?", (email,))[0]

    def make_user(self, email="ana@example.com", role="customer", verified=1):
        self.sql("INSERT INTO users (full_name, email, password_hash, role, email_verified) VALUES (?, ?, ?, ?, ?)",
                 ("Ana Cruz" if role == "customer" else "Owner", email, generate_password_hash(ADMIN_PW), role, verified))
        return self.user_row(email)["id"]


# ---------------------------------------------------------------- the OtpService class by itself
class TestOtpService(OtpBase):
    def setUp(self):
        super().setUp()
        self.uid = self.make_user("ana@example.com")
        self.otp = self.app.extensions["otp"]
        self.ctx = self.app.app_context(); self.ctx.push()

    def tearDown(self):
        self.ctx.pop(); super().tearDown()

    def test_code_is_six_digits_saved_only_as_a_hash_and_works_once(self):
        code = self.otp.issue(self.uid, "verify_email")
        self.assertRegex(code, r"^[0-9]{6}$")
        row = self.sql("SELECT * FROM email_otps")[0]
        self.assertNotIn(code, str(row)); self.assertEqual(len(row["code_hash"]), 64)
        self.assertTrue(self.otp.verify(self.uid, "verify_email", code).ok)
        self.assertEqual(self.otp.verify(self.uid, "verify_email", code).status, "none")            # used up

    def test_codes_are_random(self):
        seen = set()
        for _ in range(20):
            self.clock.advance(minutes=3); seen.add(self.otp.issue(self.uid, "verify_email")); self.sql("DELETE FROM email_otps")
        self.assertGreater(len(seen), 15)

    def test_wrong_tries_are_counted_and_five_lock_the_code(self):
        code = self.otp.issue(self.uid, "verify_email"); bad = self.wrong_code(code)
        left = [self.otp.verify(self.uid, "verify_email", bad).attempts_left for _ in range(4)]
        self.assertEqual(left, [4, 3, 2, 1])
        self.assertEqual(self.otp.verify(self.uid, "verify_email", bad).status, "locked")
        self.assertFalse(self.otp.verify(self.uid, "verify_email", code).ok)                         # even the right code is dead now

    def test_codes_expire(self):
        code = self.otp.issue(self.uid, "verify_email"); self.clock.advance(minutes=10, seconds=1)
        self.assertEqual(self.otp.verify(self.uid, "verify_email", code).status, "expired")
        code = self.otp.issue(self.uid, "admin_login"); self.clock.advance(minutes=9, seconds=59)
        self.assertTrue(self.otp.verify(self.uid, "admin_login", code).ok)

    def test_a_new_code_cancels_the_old_one(self):
        old = self.otp.issue(self.uid, "verify_email"); self.clock.advance(seconds=61); new = self.otp.issue(self.uid, "verify_email")
        self.assertNotEqual(old, new)
        self.assertFalse(self.otp.verify(self.uid, "verify_email", old).ok); self.assertTrue(self.otp.verify(self.uid, "verify_email", new).ok)

    def test_waiting_time_and_hourly_limit(self):
        self.otp.issue(self.uid, "verify_email")
        with self.assertRaises(otp_module.OtpBlocked) as c: self.otp.issue(self.uid, "verify_email")
        self.assertIn("Please wait", str(c.exception))
        for _ in range(4): self.clock.advance(seconds=61); self.otp.issue(self.uid, "verify_email")       # 5 codes in total
        self.clock.advance(seconds=61)
        with self.assertRaises(otp_module.OtpBlocked) as c: self.otp.issue(self.uid, "verify_email")
        self.assertIn("Too many codes", str(c.exception))
        self.clock.advance(hours=1); self.assertRegex(self.otp.issue(self.uid, "verify_email"), r"^[0-9]{6}$")

    def test_a_code_works_only_for_its_own_purpose_and_person(self):
        other = self.make_user("ben@example.com")
        code = self.otp.issue(self.uid, "verify_email")
        self.assertFalse(self.otp.verify(self.uid, "admin_login", code).ok)                          # wrong purpose
        self.assertFalse(self.otp.verify(other, "verify_email", code).ok)                            # another person
        self.assertTrue(self.otp.verify(self.uid, "verify_email", code).ok)
        self.assertNotEqual(self.otp._hash(self.uid, "verify_email", "123456"), self.otp._hash(other, "verify_email", "123456"))

    def test_odd_input_is_just_a_wrong_code(self):
        self.otp.issue(self.uid, "verify_email")
        for bad in ["", "12345", "1234567", "abcdef", "12 456", " ", None, "\u0661\u0662\u0663\u0664\u0665\u0666", "123456\n", "1e5000", "'; DROP TABLE email_otps;--"]:
            self.assertFalse(self.otp.verify(self.uid, "verify_email", bad).ok, repr(bad))
            self.sql("UPDATE email_otps SET attempts = 0")
        self.assertEqual(len(self.sql("SELECT * FROM email_otps")), 1)

    def test_unknown_purpose_is_refused(self):
        with self.assertRaises(ValueError): self.otp.issue(self.uid, "make_me_admin")

    def test_mask_email(self):
        self.assertEqual(otp_module.mask_email("maria@gmail.com"), "m****@gmail.com"); self.assertEqual(otp_module.mask_email("jo@x.com"), "j**@x.com")


# ---------------------------------------------------------------- confirming a customer's email
class TestCustomerVerification(OtpBase):
    def sign_up(self, email="maria@example.com", name="Maria Santos", pw="Abcdef12", client=None, path="/register"):
        c = client or self.client
        return self.post(c, path, {"name": name, "email": email, "password": pw, "confirm_password": pw}, page="/register")

    def enter(self, code, client=None):
        c = client or self.client      # the CSRF token comes from the plants page, which always has one (the code page may redirect)
        return c.post("/verify-email", data={"code": code, "csrf_token": self.token(c, "/plants")})

    def test_signing_up_sends_a_code_and_does_not_log_in_yet(self):
        r = self.sign_up(); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/verify-email"))
        self.assertEqual(self.user_row("maria@example.com")["email_verified"], 0)
        (m,) = self.outbox; self.assertEqual((m.to, m.subject), ("maria@example.com", "Your GardenGo verification code")); self.assertRegex(m.text, r"is: \d{6}")
        self.assertIn("Never share", m.text); self.assertIn("10 minutes", m.html)
        for path in ["/account", "/my-orders", "/checkout"]: self.assertEqual(self.client.get(path).status_code, 302, path)
        self.assertEqual(len(self.outbox), 1)                                                         # no welcome email before confirming

    def test_the_right_code_confirms_the_email_and_logs_in(self):
        self.sign_up(); code = self.last_code("maria@example.com")
        r = self.enter(code); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/"))
        self.assertEqual(self.user_row("maria@example.com")["email_verified"], 1)
        self.assertEqual(self.client.get("/account").status_code, 200)
        self.assertEqual(self.outbox[-1].subject, "Welcome to GardenGo")
        self.assertEqual(self.enter(code).status_code, 302)                                          # the code is used up: sent to login, not accepted again

    def test_page_shows_a_masked_email_never_the_code(self):
        self.sign_up(); code = self.last_code("maria@example.com")
        html = self.client.get("/verify-email").get_data(as_text=True)
        self.assertIn("m****@example.com", html); self.assertNotIn(code, html); self.assertNotIn("maria@example.com", html)
        with self.client.session_transaction() as s: self.assertNotIn(code, str(dict(s)))

    def test_wrong_codes_show_tries_left_then_lock_until_a_new_code(self):
        self.sign_up(); code = self.last_code("maria@example.com"); bad = self.wrong_code(code)
        for left in [4, 3, 2, 1]:
            r = self.enter(bad); self.assertEqual(r.status_code, 400); self.assertIn(f"{left} {'try' if left == 1 else 'tries'} left", r.get_data(as_text=True))
        self.assertIn("Too many wrong tries", self.enter(bad).get_data(as_text=True))
        self.assertEqual(self.enter(code).status_code, 400)                                          # locked, even with the real code
        self.assertEqual(self.client.get("/account").status_code, 302)
        self.clock.advance(seconds=61); self.post(self.client, "/verify-email/resend", page="/verify-email")
        self.assertEqual(self.enter(self.last_code("maria@example.com")).status_code, 302)           # a fresh code works

    def test_codes_expire_after_ten_minutes(self):
        self.sign_up(); code = self.last_code("maria@example.com"); self.clock.advance(minutes=10, seconds=1)
        r = self.enter(code); self.assertEqual(r.status_code, 400); self.assertIn("expired", r.get_data(as_text=True))

    def test_resend_has_a_waiting_time_and_cancels_the_old_code(self):
        self.sign_up(); first = self.last_code("maria@example.com")
        r = self.post(self.client, "/verify-email/resend", page="/verify-email", follow_redirects=True)
        self.assertIn("Please wait", r.get_data(as_text=True)); self.assertEqual(len(self.codes_for("maria@example.com")), 1)
        self.clock.advance(seconds=61)
        r = self.post(self.client, "/verify-email/resend", page="/verify-email", follow_redirects=True)
        self.assertIn("sent a new code", r.get_data(as_text=True)); second = self.last_code("maria@example.com"); self.assertNotEqual(first, second)
        self.assertEqual(self.enter(first).status_code, 400); self.assertEqual(self.enter(second).status_code, 302)

    def test_logging_in_before_confirming_asks_for_the_code_again(self):
        self.sign_up(); self.clock.advance(seconds=61)
        c = self.app.test_client()
        r = self.post(c, "/login", {"email": "maria@example.com", "password": "Abcdef12"}); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/verify-email"))
        self.assertEqual(len(self.codes_for("maria@example.com")), 2); self.assertEqual(c.get("/account").status_code, 302)
        self.assertEqual(self.post(c, "/verify-email", {"code": self.last_code("maria@example.com")}, page="/verify-email").status_code, 302)
        self.assertEqual(c.get("/account").status_code, 200)
        wrong = self.post(self.app.test_client(), "/login", {"email": "maria@example.com", "password": "Wrong12345"}); self.assertEqual(wrong.status_code, 401)

    def test_the_page_needs_a_started_signup_and_the_start_expires(self):
        self.assertEqual(self.client.get("/verify-email").headers["Location"], "/login")
        self.sign_up(); self.assertEqual(self.client.get("/verify-email").status_code, 200)
        self.clock.advance(minutes=16); self.assertEqual(self.client.get("/verify-email").status_code, 302)

    def test_next_page_is_remembered_and_unsafe_ones_are_not(self):
        self.sign_up(path="/register?next=/my-orders")
        r = self.client.post("/register?next=/my-orders", data={})
        c = self.app.test_client()
        self.post(c, "/register?next=/my-orders", {"name": "Ben Reyes", "email": "ben@example.com", "password": "Abcdef12", "confirm_password": "Abcdef12"}, page="/register")
        self.assertEqual(self.post(c, "/verify-email", {"code": self.last_code("ben@example.com")}, page="/verify-email").headers["Location"], "/my-orders")
        d = self.app.test_client()
        self.post(d, "/register?next=https://evil.com", {"name": "Cy Lim", "email": "cy@example.com", "password": "Abcdef12", "confirm_password": "Abcdef12"}, page="/register")
        self.assertEqual(self.post(d, "/verify-email", {"code": self.last_code("cy@example.com")}, page="/verify-email").headers["Location"], "/")

    def test_an_unconfirmed_email_can_be_taken_over_but_a_confirmed_one_cannot(self):
        self.sign_up(name="Typo Name", pw="Firstpass12"); self.clock.advance(seconds=61)
        c = self.app.test_client(); r = self.sign_up(name="Real Maria", pw="Secondpass34", client=c); self.assertEqual(r.status_code, 302)
        row = self.user_row("maria@example.com"); self.assertEqual(row["full_name"], "Real Maria"); self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users")[0]["n"], 1)
        self.assertEqual(self.post(c, "/verify-email", {"code": self.last_code("maria@example.com")}, page="/verify-email").status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "Firstpass12").status_code, 401)        # the first password is gone
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "Secondpass34").status_code, 302)
        r = self.sign_up(name="Thief", pw="Thiefpass12", client=self.app.test_client()); self.assertEqual(r.status_code, 400); self.assertIn("already exists", r.get_data(as_text=True))
        self.assertEqual(self.user_row("maria@example.com")["full_name"], "Real Maria")

    def test_a_forged_session_cannot_skip_the_code(self):
        self.sign_up()
        with self.client.session_transaction() as s: s["user_id"] = self.user_row("maria@example.com")["id"]
        self.assertEqual(self.client.get("/account").status_code, 302)

    def test_resetting_the_password_by_email_also_confirms_the_email(self):
        self.sign_up(); self.client.get("/login")
        c = self.app.test_client(); self.post(c, "/forgot-password", {"email": "maria@example.com"}, page="/forgot-password")
        link = re.search(r"http://localhost(/reset-password/[\w.\-]+)", self.outbox[-1].text).group(1)
        self.post(c, link, {"password": "NewPass123", "confirm_password": "NewPass123"}, page="/forgot-password")
        self.assertEqual(self.user_row("maria@example.com")["email_verified"], 1)
        self.assertEqual(self.login(self.app.test_client(), "maria@example.com", "NewPass123").headers["Location"], "/")

    def test_a_broken_mail_server_does_not_break_signing_up(self):
        self.app.extensions["mailer"].fail = True
        r = self.sign_up(); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/verify-email"))
        self.app.extensions["mailer"].fail = False; self.clock.advance(seconds=61)
        self.post(self.client, "/verify-email/resend", page="/verify-email"); self.assertEqual(self.enter(self.last_code("maria@example.com")).status_code, 302)

    def test_forms_need_a_csrf_token_and_deactivated_people_are_stopped(self):
        self.sign_up()
        self.assertEqual(self.client.post("/verify-email", data={"code": "123456"}).status_code, 400)
        self.assertEqual(self.client.post("/verify-email/resend").status_code, 400)
        code = self.last_code("maria@example.com"); self.sql("UPDATE users SET is_active = 0")
        self.assertEqual(self.client.get("/verify-email").status_code, 302); self.assertEqual(self.enter(code).status_code, 302)
        self.assertEqual(self.user_row("maria@example.com")["email_verified"], 0)

    def test_admin_code_cannot_be_used_on_the_customer_page_and_the_switch_can_turn_it_off(self):
        self.app.config["REQUIRE_EMAIL_VERIFICATION"] = False
        c = self.app.test_client(); r = self.sign_up(client=c, email="free@example.com"); self.assertEqual(r.headers["Location"], "/")
        self.assertEqual(c.get("/account").status_code, 200); self.assertEqual(self.user_row("free@example.com")["email_verified"], 1)


# ---------------------------------------------------------------- the admin's 2-step login
class TestAdminTwoStepLogin(OtpBase):
    def setUp(self):
        super().setUp()
        self.admin_id = self.make_user("owner@example.com", role="admin")
        self.guest = self.app.test_client()

    def password_step(self, client=None, pw=ADMIN_PW, path="/admin/login"):
        return self.post(client or self.guest, path, {"email": "owner@example.com", "password": pw}, page="/admin/login")

    def code_step(self, code, client=None):
        return self.post(client or self.guest, "/admin/verify", {"code": code}, page="/admin/login")

    def test_right_password_alone_is_not_enough(self):
        r = self.password_step(); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/admin/verify"))
        for path in ["/admin/", "/admin/plants", "/admin/orders"]: self.assertEqual(self.guest.get(path).status_code, 302, path)
        (m,) = self.outbox; self.assertEqual((m.to, m.subject), ("owner@example.com", "Your GardenGo admin login code")); self.assertIn("admin site", m.text)

    def test_the_right_code_finishes_the_login(self):
        self.password_step(); r = self.code_step(self.last_code("owner@example.com"))
        self.assertEqual((r.status_code, r.headers["Location"]), (302, "/admin/")); self.assertEqual(self.guest.get("/admin/").status_code, 200)

    def test_a_wrong_password_sends_no_code(self):
        r = self.password_step(pw="WrongPass123"); self.assertEqual(r.status_code, 401); self.assertEqual(self.outbox, [])
        self.assertEqual(self.guest.get("/admin/verify").status_code, 302)

    def test_wrong_codes_are_refused_and_five_lock_it(self):
        self.password_step(); code = self.last_code("owner@example.com"); bad = self.wrong_code(code)
        for _ in range(4): self.assertEqual(self.code_step(bad).status_code, 400)
        self.assertIn("Too many wrong tries", self.code_step(bad).get_data(as_text=True))
        self.assertEqual(self.code_step(code).status_code, 400); self.assertEqual(self.guest.get("/admin/").status_code, 302)
        self.clock.advance(seconds=61); self.post(self.guest, "/admin/verify/resend", page="/admin/verify")
        self.assertEqual(self.code_step(self.last_code("owner@example.com")).status_code, 302)

    def test_a_code_works_only_once_and_expires(self):
        self.password_step(); code = self.last_code("owner@example.com"); self.code_step(code)
        self.post(self.guest, "/admin/logout", page="/admin/"); self.clock.advance(seconds=61); self.password_step()
        self.assertEqual(self.code_step(code).status_code, 400)                                       # the old code is dead
        new = self.last_code("owner@example.com"); self.assertNotEqual(new, code)
        self.clock.advance(minutes=10, seconds=1); self.assertIn("expired", self.code_step(new).get_data(as_text=True))

    def test_the_password_step_expires(self):
        self.password_step(); self.clock.advance(minutes=16)
        self.assertEqual(self.guest.get("/admin/verify").status_code, 302); self.assertEqual(self.guest.get("/admin/verify").headers["Location"], "/admin/login")

    def test_resend_waits_and_cancels_the_old_code(self):
        self.password_step(); first = self.last_code("owner@example.com")
        r = self.post(self.guest, "/admin/verify/resend", page="/admin/verify", follow_redirects=True); self.assertIn("Please wait", r.get_data(as_text=True))
        self.clock.advance(seconds=61); self.post(self.guest, "/admin/verify/resend", page="/admin/verify"); second = self.last_code("owner@example.com")
        self.assertEqual(self.code_step(first).status_code, 400); self.assertEqual(self.code_step(second).status_code, 302)

    def test_next_page_is_kept_and_unsafe_ones_are_ignored(self):
        self.password_step(path="/admin/login?next=/admin/orders")
        self.assertEqual(self.code_step(self.last_code("owner@example.com")).headers["Location"], "/admin/orders")
        c = self.app.test_client(); self.clock.advance(seconds=61)
        self.password_step(c, path="/admin/login?next=https://evil.com"); self.assertEqual(self.code_step(self.last_code("owner@example.com"), c).headers["Location"], "/admin/")

    def test_codes_do_not_cross_between_admin_and_customer_pages(self):
        self.make_user("ana@example.com", verified=0)
        cust = self.app.test_client(); self.post(cust, "/login", {"email": "ana@example.com", "password": ADMIN_PW})
        customer_code = self.last_code("ana@example.com")
        self.clock.advance(seconds=61); self.password_step(); self.assertNotEqual(customer_code, self.last_code("owner@example.com"))
        r = self.code_step(customer_code if customer_code != self.last_code("owner@example.com") else "999999"); self.assertEqual(r.status_code, 400)
        self.assertEqual(cust.get("/admin/verify").headers["Location"], "/admin/login")                # a customer's pending state does not open the admin page
        self.assertEqual(self.guest.get("/verify-email").headers["Location"], "/login")                 # and the other way around

    def test_a_customer_account_cannot_use_the_admin_second_step(self):
        cid = self.make_user("ana@example.com")
        with self.guest.session_transaction() as s: s["pending_admin"] = {"uid": cid, "next": "", "at": self.clock().timestamp()}
        self.assertEqual(self.guest.get("/admin/verify").headers["Location"], "/admin/login")
        self.assertEqual(self.password_step(self.app.test_client(), pw="x").status_code, 401)

    def test_a_deactivated_admin_cannot_finish(self):
        self.password_step(); code = self.last_code("owner@example.com"); self.sql("UPDATE users SET is_active = 0")
        self.assertEqual(self.code_step(code).status_code, 302); self.assertEqual(self.guest.get("/admin/").status_code, 302)

    def test_forms_need_a_csrf_token(self):
        self.password_step()
        self.assertEqual(self.guest.post("/admin/verify", data={"code": "123456"}).status_code, 400)
        self.assertEqual(self.guest.post("/admin/verify/resend").status_code, 400)

    def test_the_code_page_never_shows_the_code_or_the_full_email(self):
        self.password_step(); code = self.last_code("owner@example.com"); html = self.guest.get("/admin/verify").get_data(as_text=True)
        self.assertIn("o****@example.com", html); self.assertNotIn(code, html); self.assertNotIn("owner@example.com", html)
        with self.guest.session_transaction() as s: self.assertNotIn(code, str(dict(s)))

    def test_switching_2fa_off_gives_the_old_one_step_login(self):
        self.app.config["ADMIN_2FA"] = False
        r = self.password_step(); self.assertEqual(r.headers["Location"], "/admin/"); self.assertEqual(self.outbox, [])
        self.assertEqual(self.guest.get("/admin/").status_code, 200)

    def test_a_broken_mail_server_does_not_crash_the_login(self):
        self.app.extensions["mailer"].fail = True
        r = self.password_step(); self.assertEqual((r.status_code, r.headers["Location"]), (302, "/admin/verify"))


if __name__ == "__main__":
    import unittest; unittest.main()