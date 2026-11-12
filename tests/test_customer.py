"""Automatic tests for the customer side. Run:  python -m unittest discover -s tests -v
They use a temporary SQLite database, so they never touch your real MySQL data."""
import os
import re
import tempfile
import unittest
from decimal import Decimal

import security
import services
from app import create_app
from tests import sqlite_shim
from werkzeug.security import generate_password_hash

GOOD = {"name": "Maria Santos", "phone": "0917 123 4567", "address": "12 Rizal St., Brgy. Uno", "city": "Bay", "province": "Laguna", "notes": ""}


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        sqlite_shim.create_database(self.path)
        self.fail_on = []
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "DB_FACTORY": sqlite_shim.make_factory(self.path, self.fail_on), **self.app_config()})
        security.reset_attempts_for_tests()
        self.sql("INSERT INTO categories (name) VALUES ('Indoor'), ('Outdoor'), ('Succulent')")
        for name, cat, price, stock, avail in [("Monstera", 1, "450.00", 12, 1), ("Snake Plant", 1, "280.00", 25, 1), ("Boston Fern", 1, "220.00", 3, 1),
                                               ("Yellow Ixora", 2, "180.00", 0, 1), ("Echeveria", 3, "120.00", 40, 1), ("Hidden Plant", 3, "99.00", 5, 0)]:
            self.sql("INSERT INTO plants (category_id, name, description, price, stock_quantity, is_available) VALUES (?, ?, 'Nice plant', ?, ?, ?)",
                     (cat, name, price, stock, avail))
        self.client = self.app.test_client()

    def tearDown(self):
        leaked = list(sqlite_shim.OPEN)
        for conn in leaked:
            conn.close()
        try:
            os.unlink(self.path)
        finally:
            self.assertEqual(leaked, [], "a database connection was left open")

    def app_config(self):
        """Most tests run with the OTP steps switched off (they are tested on their own in test_otp.py)."""
        return {"REQUIRE_EMAIL_VERIFICATION": False, "ADMIN_2FA": False}

    # ---- helpers
    def sql(self, query, args=()):
        import sqlite3
        c = sqlite3.connect(self.path)
        try:                                   # always close, even when the query fails (an open file cannot be deleted on Windows)
            c.row_factory = sqlite3.Row
            cur = c.execute(query, args); rows = [dict(r) for r in cur.fetchall()] if cur.description else []
            c.commit()
            return rows
        finally:
            c.close()

    def token(self, client, path="/login"):
        html = client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)

    def post(self, client, path, data=None, page="/login", **kw):
        data = dict(data or {}); data["csrf_token"] = self.token(client, page)
        return client.post(path, data=data, **kw)

    def register(self, client, email="maria@example.com", name="Maria Santos", pw="Abcdef12"):
        return self.post(client, "/register", {"name": name, "email": email, "password": pw, "confirm_password": pw}, page="/register")

    def login(self, client, email="maria@example.com", pw="Abcdef12"):
        return self.post(client, "/login", {"email": email, "password": pw})

    def plant_id(self, name):
        return self.sql("SELECT id FROM plants WHERE name = ?", (name,))[0]["id"]

    def stock(self, name):
        return self.sql("SELECT stock_quantity AS s FROM plants WHERE name = ?", (name,))[0]["s"]

    def add_to_cart(self, client, name, qty=1, **extra):
        return self.post(client, "/cart/add", {"plant_id": self.plant_id(name), "qty": qty, **extra}, page="/plants")

    def customer(self, email="maria@example.com", name="Maria Santos"):
        c = self.app.test_client(); self.register(c, email, name); return c

    def order(self, client, items, **over):
        for name, qty in items:
            self.add_to_cart(client, name, qty)
        data = {**GOOD, "fulfillment": "pickup", **over}
        return self.post(client, "/checkout", data, page="/checkout")


class TestSecurity(Base):
    def test_post_without_csrf_token_is_refused(self):
        self.assertEqual(self.client.post("/login", data={"email": "a@b.com", "password": "x"}).status_code, 400)
        self.assertEqual(self.client.post("/logout").status_code, 400)
        self.assertEqual(self.client.post("/cart/add", data={"plant_id": 1}).status_code, 400)

    def test_wrong_csrf_token_is_refused(self):
        self.client.get("/login")
        self.assertEqual(self.client.post("/login", data={"csrf_token": "wrong", "email": "a@b.com", "password": "x"}).status_code, 400)

    def test_login_and_register_cards_use_the_centering_wrapper(self):
        for path in ["/login", "/register"]:
            html = self.client.get(path).get_data(as_text=True)
            self.assertIn('<section class="auth-wrap">', html, path); self.assertIn('class="auth-card card"', html, path)

    def test_security_headers_and_cookie_flags(self):
        r = self.client.get("/login")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=Lax", cookie)

    def test_open_redirect_is_blocked(self):
        self.register(self.client); self.client.post("/logout", data={"csrf_token": self.token(self.client, "/account")})
        for bad in ["https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)"]:
            r = self.post(self.client, "/login?next=" + bad, {"email": "maria@example.com", "password": "Abcdef12"})
            self.assertEqual(r.status_code, 302)
            self.assertNotIn("evil", r.headers["Location"]); self.assertEqual(r.headers["Location"], "/")
            self.client.post("/logout", data={"csrf_token": self.token(self.client, "/account")})

    def test_next_to_own_page_is_allowed(self):
        self.register(self.client); self.client.post("/logout", data={"csrf_token": self.token(self.client, "/account")})
        r = self.post(self.client, "/login?next=/my-orders", {"email": "maria@example.com", "password": "Abcdef12"})
        self.assertEqual(r.headers["Location"], "/my-orders")

    def test_sql_injection_text_in_search_is_harmless(self):
        for q in ["' OR 1=1 --", "'; DROP TABLE plants; --", "%", "_"]:
            r = self.client.get("/plants", query_string={"q": q})
            self.assertEqual(r.status_code, 200)
            self.assertIn("No plants match", r.get_data(as_text=True))
        self.assertEqual(len(self.sql("SELECT id FROM plants")), 6)

    def test_html_in_names_is_escaped(self):
        c = self.app.test_client(); self.register(c, "x@example.com", "<script>alert(1)</script>")
        html = c.get("/account").get_data(as_text=True) + c.get("/").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html); self.assertIn("&lt;script&gt;", html)


class TestAccounts(Base):
    def test_register_hashes_password_and_logs_in(self):
        r = self.register(self.client)
        self.assertEqual(r.status_code, 302)
        row = self.sql("SELECT password_hash, role FROM users")[0]
        self.assertNotEqual(row["password_hash"], "Abcdef12"); self.assertNotIn("Abcdef12", row["password_hash"]); self.assertEqual(row["role"], "customer")
        self.assertEqual(self.client.get("/account").status_code, 200)

    def test_register_validation(self):
        for pw, cpw, msg in [("short1", "short1", "at least 8"), ("onlyletters", "onlyletters", "letters and numbers"), ("Abcdef12", "Abcdef13", "do not match")]:
            r = self.post(self.client, "/register", {"name": "Maria", "email": "m@example.com", "password": pw, "confirm_password": cpw}, page="/register")
            self.assertEqual(r.status_code, 400); self.assertIn(msg, r.get_data(as_text=True))
        r = self.post(self.client, "/register", {"name": "M", "email": "nope", "password": "Abcdef12", "confirm_password": "Abcdef12"}, page="/register")
        self.assertIn("valid email", r.get_data(as_text=True)); self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users")[0]["n"], 0)

    def test_duplicate_email_is_rejected_even_with_different_case(self):
        self.register(self.client)
        r = self.register(self.app.test_client(), email="MARIA@Example.com")
        self.assertEqual(r.status_code, 400); self.assertIn("already exists", r.get_data(as_text=True))
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users")[0]["n"], 1)

    def test_login_and_logout(self):
        self.register(self.client)
        self.post(self.client, "/logout", page="/account")
        self.assertEqual(self.client.get("/account").status_code, 302)          # logged out: sent to login
        r = self.login(self.client); self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/account").status_code, 200)

    def test_wrong_password_and_unknown_email_look_the_same(self):
        self.register(self.client)
        a = self.login(self.app.test_client(), pw="WrongPass1"); b = self.login(self.app.test_client(), email="nobody@example.com")
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        for r in (a, b): self.assertIn("Email or password is incorrect.", r.get_data(as_text=True))

    def test_too_many_wrong_passwords_are_slowed_down(self):
        self.register(self.client)
        c = self.app.test_client()
        for _ in range(5): self.login(c, pw="WrongPass1")
        self.assertEqual(self.login(c, pw="Abcdef12").status_code, 429)          # even the right password waits

    def test_deactivated_customer_cannot_log_in_and_is_logged_out(self):
        self.register(self.client)
        self.sql("UPDATE users SET is_active = 0")
        self.assertEqual(self.client.get("/account").status_code, 302)           # existing session is dropped
        self.assertEqual(self.login(self.app.test_client()).status_code, 401)

    def test_admin_cannot_use_customer_pages(self):
        self.sql("INSERT INTO users (full_name, email, password_hash, role) VALUES ('Owner', 'owner@example.com', ?, 'admin')", (generate_password_hash("Abcdef12"),))
        self.assertEqual(self.login(self.app.test_client(), "owner@example.com").status_code, 401)   # customer login refuses admins
        with self.client.session_transaction() as s: s["user_id"] = 1
        for path in ["/checkout", "/my-orders", "/account", "/track"]:
            self.assertEqual(self.client.get(path).status_code, 403, path)

    def test_pages_need_login(self):
        for path in ["/checkout", "/my-orders", "/account", "/track", "/orders/2001", "/orders/2001/confirmation"]:
            r = self.client.get(path); self.assertEqual(r.status_code, 302, path); self.assertIn("/login", r.headers["Location"])

    def test_profile_update(self):
        c = self.customer()
        r = self.post(c, "/account", {"name": "M", "phone": "123", "address": "", "city": "", "province": ""}, page="/account")
        self.assertEqual(r.status_code, 400); self.assertIn("valid PH mobile", r.get_data(as_text=True))
        r = self.post(c, "/account", {"name": "Maria S.", "phone": "0917-123-4567", "address": "1 Main St", "city": "Bay", "province": "Laguna"}, page="/account")
        self.assertEqual(r.status_code, 302)
        row = self.sql("SELECT full_name, phone FROM users")[0]; self.assertEqual((row["full_name"], row["phone"]), ("Maria S.", "09171234567"))


class TestCatalogAndCart(Base):
    def test_catalog_shows_only_available_plants(self):
        html = self.client.get("/plants").get_data(as_text=True)
        self.assertIn("Monstera", html); self.assertNotIn("Hidden Plant", html); self.assertIn("Showing 5 of 5 plants", html)

    def test_search_filter_and_sort(self):
        self.assertIn("Boston Fern", self.client.get("/plants?q=fern").get_data(as_text=True))
        self.assertNotIn("Monstera", self.client.get("/plants?q=fern").get_data(as_text=True))
        html = self.client.get("/plants?category=Succulent").get_data(as_text=True)
        self.assertIn("Echeveria", html); self.assertNotIn("Snake Plant", html)
        names = re.findall(r'<h3><a href="/plants/\d+">([^<]+)</a></h3>', self.client.get("/plants?sort=price-asc").get_data(as_text=True))
        self.assertEqual(names, ["Echeveria", "Boston Fern", "Yellow Ixora", "Snake Plant", "Monstera"][:0] or ["Echeveria", "Yellow Ixora", "Boston Fern", "Snake Plant", "Monstera"])
        out = self.client.get("/plants?availability=out").get_data(as_text=True)
        self.assertIn("Yellow Ixora", out); self.assertNotIn("Monstera", out)
        self.assertEqual(self.client.get("/plants?sort=;DROP").status_code, 200)

    def test_plant_details_and_hidden_plant(self):
        self.assertEqual(self.client.get(f"/plants/{self.plant_id('Monstera')}").status_code, 200)
        self.assertEqual(self.client.get(f"/plants/{self.plant_id('Hidden Plant')}").status_code, 404)
        self.assertEqual(self.client.get("/plants/9999").status_code, 404)

    def test_cart_add_update_remove(self):
        self.add_to_cart(self.client, "Monstera", 2); self.add_to_cart(self.client, "Monstera", 1)
        self.assertIn('value="3"', self.client.get("/cart").get_data(as_text=True))
        pid = self.plant_id("Monstera")
        self.post(self.client, "/cart/update", {"plant_id": pid, "qty": 99}, page="/cart")
        self.assertIn('value="10"', self.client.get("/cart").get_data(as_text=True))                  # limited to 10 per order
        self.post(self.client, "/cart/update", {"plant_id": pid, "qty": 0}, page="/cart")
        self.assertIn('value="1"', self.client.get("/cart").get_data(as_text=True))
        self.post(self.client, "/cart/remove", {"plant_id": pid}, page="/cart")
        self.assertIn("Your cart is empty", self.client.get("/cart").get_data(as_text=True))

    def test_cart_is_limited_by_stock_and_refuses_out_of_stock(self):
        self.add_to_cart(self.client, "Boston Fern", 9)                                               # stock is 3
        self.assertIn('value="3"', self.client.get("/cart").get_data(as_text=True))
        r = self.add_to_cart(self.client, "Yellow Ixora", 1, next="/plants")
        self.assertIn("out of stock", self.client.get("/plants").get_data(as_text=True))
        self.assertNotIn("Yellow Ixora</a></h3><p class=\"unit\"", self.client.get("/cart").get_data(as_text=True))

    def test_bad_quantities_are_ignored(self):
        for qty in ["abc", "0", "-3", "1.5", ""]:
            self.add_to_cart(self.client, "Monstera", qty)
        self.assertIn("Your cart is empty", self.client.get("/cart").get_data(as_text=True))
        self.post(self.client, "/cart/add", {"plant_id": "abc", "qty": 1}, page="/plants")
        self.post(self.client, "/cart/add", {"plant_id": self.plant_id("Hidden Plant"), "qty": 1}, page="/plants")
        self.assertIn("Your cart is empty", self.client.get("/cart").get_data(as_text=True))

    def test_tampered_cart_cookie_values_are_cleaned(self):
        with self.client.session_transaction() as s: s["cart"] = {"abc": 1, str(self.plant_id("Monstera")): 50, "99999": 2, "5": -4}
        html = self.client.get("/cart").get_data(as_text=True)
        self.assertIn('value="10"', html); self.assertEqual(html.count('class="cart-item"'), 1)


class TestOrders(Base):
    def test_order_is_saved_with_correct_items_total_stock_and_history(self):
        c = self.customer()
        r = self.order(c, [("Monstera", 2), ("Echeveria", 3)], fulfillment="delivery")
        self.assertEqual(r.status_code, 302); self.assertEqual(r.headers["Location"], "/orders/2001/confirmation")
        o = self.sql("SELECT * FROM orders")[0]
        self.assertEqual((o["status"], o["fulfillment"], o["contact_phone"]), ("Pending", "delivery", "09171234567"))
        self.assertEqual(Decimal(str(o["total_amount"])), Decimal("1340.00"))                     # 450*2 + 120*3 + 80 delivery
        items = {i["plant_name"]: i for i in self.sql("SELECT * FROM order_items")}
        self.assertEqual((items["Monstera"]["quantity"], items["Echeveria"]["quantity"]), (2, 3))
        self.assertEqual((self.stock("Monstera"), self.stock("Echeveria")), (10, 37))
        mv = self.sql("SELECT plant_id, quantity_change, balance_after, order_id FROM stock_movements ORDER BY id")
        self.assertEqual([(m["quantity_change"], m["balance_after"], m["order_id"]) for m in mv], [(-2, 10, 2001), (-3, 37, 2001)])
        self.assertIn("GG-2001", c.get("/orders/2001/confirmation").get_data(as_text=True))
        self.assertIn("Your cart is empty", c.get("/cart").get_data(as_text=True))                  # cart cleared

    def test_pickup_has_no_delivery_fee(self):
        c = self.customer(); self.order(c, [("Snake Plant", 1)])
        o = self.sql("SELECT delivery_fee, total_amount FROM orders")[0]
        self.assertEqual((Decimal(str(o["delivery_fee"])), Decimal(str(o["total_amount"]))), (Decimal("0"), Decimal("280")))

    def test_old_orders_keep_their_price_after_the_plant_price_changes(self):
        c = self.customer(); self.order(c, [("Monstera", 1)])
        self.sql("UPDATE plants SET price = 999.00 WHERE name = 'Monstera'")
        html = c.get("/orders/2001").get_data(as_text=True)
        self.assertIn("₱450.00", html); self.assertNotIn("₱999.00", html)

    def test_buy_now_goes_to_checkout(self):
        c = self.customer()
        r = self.post(c, "/cart/add", {"plant_id": self.plant_id("Snake Plant"), "qty": 1, "buy_now": "1"}, page="/plants")
        self.assertEqual(r.headers["Location"], "/checkout")

    def test_not_enough_stock_rejects_whole_order_and_changes_nothing(self):
        c = self.customer(); self.add_to_cart(c, "Boston Fern", 3); self.add_to_cart(c, "Monstera", 2)
        token = self.token(c, "/checkout")                                                         # the customer opens the checkout page...
        self.sql("UPDATE plants SET stock_quantity = 1 WHERE name = 'Boston Fern'")               # ...someone else buys some plants meanwhile...
        r = c.post("/checkout", data={**GOOD, "fulfillment": "pickup", "csrf_token": token})        # ...and then the customer presses Place order
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 400); self.assertIn("only 1 left in stock", html)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 0)                  # the order was NOT placed with fewer plants
        self.assertEqual((self.stock("Boston Fern"), self.stock("Monstera")), (1, 12))             # nothing was taken
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM stock_movements")[0]["n"], 0)
        self.assertIn("updated your cart", html)                                                   # cart is fixed for the next try
        r = self.post(c, "/checkout", {**GOOD, "fulfillment": "pickup"}, page="/checkout")          # customer reviews and tries again
        self.assertEqual(r.status_code, 302)
        self.assertEqual((self.stock("Boston Fern"), self.stock("Monstera")), (0, 10))

    def test_service_rejects_invalid_quantities_and_never_touches_stock(self):
        c = self.customer()
        user = self.sql("SELECT id FROM users")[0]
        pid = self.plant_id("Monstera"); fern = self.plant_id("Boston Fern"); ix = self.plant_id("Yellow Ixora")
        details = {**GOOD, "fulfillment": "pickup"}
        with self.app.test_request_context():
            for bad in [{pid: 0}, {pid: -1}, {pid: 11}, {fern: 4}, {ix: 1}, {9999: 1}, {}]:
                with self.assertRaises(services.OrderRejected, msg=str(bad)):
                    services.place_order(user, bad, details)
            with self.assertRaises(services.OrderRejected):
                services.place_order(user, {pid: 1}, {**details, "fulfillment": "drone"})
            with self.assertRaises(services.OrderRejected):
                services.place_order(user, {pid: 1}, {**details, "phone": "123"})
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 0); self.assertEqual(self.stock("Monstera"), 12)

    def test_a_crash_in_the_middle_of_an_order_saves_nothing(self):
        c = self.customer(); self.add_to_cart(c, "Monstera", 2); self.add_to_cart(c, "Echeveria", 1)
        user = self.sql("SELECT id FROM users")[0]
        self.fail_on.append("INSERT INTO stock_movements")                                         # simulate a failure near the end
        with self.app.test_request_context():
            with self.assertRaises(RuntimeError):
                services.place_order(user, {self.plant_id("Monstera"): 2, self.plant_id("Echeveria"): 1}, {**GOOD, "fulfillment": "pickup"})
        self.fail_on.clear()
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM order_items")[0]["n"], 0)
        self.assertEqual((self.stock("Monstera"), self.stock("Echeveria")), (12, 40))               # stock was put back (rolled back)

    def test_checkout_form_validation_shows_errors_and_saves_nothing(self):
        c = self.customer(); self.add_to_cart(c, "Monstera", 1)
        r = self.post(c, "/checkout", {"name": "", "phone": "123", "address": "x", "city": "", "province": "", "fulfillment": "pickup", "notes": ""}, page="/checkout")
        html = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 400)
        for msg in ["full name", "valid PH mobile", "street address", "city", "province"]: self.assertIn(msg, html)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 0)

    def test_empty_cart_cannot_check_out(self):
        c = self.customer()
        self.assertEqual(c.get("/checkout").status_code, 302)
        r = self.post(c, "/checkout", {**GOOD, "fulfillment": "pickup"}, page="/plants")
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 0)

    def test_order_history_lists_only_own_orders(self):
        a = self.customer("a@example.com", "Ana A"); b = self.customer("b@example.com", "Ben B")
        self.order(a, [("Monstera", 1)]); self.order(b, [("Snake Plant", 1)])
        self.assertIn("GG-2001", a.get("/my-orders").get_data(as_text=True)); self.assertNotIn("GG-2002", a.get("/my-orders").get_data(as_text=True))
        self.assertIn("GG-2002", b.get("/my-orders").get_data(as_text=True)); self.assertNotIn("GG-2001", b.get("/my-orders").get_data(as_text=True))

    def test_customers_cannot_see_each_others_orders(self):
        a = self.customer("a@example.com", "Ana A"); b = self.customer("b@example.com", "Ben B")
        self.order(a, [("Monstera", 1)])
        self.assertEqual(a.get("/orders/2001").status_code, 200)
        for path in ["/orders/2001", "/orders/2001/confirmation"]:
            self.assertEqual(b.get(path).status_code, 404, path)
        html = b.get("/track?id=GG-2001").get_data(as_text=True)
        self.assertIn("could not find", html); self.assertNotIn("Monstera", html); self.assertNotIn("Ana A", html)
        self.assertEqual(b.get("/orders/9999").status_code, 404)

    def test_customer_has_no_way_to_change_order_status(self):
        a = self.customer(); self.order(a, [("Monstera", 1)])
        for method, path in [("post", "/orders/2001"), ("post", "/orders/2001/status"), ("post", "/orders/2001/cancel"), ("put", "/orders/2001")]:
            r = getattr(a, method)(path, data={"csrf_token": self.token(a, "/account"), "status": "Completed"})
            self.assertIn(r.status_code, (404, 405), path)
        self.assertEqual(self.sql("SELECT status FROM orders")[0]["status"], "Pending")


class TestTracking(Base):
    def setUp(self):
        super().setUp()
        self.c = self.customer(); self.order(self.c, [("Monstera", 1)])

    def track(self, value): return self.c.get("/track", query_string={"id": value})

    def test_timeline_follows_the_status_saved_in_the_database(self):
        for status, done, current in [("Pending", 0, "Order placed"), ("Confirmed", 1, "Order confirmed"), ("Processing", 2, "Order processing"),
                                      ("Ready for Pickup", 3, "Ready for pickup"), ("Completed", 4, "Order completed")]:
            self.sql("UPDATE orders SET status = ?", (status,))
            html = self.track("GG-2001").get_data(as_text=True)
            self.assertEqual(html.count('class="done"'), done, status)
            self.assertRegex(html, r'<li class="current" aria-current="step">\s*<span class="dot">\d</span><span class="tl-label">' + current)

    def test_cancelled_order_shows_cancellation_not_timeline(self):
        self.sql("UPDATE orders SET status = 'Cancelled'")
        html = self.track("gg-2001").get_data(as_text=True)
        self.assertIn("This order was cancelled", html); self.assertNotIn('class="timeline"', html)

    def test_delivery_order_wording(self):
        self.sql("UPDATE orders SET status = 'Ready for Pickup', fulfillment = 'delivery'")
        html = self.track("GG-2001").get_data(as_text=True); self.assertIn("Ready for Delivery", html); self.assertIn("Ready for delivery", html)

    def test_shows_date_items_quantity_and_total(self):
        html = self.track("GG-2001").get_data(as_text=True)
        for text in ["Order date:", "Monstera", "₱450.00", "Current status:"]: self.assertIn(text, html)

    def test_bad_input_messages(self):
        self.assertIn("Enter your order ID", self.track("").get_data(as_text=True))
        self.assertIn("look like GG-2001", self.track("hello").get_data(as_text=True))
        self.assertIn("look like GG-2001", self.track("GG-1; DROP TABLE orders").get_data(as_text=True))
        self.assertIn("could not find", self.track("GG-9999").get_data(as_text=True))
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 1)


if __name__ == "__main__":
    unittest.main()


class TestCreateAdminScript(Base):
    def test_creates_admin_with_hashed_password_and_rejects_weak_or_customer_email(self):
        import create_admin
        with self.app.app_context():
            self.assertFalse(create_admin.create_or_update_admin("Owner", "owner@example.com", "short1")[0])
            self.assertFalse(create_admin.create_or_update_admin("Owner", "owner@example.com", "onlyletterspassword")[0])
            ok, msg = create_admin.create_or_update_admin("Owner", "OWNER@example.com", "StrongPass123")
            self.assertTrue(ok, msg)
        row = self.sql("SELECT role, password_hash, email FROM users")[0]
        self.assertEqual((row["role"], row["email"]), ("admin", "owner@example.com")); self.assertNotIn("StrongPass123", row["password_hash"])
        self.register(self.client, "cust@example.com")
        with self.app.app_context():
            self.assertFalse(create_admin.create_or_update_admin("Owner", "cust@example.com", "StrongPass123")[0])   # cannot take over a customer
            self.assertTrue(create_admin.create_or_update_admin("Owner", "owner@example.com", "AnotherPass456")[0])  # reset works
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")[0]["n"], 1)