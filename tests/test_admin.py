"""Automatic tests for the admin side (temporary SQLite database, never your real MySQL data).
Run:  python -m unittest discover -s tests -t . -v"""
import io
import os
import re
import shutil
import tempfile
from decimal import Decimal

from PIL import Image
from werkzeug.security import generate_password_hash

from tests.test_customer import GOOD, Base

ADMIN_PW = "AdminPass123"


def png_bytes(size=(60, 40), color="green", fmt="PNG"):
    buf = io.BytesIO(); Image.new("RGB", size, color).save(buf, fmt); buf.seek(0); return buf


class AdminBase(Base):
    def setUp(self):
        super().setUp()
        self.uploads = tempfile.mkdtemp()
        self.app.config["UPLOAD_FOLDER"] = self.uploads
        self.sql("INSERT INTO users (full_name, email, password_hash, role) VALUES ('Owner', 'owner@example.com', ?, 'admin')", (generate_password_hash(ADMIN_PW),))
        self.admin = self.app.test_client()
        self.admin_login(self.admin)

    def tearDown(self):
        shutil.rmtree(self.uploads, ignore_errors=True)
        super().tearDown()

    def admin_login(self, client, email="owner@example.com", pw=ADMIN_PW):
        return self.post(client, "/admin/login", {"email": email, "password": pw}, page="/admin/login")

    def apost(self, path, data=None, page="/admin/", client=None, **kw):
        client = client or self.admin
        return self.post(client, path, data, page=page, **kw)

    def cat(self, name):
        return self.sql("SELECT id FROM categories WHERE name = ?", (name,))[0]["id"]

    def plant_form(self, **over):
        data = {"name": "Calathea", "category_id": self.cat("Indoor"), "price": "250.50", "stock": "7", "description": "Striped leaves", "is_available": "1"}
        data.update(over)
        return data

    def add_plant(self, image=None, **over):
        data = self.plant_form(**over)
        if image is not None:
            data["image"] = image
        return self.apost("/admin/plants/new", data, page="/admin/plants/new", content_type="multipart/form-data")

    def status(self, order_id, new):
        return self.apost(f"/admin/orders/{order_id}/status", {"status": new}, page=f"/admin/orders/{order_id}")

    def order_status(self, order_id=2001):
        return self.sql("SELECT status FROM orders WHERE id = ?", (order_id,))[0]["status"]


class TestAccessControl(AdminBase):
    ADMIN_PAGES = ["/admin/", "/admin/plants", "/admin/plants/new", "/admin/orders", "/admin/inventory", "/admin/customers", "/admin/orders/2001",
                   "/admin/plants/1/edit", "/admin/inventory/1/adjust", "/admin/customers/1"]

    def test_anonymous_visitors_are_sent_to_admin_login(self):
        anon = self.app.test_client()
        for path in self.ADMIN_PAGES:
            r = anon.get(path); self.assertEqual(r.status_code, 302, path); self.assertIn("/admin/login", r.headers["Location"], path)

    def test_customers_cannot_open_any_admin_page(self):
        c = self.customer()
        for path in self.ADMIN_PAGES:
            self.assertEqual(c.get(path).status_code, 403, path)

    def test_customers_cannot_use_admin_actions(self):
        c = self.customer(); self.order(c, [("Monstera", 1)])
        for path, data in [("/admin/orders/2001/status", {"status": "Confirmed"}), ("/admin/plants/1/delete", {}), ("/admin/plants/1/toggle", {"available": "0"}),
                           ("/admin/inventory/1/adjust", {"mode": "restock", "qty": "5"}), ("/admin/customers/1/toggle", {"active": "0"}),
                           ("/admin/plants/new", self.plant_form())]:
            self.assertEqual(self.post(c, path, data, page="/account").status_code, 403, path)
        self.assertEqual((self.order_status(), self.stock("Monstera")), ("Pending", 11))

    def test_anonymous_cannot_use_admin_actions(self):
        anon = self.app.test_client()
        for path in ["/admin/orders/2001/status", "/admin/plants/1/delete", "/admin/plants/new"]:
            r = self.post(anon, path, {}, page="/login"); self.assertIn(r.status_code, (302,)); self.assertIn("/admin/login", r.headers["Location"])

    def test_admin_post_without_csrf_token_is_refused(self):
        for path in ["/admin/plants/new", "/admin/orders/2001/status", "/admin/plants/1/delete", "/admin/logout"]:
            self.assertEqual(self.admin.post(path, data={"status": "Confirmed"}).status_code, 400, path)

    def test_admin_login_rules(self):
        self.register(self.client, "cust@example.com")
        self.client.post("/logout", data={"csrf_token": self.token(self.client, "/account")})
        c = self.app.test_client()
        self.assertEqual(self.admin_login(c, "cust@example.com", "Abcdef12").status_code, 401)        # a customer cannot enter here
        self.assertEqual(self.admin_login(c, pw="WrongPass123").status_code, 401)
        self.assertEqual(self.admin_login(c, "nobody@example.com").status_code, 401)
        self.assertEqual(self.admin_login(self.app.test_client()).status_code, 302)
        self.assertEqual(self.login(self.app.test_client(), "owner@example.com", ADMIN_PW).status_code, 401)   # admin cannot use the customer login

    def test_admin_login_is_rate_limited_and_next_is_safe(self):
        c = self.app.test_client()
        for _ in range(5): self.admin_login(c, pw="WrongPass123")
        self.assertEqual(self.admin_login(c).status_code, 429)
        import security; security.reset_attempts_for_tests()
        r = self.post(self.app.test_client(), "/admin/login?next=https://evil.com", {"email": "owner@example.com", "password": ADMIN_PW}, page="/admin/login")
        self.assertEqual(r.headers["Location"], "/admin/")

    def test_deactivated_admin_is_locked_out(self):
        self.sql("UPDATE users SET is_active = 0 WHERE role = 'admin'")
        self.assertEqual(self.admin.get("/admin/").status_code, 302)
        self.assertEqual(self.admin_login(self.app.test_client()).status_code, 401)

    def test_logout(self):
        self.apost("/admin/logout"); self.assertEqual(self.admin.get("/admin/").status_code, 302)

    def test_every_admin_page_renders_for_the_admin(self):
        c = self.customer(); self.order(c, [("Monstera", 1)])
        for path in ["/admin/", "/admin/?range=30", "/admin/plants", "/admin/plants/new", "/admin/plants/1/edit", "/admin/orders", "/admin/orders/2001",
                     "/admin/inventory", "/admin/inventory?plant=1#history", "/admin/inventory/1/adjust", "/admin/customers", "/admin/customers/2"]:
            self.assertEqual(self.admin.get(path).status_code, 200, path)
        for path in ["/admin/orders/9999", "/admin/plants/9999/edit", "/admin/customers/9999", "/admin/customers/1", "/admin/inventory/9999/adjust"]:
            self.assertEqual(self.admin.get(path).status_code, 404, path)       # customers/1 is the admin account itself


class TestPlantManagement(AdminBase):
    def test_new_plant_appears_in_customer_catalog_with_stock_history(self):
        r = self.add_plant(); self.assertEqual(r.status_code, 302)
        row = self.sql("SELECT * FROM plants WHERE name = 'Calathea'")[0]
        self.assertEqual((Decimal(str(row["price"])), row["stock_quantity"], row["is_available"]), (Decimal("250.50"), 7, 1))
        html = self.client.get("/plants").get_data(as_text=True)
        self.assertIn("Calathea", html); self.assertIn("₱250.50", html)
        m = self.sql("SELECT movement_type, quantity_change, balance_after, created_by FROM stock_movements")[0]
        self.assertEqual((m["movement_type"], m["quantity_change"], m["balance_after"]), ("initial_stock", 7, 7)); self.assertIsNotNone(m["created_by"])

    def test_validation_messages_and_nothing_saved(self):
        before = self.sql("SELECT COUNT(*) AS n FROM plants")[0]["n"]
        for over, msg in [({"name": ""}, "plant name"), ({"name": "snake plant"}, "already exists"), ({"category_id": ""}, "choose a category"), ({"category_id": "999"}, "choose a category"),
                          ({"price": "-5"}, "greater than"), ({"price": "0"}, "greater than"), ({"price": "abc"}, "greater than"), ({"price": "19.999"}, "2 decimal"), ({"price": "100001"}, "too high"),
                          ({"price": "NaN"}, "greater than"), ({"stock": "-1"}, "whole number"), ({"stock": "1.5"}, "whole number"), ({"stock": "10000"}, "too high"),
                          ({"description": "x" * 301}, "300 characters")]:
            r = self.add_plant(**over); self.assertEqual(r.status_code, 400, over); self.assertIn(msg, r.get_data(as_text=True), over)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM plants")[0]["n"], before)

    def test_edit_changes_price_but_old_orders_keep_their_price(self):
        c = self.customer(); self.order(c, [("Monstera", 1)])
        pid = self.plant_id("Monstera")
        r = self.apost(f"/admin/plants/{pid}/edit", self.plant_form(name="Monstera", price="999.00", stock="12"), page=f"/admin/plants/{pid}/edit")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Decimal(str(self.sql("SELECT price FROM plants WHERE id = ?", (pid,))[0]["price"])), Decimal("999.00"))
        html = c.get("/orders/2001").get_data(as_text=True); self.assertIn("₱450.00", html); self.assertNotIn("₱999.00", html)

    def test_edit_stock_is_saved_as_a_correction_and_never_negative(self):
        pid = self.plant_id("Monstera")
        self.apost(f"/admin/plants/{pid}/edit", self.plant_form(name="Monstera", stock="20"), page=f"/admin/plants/{pid}/edit")
        m = self.sql("SELECT movement_type, quantity_change, balance_after FROM stock_movements WHERE plant_id = ?", (pid,))[0]
        self.assertEqual((m["movement_type"], m["quantity_change"], m["balance_after"]), ("correction", 8, 20))
        r = self.apost(f"/admin/plants/{pid}/edit", self.plant_form(name="Monstera", stock="-3"), page=f"/admin/plants/{pid}/edit")
        self.assertEqual(r.status_code, 400); self.assertEqual(self.stock("Monstera"), 20)

    def test_rename_to_existing_name_is_refused_but_keeping_own_name_is_fine(self):
        pid = self.plant_id("Monstera")
        self.assertEqual(self.apost(f"/admin/plants/{pid}/edit", self.plant_form(name="Snake Plant", stock="12"), page="/admin/plants").status_code, 400)
        self.assertEqual(self.apost(f"/admin/plants/{pid}/edit", self.plant_form(name="Monstera", stock="12"), page="/admin/plants").status_code, 302)

    def test_hide_plant_removes_it_from_customer_site_and_show_brings_it_back(self):
        pid = self.plant_id("Monstera")
        self.apost(f"/admin/plants/{pid}/toggle", {"available": "0"}, page="/admin/plants")
        self.assertNotIn("Monstera", self.client.get("/plants").get_data(as_text=True)); self.assertEqual(self.client.get(f"/plants/{pid}").status_code, 404)
        self.apost(f"/admin/plants/{pid}/toggle", {"available": "1"}, page="/admin/plants")
        self.assertIn("Monstera", self.client.get("/plants").get_data(as_text=True))

    def test_hidden_plant_in_a_cart_is_dropped_and_cannot_be_ordered(self):
        c = self.customer(); self.add_to_cart(c, "Monstera", 1)
        self.apost(f"/admin/plants/{self.plant_id('Monstera')}/toggle", {"available": "0"}, page="/admin/plants")
        r = self.post(c, "/checkout", {**GOOD, "fulfillment": "pickup"}, page="/plants")
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 0)

    def test_delete_is_blocked_for_ordered_plants_and_allowed_for_unused_ones(self):
        c = self.customer(); self.order(c, [("Monstera", 1)])
        self.add_plant()
        r = self.apost(f"/admin/plants/{self.plant_id('Monstera')}/delete", page="/admin/plants", follow_redirects=True)
        self.assertIn("cannot be deleted", r.get_data(as_text=True)); self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM plants WHERE name = 'Monstera'")[0]["n"], 1)
        pid = self.plant_id("Calathea")
        self.apost(f"/admin/plants/{pid}/delete", page="/admin/plants")
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM plants WHERE name = 'Calathea'")[0]["n"], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM stock_movements WHERE plant_id = ?", (pid,))[0]["n"], 0)

    def test_search_filter_and_sort(self):
        html = self.admin.get("/admin/plants?q=fern").get_data(as_text=True); self.assertIn("Boston Fern", html); self.assertNotIn("Monstera", html)
        self.assertNotIn("Boston Fern", self.admin.get(f"/admin/plants?category={self.cat('Succulent')}").get_data(as_text=True))
        self.assertIn("Hidden Plant", self.admin.get("/admin/plants?availability=unavailable").get_data(as_text=True))
        self.assertNotIn("Monstera", self.admin.get("/admin/plants?availability=out").get_data(as_text=True))
        for q in ["' OR 1=1 --", "%", "_"]:
            self.assertEqual(self.admin.get("/admin/plants", query_string={"q": q}).status_code, 200)
        self.assertEqual(self.admin.get("/admin/plants?sort=;DROP TABLE plants").status_code, 200)
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM plants")[0]["n"], 6)

    def test_html_in_plant_name_is_escaped_everywhere(self):
        self.add_plant(name="<script>alert(1)</script>")
        for client, path in [(self.admin, "/admin/plants"), (self.client, "/plants"), (self.admin, "/admin/inventory")]:
            html = client.get(path).get_data(as_text=True)
            self.assertNotIn("<script>alert(1)</script>", html, path); self.assertIn("&lt;script&gt;", html, path)


class TestPhotoUpload(AdminBase):
    def files(self): return os.listdir(self.uploads)

    def image_size(self, name):
        with Image.open(os.path.join(self.uploads, name)) as img: return img.size

    def test_valid_photo_is_saved_under_a_random_name_and_shown(self):
        r = self.add_plant(image=(png_bytes(), "../../evil name.png")); self.assertEqual(r.status_code, 302)
        path = self.sql("SELECT image_path FROM plants WHERE name = 'Calathea'")[0]["image_path"]
        self.assertRegex(path, r"^[0-9a-f]{32}\.jpg$"); self.assertEqual(self.files(), [path])
        with Image.open(os.path.join(self.uploads, path)) as img: self.assertEqual(img.format, "JPEG")
        self.assertIn(path, self.client.get("/plants").get_data(as_text=True))

    def test_a_large_phone_style_photo_is_accepted_and_shrunk(self):
        import random
        random.seed(1); noisy = Image.frombytes("RGB", (2400, 1800), random.randbytes(2400 * 1800 * 3))      # noisy = big file, like a real camera photo
        buf = io.BytesIO(); noisy.save(buf, "JPEG", quality=95); self.assertGreater(buf.tell(), 3 * 1024 * 1024); buf.seek(0)
        self.assertEqual(self.add_plant(name="Phone", image=(buf, "IMG_2031.JPG")).status_code, 302)
        p = self.sql("SELECT image_path FROM plants WHERE name = 'Phone'")[0]["image_path"]
        self.assertLessEqual(max(self.image_size(p)), 800); self.assertLess(os.path.getsize(os.path.join(self.uploads, p)), 600 * 1024)

    def test_big_photos_are_shrunk_and_transparent_png_is_accepted(self):
        self.add_plant(name="Big", image=(png_bytes((2000, 1500)), "big.png"))
        p = self.sql("SELECT image_path FROM plants WHERE name = 'Big'")[0]["image_path"]; self.assertLessEqual(max(self.image_size(p)), 800)
        buf = io.BytesIO(); Image.new("RGBA", (30, 30), (0, 0, 0, 0)).save(buf, "PNG"); buf.seek(0)
        self.assertEqual(self.add_plant(name="Clear", image=(buf, "t.png")).status_code, 302)

    def test_fake_and_dangerous_files_are_rejected(self):
        cases = [(io.BytesIO(b"<?php system($_GET['x']); ?>"), "shell.php", "Only JPG"), (io.BytesIO(b"<?php evil ?>"), "shell.jpg", "not a valid photo"),
                 (io.BytesIO(b"<svg onload=alert(1)></svg>"), "x.svg", "Only JPG"), (io.BytesIO(b"<html><script>alert(1)</script></html>"), "x.png", "not a valid photo"),
                 (io.BytesIO(b"GIF89a" + b"\x00" * 50), "x.gif", "Only JPG"), (io.BytesIO(b""), "empty.png", "not a valid photo"),
                 (png_bytes(fmt="GIF"), "gif_in_png.png", "not a valid photo"), (io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"junk"), "broken.png", "not a valid photo")]
        for data, name, msg in cases:
            r = self.add_plant(name="X " + name, image=(data, name)); self.assertEqual(r.status_code, 400, name); self.assertIn(msg, r.get_data(as_text=True), name)
        self.assertEqual(self.files(), []); self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM plants WHERE name LIKE 'X %'")[0]["n"], 0)

    def test_too_big_photos_are_rejected(self):
        r = self.add_plant(image=(io.BytesIO(b"\x89PNG" + b"0" * (10 * 1024 * 1024 + 10)), "big.png")); self.assertEqual(r.status_code, 400); self.assertIn("too big", r.get_data(as_text=True))
        r = self.add_plant(image=(io.BytesIO(b"0" * (13 * 1024 * 1024)), "huge.png")); self.assertEqual(r.status_code, 413)
        self.assertEqual(self.files(), [])

    def test_failed_form_does_not_leave_an_uploaded_file_behind(self):
        r = self.add_plant(name="", image=(png_bytes(), "ok.png")); self.assertEqual(r.status_code, 400); self.assertEqual(self.files(), [])

    def test_replacing_a_photo_deletes_the_old_file_and_deleting_the_plant_deletes_the_photo(self):
        self.add_plant(image=(png_bytes(), "a.png")); pid = self.plant_id("Calathea"); first = self.files()[0]
        self.apost(f"/admin/plants/{pid}/edit", self.plant_form(), page="/admin/plants/new", content_type="multipart/form-data", **{})
        self.assertEqual(self.files(), [first])                                                      # no new file chosen: photo kept
        data = self.plant_form(); data["image"] = (png_bytes(color="red"), "b.png")
        self.apost(f"/admin/plants/{pid}/edit", data, page="/admin/plants/new", content_type="multipart/form-data")
        self.assertEqual(len(self.files()), 1); self.assertNotEqual(self.files()[0], first)
        self.apost(f"/admin/plants/{pid}/delete", page="/admin/plants"); self.assertEqual(self.files(), [])

    def test_a_database_error_after_the_upload_removes_the_new_file(self):
        self.fail_on.append("INSERT INTO plants")
        with self.app.test_request_context():
            import services_admin as svc
            from werkzeug.datastructures import FileStorage, MultiDict
            with self.assertRaises(RuntimeError):
                svc.save_plant(MultiDict(self.plant_form()), FileStorage(png_bytes(), "p.png"), 1)
        self.fail_on.clear(); self.assertEqual(self.files(), [])


class TestOrderManagement(AdminBase):
    def setUp(self):
        super().setUp()
        self.c = self.customer(); self.order(self.c, [("Monstera", 2), ("Echeveria", 3)], fulfillment="delivery")    # order GG-2001

    def test_list_search_filters(self):
        c2 = self.customer("ben@example.com", "Ben Reyes"); self.order(c2, [("Snake Plant", 1)], name="Ben Reyes")      # GG-2002
        def ids(q=""): return set(re.findall(r"GG-(\d+)</td>", self.admin.get("/admin/orders" + q).get_data(as_text=True)))
        self.assertEqual(ids(), {"2001", "2002"})
        self.assertEqual(ids("?q=2002"), {"2002"}); self.assertEqual(ids("?q=gg-2001"), {"2001"})
        self.assertEqual(ids("?q=maria"), {"2001"}); self.assertEqual(ids("?q=ben@example"), {"2002"}); self.assertEqual(ids("?q=nobody"), set())
        self.assertEqual(ids("?status=Pending"), {"2001", "2002"}); self.assertEqual(ids("?status=Completed"), set())
        self.sql("UPDATE orders SET created_at = '2026-01-10 10:00:00' WHERE id = 2001")
        self.assertEqual(ids("?from=2026-01-10&to=2026-01-10"), {"2001"}); self.assertEqual(ids("?from=2026-01-11"), {"2002"}); self.assertEqual(ids("?to=2026-01-09"), set())
        html = self.admin.get("/admin/orders?from=2026-02-01&to=2026-01-01").get_data(as_text=True); self.assertIn("must be on or before", html)
        self.assertIn("valid dates", self.admin.get("/admin/orders?from=not-a-date").get_data(as_text=True))
        for q in ["' OR 1=1 --", "%", "_"]: self.assertEqual(self.admin.get("/admin/orders", query_string={"q": q}).status_code, 200)

    def test_pagination(self):
        for _ in range(17): self.sql("INSERT INTO orders (user_id, fulfillment, total_amount, contact_name, contact_phone, address, city, province) VALUES (2, 'pickup', 100, 'A', '09171234567', 'Street 1', 'Bay', 'Laguna')")
        p1 = self.admin.get("/admin/orders").get_data(as_text=True); p2 = self.admin.get("/admin/orders?page=2").get_data(as_text=True)
        self.assertEqual(len(re.findall(r"GG-\d+</td>", p1)), 15); self.assertEqual(len(re.findall(r"GG-\d+</td>", p2)), 3); self.assertIn("Page 1 of 2", p1)
        self.assertEqual(self.admin.get("/admin/orders?page=999").status_code, 200); self.assertEqual(self.admin.get("/admin/orders?page=abc").status_code, 200)

    def test_order_detail_shows_everything(self):
        html = self.admin.get("/admin/orders/2001").get_data(as_text=True)
        for text in ["Monstera", "Echeveria", "₱1,340.00", "Delivery fee", "Maria Santos", "maria@example.com", "09171234567", "12 Rizal St.", "taken off"]: self.assertIn(text, html)

    def test_status_flow_is_visible_to_the_customer_on_the_tracking_page(self):
        for new, expect in [("Confirmed", "Order confirmed"), ("Processing", "Order processing"), ("Ready for Pickup", "Ready for delivery"), ("Completed", "Order completed")]:
            self.assertEqual(self.status(2001, new).status_code, 302); self.assertEqual(self.order_status(), new)
            html = self.c.get("/track?id=GG-2001").get_data(as_text=True)
            self.assertRegex(html, r'<li class="current" aria-current="step">\s*<span class="dot">\d</span><span class="tl-label">' + expect)
        self.assertIn("Completed", self.c.get("/my-orders").get_data(as_text=True))

    def test_invalid_status_changes_are_refused(self):
        for bad in ["Completed", "Processing", "Ready for Pickup", "Pending", "Hacked", "", "cancelled"]:
            self.status(2001, bad)
            self.assertEqual(self.order_status(), "Pending", bad)
        self.status(2001, "Confirmed"); self.assertEqual(self.status(2001, "Pending").status_code, 302); self.assertEqual(self.order_status(), "Confirmed")
        for s in ["Processing", "Ready for Pickup", "Completed"]: self.status(2001, s)
        for s in ["Pending", "Confirmed", "Processing", "Cancelled", "Completed"]: self.status(2001, s); self.assertEqual(self.order_status(), "Completed", s)

    def test_refused_change_shows_a_message(self):
        r = self.status(2001, "Completed"); html = self.admin.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("cannot be changed to Completed", html)

    def test_unknown_order_is_refused(self):
        self.assertEqual(self.status(9999, "Confirmed").status_code, 302); self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"], 1)

    def test_cancel_returns_stock_once_and_records_history(self):
        self.assertEqual((self.stock("Monstera"), self.stock("Echeveria")), (10, 37))
        self.status(2001, "Cancelled")
        self.assertEqual((self.stock("Monstera"), self.stock("Echeveria")), (12, 40)); self.assertEqual(self.order_status(), "Cancelled")
        self.assertEqual(self.sql("SELECT stock_deducted FROM orders")[0]["stock_deducted"], 0)
        back = self.sql("SELECT quantity_change, balance_after, order_id, created_by FROM stock_movements WHERE movement_type = 'order_cancelled' ORDER BY plant_id")
        self.assertEqual([(m["quantity_change"], m["balance_after"], m["order_id"]) for m in back], [(2, 12, 2001), (3, 40, 2001)]); self.assertIsNotNone(back[0]["created_by"])
        html = self.c.get("/track?id=GG-2001").get_data(as_text=True); self.assertIn("This order was cancelled", html); self.assertNotIn('class="timeline"', html)

    def test_replaying_the_cancel_request_never_returns_stock_twice(self):
        token = self.token(self.admin, "/admin/orders/2001")
        for _ in range(3): self.admin.post("/admin/orders/2001/status", data={"status": "Cancelled", "csrf_token": token})
        self.assertEqual((self.stock("Monstera"), self.stock("Echeveria")), (12, 40))
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM stock_movements WHERE movement_type = 'order_cancelled'")[0]["n"], 2)

    def test_cancel_works_from_every_open_status_but_not_after_completion(self):
        for steps in [[], ["Confirmed"], ["Confirmed", "Processing"], ["Confirmed", "Processing", "Ready for Pickup"]]:
            self.sql("UPDATE orders SET status = 'Pending', stock_deducted = 1 WHERE id = 2001"); self.sql("UPDATE plants SET stock_quantity = 10 WHERE name = 'Monstera'")
            for s in steps: self.status(2001, s)
            self.status(2001, "Cancelled"); self.assertEqual((self.order_status(), self.stock("Monstera")), ("Cancelled", 12), steps)
        self.sql("UPDATE orders SET status = 'Completed', stock_deducted = 1 WHERE id = 2001"); self.sql("UPDATE plants SET stock_quantity = 10 WHERE name = 'Monstera'")
        self.status(2001, "Cancelled"); self.assertEqual((self.order_status(), self.stock("Monstera")), ("Completed", 10))

    def test_failure_while_cancelling_changes_nothing(self):
        self.fail_on.append("INSERT INTO stock_movements")
        with self.app.test_request_context():
            import services_admin as svc
            with self.assertRaises(RuntimeError): svc.set_order_status(2001, "Cancelled", 1)
        self.fail_on.clear()
        self.assertEqual((self.order_status(), self.stock("Monstera"), self.sql("SELECT stock_deducted FROM orders")[0]["stock_deducted"]), ("Pending", 10, 1))

    def test_confirming_does_not_touch_stock(self):
        for s in ["Confirmed", "Processing", "Ready for Pickup", "Completed"]: self.status(2001, s)
        self.assertEqual((self.stock("Monstera"), self.stock("Echeveria")), (10, 37))
        self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM stock_movements WHERE movement_type = 'order_placed'")[0]["n"], 2)


class TestInventory(AdminBase):
    def adjust(self, name, mode, qty, note=""):
        pid = self.plant_id(name); return self.apost(f"/admin/inventory/{pid}/adjust", {"mode": mode, "qty": qty, "note": note}, page=f"/admin/inventory/{pid}/adjust")

    def last_move(self, name): return self.sql("SELECT * FROM stock_movements WHERE plant_id = ? ORDER BY id DESC", (self.plant_id(name),))[0]

    def test_restock_remove_and_set_are_saved_with_history(self):
        self.assertEqual(self.adjust("Boston Fern", "restock", "10").status_code, 302)
        m = self.last_move("Boston Fern"); self.assertEqual((m["movement_type"], m["quantity_change"], m["balance_after"]), ("restock", 10, 13)); self.assertIsNotNone(m["created_by"])
        self.adjust("Boston Fern", "remove", "4", "broken pots"); m = self.last_move("Boston Fern")
        self.assertEqual((m["movement_type"], m["quantity_change"], m["balance_after"], m["note"]), ("damaged_lost", -4, 9, "broken pots"))
        self.adjust("Boston Fern", "set", "0", "counted shelf"); self.assertEqual(self.stock("Boston Fern"), 0)
        m = self.last_move("Boston Fern"); self.assertEqual((m["movement_type"], m["quantity_change"]), ("correction", -9))

    def test_bad_adjustments_are_refused_and_change_nothing(self):
        for mode, qty, note, msg in [("restock", "", "", "whole number"), ("restock", "0", "", "1 or more"), ("restock", "-5", "", "1 or more"), ("restock", "2.5", "", "whole number"),
                                     ("restock", "abc", "", "whole number"), ("restock", "10000", "", "too high"), ("restock", "9999", "", "above 9,999"),
                                     ("remove", "99", "lost", "Not enough stock"), ("remove", "1", "", "reason"), ("remove", "1", "ab", "reason"), ("set", "5", "", "reason"),
                                     ("set", "3", "same count", "same as the current"), ("set", "-1", "x" * 5, "0 or more"), ("fly", "1", "", "Choose")]:
            r = self.adjust("Boston Fern", mode, qty, note); self.assertEqual(r.status_code, 400, (mode, qty)); self.assertIn(msg, r.get_data(as_text=True), (mode, qty, note))
        self.assertEqual(self.stock("Boston Fern"), 3); self.assertEqual(self.sql("SELECT COUNT(*) AS n FROM stock_movements")[0]["n"], 0)

    def test_stock_can_never_go_below_zero_in_the_database(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError): self.sql("UPDATE plants SET stock_quantity = -1 WHERE name = 'Monstera'")

    def test_summary_search_and_filters(self):
        html = self.admin.get("/admin/inventory").get_data(as_text=True); self.assertIn("Units in stock", html)
        table = lambda q: self.admin.get("/admin/inventory" + q).get_data(as_text=True).split("<tbody>")[1].split("</tbody>")[0]      # only the plants table
        self.assertIn("Boston Fern", table("?level=low")); self.assertNotIn("Monstera", table("?level=low"))
        self.assertIn("Yellow Ixora", table("?level=out")); self.assertNotIn("Boston Fern", table("?level=out"))
        self.assertIn("Monstera", table("?level=ok")); self.assertNotIn("Yellow Ixora", table("?level=ok")); self.assertNotIn("Boston Fern", table("?level=ok"))
        self.assertIn("Snake Plant", table("?q=snake")); self.assertNotIn("Monstera", table("?q=snake"))
        self.assertEqual(self.admin.get("/admin/inventory?q=%25&sort=;DROP").status_code, 200)

    def test_history_filters_and_paging(self):
        c = self.customer(); self.order(c, [("Monstera", 1)]); self.adjust("Boston Fern", "restock", "5")
        h = self.admin.get(f"/admin/inventory?plant={self.plant_id('Boston Fern')}").get_data(as_text=True)
        rows = lambda html: html.split("<tbody>")[-1]                                                  # only the history table rows
        self.assertIn("Restock", rows(h)); self.assertNotIn("Order placed", rows(h))
        self.assertIn("Order placed", rows(self.admin.get("/admin/inventory?type=order_placed").get_data(as_text=True)))
        self.assertNotIn("Restock", rows(self.admin.get("/admin/inventory?type=order_placed").get_data(as_text=True)))
        self.assertEqual(self.admin.get("/admin/inventory?type=nonsense&plant=abc&page=zzz").status_code, 200)

    def test_orders_and_cancellations_show_in_history_with_balance(self):
        c = self.customer(); self.order(c, [("Monstera", 2)]); self.status(2001, "Cancelled")
        rows = self.sql("SELECT movement_type, quantity_change, balance_after FROM stock_movements WHERE plant_id = ? ORDER BY id", (self.plant_id("Monstera"),))
        self.assertEqual([(r["movement_type"], r["quantity_change"], r["balance_after"]) for r in rows], [("order_placed", -2, 10), ("order_cancelled", 2, 12)])


class TestCustomers(AdminBase):
    def test_list_search_filter_sort_and_totals(self):
        a = self.customer("ana@example.com", "Ana Cruz"); b = self.customer("ben@example.com", "Ben Reyes")
        self.order(a, [("Monstera", 1)]); self.order(b, [("Snake Plant", 2)]); self.status(2002, "Cancelled")
        html = self.admin.get("/admin/customers").get_data(as_text=True)
        rows = html.split("<tbody>")[1]
        self.assertIn("Ana Cruz", rows); self.assertIn("Ben Reyes", rows); self.assertNotIn("Owner", rows)           # the admin is not listed as a customer
        self.assertIn("Ana Cruz", self.admin.get("/admin/customers?q=ana@").get_data(as_text=True)); self.assertNotIn("Ben Reyes", self.admin.get("/admin/customers?q=ana@").get_data(as_text=True))
        self.assertNotIn("Ana Cruz", self.admin.get("/admin/customers?status=deactivated").get_data(as_text=True))
        for q in ["' OR 1=1 --", "%"]: self.assertEqual(self.admin.get("/admin/customers", query_string={"q": q}).status_code, 200)
        self.assertEqual(self.admin.get("/admin/customers?sort=spent-desc").status_code, 200)

    def test_detail_shows_order_history(self):
        a = self.customer("ana@example.com", "Ana Cruz"); self.order(a, [("Monstera", 1)])
        html = self.admin.get("/admin/customers/2").get_data(as_text=True)
        for text in ["Ana Cruz", "ana@example.com", "GG-2001", "₱450.00", "1 order"]: self.assertIn(text, html)

    def test_deactivate_is_blocked_while_orders_are_open_then_allowed(self):
        a = self.customer("ana@example.com", "Ana Cruz"); self.order(a, [("Monstera", 1)])
        r = self.apost("/admin/customers/2/toggle", {"active": "0"}, page="/admin/customers/2", follow_redirects=True)
        self.assertIn("unfinished orders (GG-2001)", r.get_data(as_text=True)); self.assertEqual(self.sql("SELECT is_active FROM users WHERE id = 2")[0]["is_active"], 1)
        self.status(2001, "Cancelled"); self.apost("/admin/customers/2/toggle", {"active": "0"}, page="/admin/customers/2")
        self.assertEqual(self.sql("SELECT is_active FROM users WHERE id = 2")[0]["is_active"], 0)
        self.assertEqual(a.get("/account").status_code, 302)                                                          # logged out immediately
        self.assertEqual(self.login(self.app.test_client(), "ana@example.com").status_code, 401)
        self.apost("/admin/customers/2/toggle", {"active": "1"}, page="/admin/customers/2"); self.assertEqual(self.login(self.app.test_client(), "ana@example.com").status_code, 302)

    def test_admin_account_cannot_be_deactivated_from_the_customers_page(self):
        self.apost("/admin/customers/1/toggle", {"active": "0"}, page="/admin/customers"); self.assertEqual(self.sql("SELECT is_active FROM users WHERE id = 1")[0]["is_active"], 1)


class TestDashboard(AdminBase):
    def test_numbers_come_from_the_database(self):
        a = self.customer("ana@example.com", "Ana Cruz"); b = self.customer("ben@example.com", "Ben Reyes")
        self.order(a, [("Monstera", 2)]); self.order(b, [("Snake Plant", 1), ("Echeveria", 4)], fulfillment="delivery"); self.order(a, [("Boston Fern", 1)])   # 900, 280+480+80=840, 220
        self.status(2003, "Cancelled")
        import services_admin as svc
        with self.app.test_request_context():
            d = svc.dashboard(7)
        s = d["stats"]
        self.assertEqual((s["orders"], s["cancelled"], s["pending"], s["customers"], s["plants"], s["unavailable"]), (3, 1, 2, 2, 6, 1))
        self.assertEqual(s["revenue"], Decimal("1740.00"))                                                             # cancelled order not counted
        self.assertEqual((s["low_stock"], s["out_of_stock"]), (2, 1))                                                  # Boston Fern (3 back to 3) + Yellow Ixora (0); hidden plant not counted
        self.assertEqual([(p["name"], int(p["sold"])) for p in d["popular"]], [("Echeveria", 4), ("Monstera", 2), ("Snake Plant", 1)])
        self.assertEqual(len(d["chart"]["labels"]), 7); self.assertAlmostEqual(d["chart"]["values"][-1], 1740.0); self.assertAlmostEqual(d["chart_total"], 1740.0)
        self.assertEqual([r["id"] for r in d["recent"]], [2003, 2002, 2001])

    def test_page_shows_the_numbers_and_empty_state_is_safe(self):
        html = self.admin.get("/admin/").get_data(as_text=True)
        for text in ["Total orders", "₱0.00", "No sales yet.", "No orders yet.", "Yellow Ixora", "Out of stock"]: self.assertIn(text, html)
        self.assertEqual(self.admin.get("/admin/?range=abc").status_code, 200)
        self.assertIn('"labels"', self.admin.get("/admin/?range=30").get_data(as_text=True))


class TestEndToEnd(AdminBase):
    def test_the_whole_story(self):
        # 1. admin adds a plant, it appears in the customer catalog
        self.add_plant(name="Calathea", stock="5", image=(png_bytes(), "c.png"))
        self.assertIn("Calathea", self.client.get("/plants?q=calathea").get_data(as_text=True))
        # 2-5. customer finds it, adds it to the cart, orders; order saved with items/total; stock updated
        c = self.customer(); self.assertIn("Calathea", c.get("/plants?q=cala").get_data(as_text=True))
        r = self.order(c, [("Calathea", 2)]); self.assertEqual(r.headers["Location"], "/orders/2001/confirmation")
        self.assertEqual(self.stock("Calathea"), 3); self.assertEqual(Decimal(str(self.sql("SELECT total_amount FROM orders")[0]["total_amount"])), Decimal("501.00"))
        # 6. customer sees the order in history
        self.assertIn("GG-2001", c.get("/my-orders").get_data(as_text=True))
        # 7-8. admin opens it and changes the status, customer sees the change
        self.assertIn("Calathea", self.admin.get("/admin/orders/2001").get_data(as_text=True))
        self.status(2001, "Confirmed"); self.assertIn("Confirmed", c.get("/track?id=GG-2001").get_data(as_text=True))
        # 9. insufficient stock is rejected (someone else bought plants while this customer was on the checkout page)
        self.add_to_cart(c, "Calathea", 3); token = self.token(c, "/checkout")
        self.sql("UPDATE plants SET stock_quantity = 1 WHERE name = 'Calathea'")
        r = c.post("/checkout", data={**GOOD, "fulfillment": "pickup", "csrf_token": token})
        self.assertEqual((r.status_code, self.stock("Calathea"), self.sql("SELECT COUNT(*) AS n FROM orders")[0]["n"]), (400, 1, 1))
        # 10. other customers cannot see the order
        d = self.customer("other@example.com", "Other"); self.assertEqual(d.get("/orders/2001").status_code, 404); self.assertEqual(d.get("/admin/").status_code, 403)
        # 11. cancelling returns stock once
        self.status(2001, "Cancelled"); self.status(2001, "Cancelled"); self.assertEqual(self.stock("Calathea"), 3)       # 1 left + the 2 that were returned, once


if __name__ == "__main__":
    import unittest; unittest.main()