"""Checks that the GardenGo logo and favicon are on every page and that the image files are good."""
import re
from pathlib import Path

from PIL import Image

from tests.test_admin import AdminBase

IMG = Path(__file__).resolve().parent.parent / "static" / "img"


class TestBranding(AdminBase):
    def test_logo_files_are_real_images_with_a_transparent_background_and_a_small_size(self):
        for name, size, max_kb in [("logo.png", (320, 320), 80), ("logo-96.png", (96, 96), 20), ("favicon-32.png", (32, 32), 10), ("apple-touch-icon.png", (180, 180), 80)]:
            path = IMG / name
            with Image.open(path) as img: self.assertEqual((img.format, img.size), ("PNG", size), name)
            self.assertLessEqual(path.stat().st_size / 1024, max_kb, name + " is too heavy for a web page")
        for name in ["logo.png", "logo-96.png", "favicon-32.png"]:
            with Image.open(IMG / name) as img: self.assertEqual(img.convert("RGBA").getpixel((0, 0))[3], 0, name + " should be transparent in the corners")
        with Image.open(IMG / "favicon.ico") as ico: self.assertEqual(ico.format, "ICO"); self.assertIn((32, 32), ico.info["sizes"])

    def test_every_customer_page_has_the_favicon_and_the_logo(self):
        c = self.customer()
        for path in ["/", "/plants", "/plants/1", "/cart", "/login", "/register", "/does-not-exist"]:
            html = (c if path in ("/cart",) else self.client).get(path).get_data(as_text=True)
            self.assertIn("img/favicon.ico", html, path); self.assertIn("img/favicon-32.png", html, path); self.assertIn("apple-touch-icon", html, path)
            self.assertIn('name="theme-color"', html, path); self.assertIn('class="logo-img"', html, path)
        for path in ["/my-orders", "/account", "/track", "/checkout"]:
            self.assertIn('class="logo-img"', c.get(path, follow_redirects=True).get_data(as_text=True), path)

    def test_login_register_and_home_show_the_big_logo_with_alt_text(self):
        for path in ["/login", "/register"]:
            html = self.client.get(path).get_data(as_text=True)
            self.assertRegex(html, r'class="auth-logo"[^>]*alt="Gripalda.s Garden logo"')   # "." matches the apostrophe
        self.assertIn("logo-img big", self.client.get("/").get_data(as_text=True))

    def test_admin_pages_have_the_favicon_and_the_logo(self):
        for client, path in [(self.app.test_client(), "/admin/login"), (self.admin, "/admin/"), (self.admin, "/admin/plants")]:
            html = client.get(path).get_data(as_text=True)
            self.assertIn("img/favicon.ico", html, path); self.assertRegex(html, r"img/logo(-96)?\.png", path)
        self.assertIn('class="login-logo"', self.app.test_client().get("/admin/login").get_data(as_text=True))
        self.assertIn('class="side-logo"', self.admin.get("/admin/").get_data(as_text=True))

    def test_all_logo_urls_used_in_pages_are_served(self):
        urls = set()
        for client, path in [(self.client, "/"), (self.client, "/login"), (self.app.test_client(), "/admin/login"), (self.admin, "/admin/")]:
            urls |= set(re.findall(r'(?:src|href)="(/static/img/[^"]+)"', client.get(path).get_data(as_text=True)))
        self.assertGreaterEqual(len(urls), 5)
        for url in urls:
            r = self.client.get(url)
            try:
                self.assertEqual(r.status_code, 200, url); self.assertTrue(r.content_type.startswith(("image/",)), url)
            finally:
                r.close()                  # a static file response keeps the file open until closed