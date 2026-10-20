"""Real-browser smoke flow; install playwright and Chromium to run this suite."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sync_playwright, "Install Playwright and Chromium to run browser acceptance")
class BrowserAcceptance(unittest.TestCase):
    def test_setup_sign_in_dashboard_and_logout(self):
        with tempfile.TemporaryDirectory() as data_dir:
            port = 18871
            env = os.environ.copy()
            env.update({"CHM_DATA_DIR": data_dir, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(port), "CHM_ENABLE_FIXTURE": "true"})
            process = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(50):
                    try:
                        import urllib.request
                        urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
                        break
                    except Exception:
                        time.sleep(.1)
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(headless=True)
                    page = browser.new_page()
                    page.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
                    page.get_by_role("heading", name="Set up your monitor").wait_for()
                    page.get_by_label("Username").fill("siteadmin")
                    page.get_by_label("Password").fill("A-secure-password-2026")
                    page.get_by_role("button", name="Create administrator").click()
                    page.get_by_role("heading", name="No servers configured").wait_for()
                    self.assertTrue(page.get_by_text("Servers").is_visible())
                    page.get_by_label("Display name").fill("Main recorder")
                    page.get_by_label("Host").fill("exacq.example.test")
                    page.get_by_role("button", name="Add recorder").click()
                    page.get_by_role("heading", name="Main recorder").wait_for()
                    self.assertTrue(page.get_by_text("Discovery untested").is_visible())
                    self.assertTrue(page.get_by_text("ExacqVision Web Service support is enabled.").is_visible())
                    page.get_by_label("Display name").fill("Main recorder")
                    page.get_by_label("Host").fill("exacq.example.test")
                    page.get_by_role("button", name="Add recorder").click()
                    page.get_by_role("heading", name="Main recorder").wait_for()
                    self.assertTrue(page.get_by_text("Discovery untested").is_visible())
                    self.assertTrue(page.get_by_text("ExacqVision Web Service support is enabled.").is_visible())
                    page.get_by_role("button", name="Sign out").click()
                    page.get_by_role("heading", name="Sign in").wait_for()
                    page.get_by_label("Username").fill("siteadmin")
                    page.get_by_label("Password").fill("A-secure-password-2026")
                    page.get_by_role("button", name="Sign in").click()
                    page.get_by_role("heading", name="Camera health").wait_for()
                    page.get_by_label("Theme preference").select_option("light")
                    self.assertEqual("light", page.evaluate("document.documentElement.dataset.theme"))
                    self.assertEqual("light", page.evaluate("localStorage.getItem('chm-theme-preference')"))
                    page.get_by_role("button", name="Branding").click()
                    page.get_by_label("Application name").fill("Preview Name")
                    self.assertIn("Preview Name", page.locator(".wordmark").inner_text())
                    page.get_by_role("button", name="Discard changes").click()
                    self.assertNotIn("Preview Name", page.locator(".wordmark").inner_text())
                    page.get_by_role("button", name="Branding").click()
                    page.get_by_role("button", name="Reset branding").click()
                    page.get_by_role("button", name="Save branding").click()
                    page.get_by_role("heading", name="Camera health").wait_for()
                    self.assertEqual("Camera Health Monitor", page.locator(".wordmark").inner_text().replace("CH", "").strip())
                    page.get_by_role("button", name="API tokens").click()
                    page.get_by_label("Token name").fill("browser acceptance")
                    page.get_by_role("button", name="Issue token").click()
                    token_secret = page.get_by_label("New API token").input_value()
                    self.assertTrue(token_secret.startswith("chm_at_"))
                    page.get_by_text("browser acceptance", exact=True).wait_for()
                    page.get_by_role("button", name="Revoke").click()
                    page.get_by_text("revoked", exact=False).wait_for()
                    page.get_by_role("button", name="Close").click()
                    page.reload(wait_until="networkidle")
                    self.assertEqual("light", page.evaluate("document.documentElement.dataset.theme"))
                    fixture = page.request.post(f"http://127.0.0.1:{port}/api/v1/servers", data={"name": "Browser fixture", "host": "fixture.local", "adapter": "fixture"})
                    self.assertEqual(201, fixture.status)
                    server_id = fixture.json()["id"]
                    self.assertEqual(200, page.request.post(f"http://127.0.0.1:{port}/api/v1/servers/{server_id}/discover", data={}).status)
                    page.reload(wait_until="networkidle")
                    page.get_by_role("button", name="Run live check").click()
                    page.get_by_text("Live frames decoded; source timestamp", exact=False).wait_for(timeout=8000)
                    configured = page.request.post(f"http://127.0.0.1:{port}/api/v1/webhooks", data={"name":"Browser receiver","url":f"http://127.0.0.1:{port}/healthz","events":["incident.opened"]})
                    self.assertEqual(201, configured.status)
                    page.get_by_role("button", name="Webhooks").click()
                    page.get_by_role("heading", name="Webhook receivers").wait_for()
                    self.assertTrue(page.get_by_label("Receiver name").is_visible())
                    self.assertTrue(page.get_by_label("Signing secret (optional, 16–256 characters)").is_visible())
                    self.assertTrue(page.get_by_text("incident.opened", exact=True).is_visible())
                    page.get_by_role("button", name="Edit").click()
                    page.get_by_label("Receiver name").fill("Edited browser receiver")
                    page.get_by_role("button", name="Save receiver").click()
                    page.get_by_role("heading", name="Edited browser receiver").wait_for()
                    browser.close()
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
