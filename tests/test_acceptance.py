"""Black-box acceptance tests against a running Camera Health Monitor process."""

import json
import base64
import struct
import zlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RunningApp(unittest.TestCase):
    port_counter = 18763

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock_file = Path(self.temp.name) / "test-clock.epoch"
        self.clock_file.write_text(str(time.time()))
        type(self).port_counter += 1
        self.port = type(self).port_counter
        env = os.environ.copy()
        env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port), "CHM_ENABLE_FIXTURE": "true", "CHM_DISCOVERY_INTERVAL_SECONDS": "3600", "CHM_TEST_CLOCK_FILE": str(self.clock_file), "CHM_SCHEDULER_TICK_SECONDS": "0.25", "CHM_LIVE_CHECK_TIMEOUT_SECONDS": "2"})
        self.env = env.copy()
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        else:
            raise RuntimeError("application did not start")

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.temp.cleanup()

    def request(self, path, method="GET", body=None, cookie=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {}), **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers, err.read()

    def advance_clock(self, seconds):
        self.clock_file.write_text(str(float(self.clock_file.read_text()) + seconds))

    def set_clock(self, epoch):
        self.clock_file.write_text(str(float(epoch)))

    def restart_app(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=self.env, cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                return
            except Exception:
                time.sleep(.1)
        raise RuntimeError("application did not restart")

    def test_first_admin_setup_is_single_use_and_login_persists_after_restart(self):
        status, _, body = self.request("/api/v1/setup/status")
        self.assertEqual(200, status)
        self.assertEqual({"setup_required": True}, json.loads(body))
        status, headers, body = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        self.assertEqual(201, status)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        self.assertEqual(409, self.request("/api/v1/setup/admin", "POST", {"username": "takeover", "password": "A-secure-password-2026"})[0])
        self.assertEqual(200, self.request("/api/v1/auth/me", cookie=cookie)[0])
        self.assertEqual(204, self.request("/api/v1/auth/logout", "POST", cookie=cookie)[0])
        self.assertEqual(401, self.request("/api/v1/auth/me")[0])
        self.proc.terminate()
        self.proc.wait(timeout=5)
        env = os.environ.copy()
        env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port)})
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        self.assertEqual({"setup_required": False}, json.loads(self.request("/api/v1/setup/status")[2]))
        self.assertEqual(401, self.request("/api/v1/auth/me")[0])
        status, headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        self.assertEqual(200, status)
        self.assertEqual(200, self.request("/api/v1/auth/me", cookie=headers.get("Set-Cookie").split(";", 1)[0])[0])

    def test_incidents_are_independent_acknowledgeable_and_resolve_after_recovery(self):
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        _, _, created = self.request("/api/v1/servers", "POST", {"name": "Fixture recorder", "host": "fixture.local", "adapter": "fixture", "fixture_profile": "recording_invalid_media"}, cookie)
        server_id = json.loads(created)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
        for _ in range(30):
            incidents = json.loads(self.request("/api/v1/incidents", cookie=cookie)[2])
            if incidents:
                break
            time.sleep(.1)
        self.assertEqual(1, len(incidents))
        incident = incidents[0]
        self.assertEqual("recording", incident["check_type"])
        self.assertEqual("decode_failed", incident["reason"])
        self.assertEqual("failure", incident["severity"])
        _, _, operator_created = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "incident reviewer", "role": "operator", "scopes": ["health:read"],
        }, cookie)
        operator_token = json.loads(operator_created)["token"]
        operator_headers = {"Authorization": f"Bearer {operator_token}"}
        self.assertEqual(200, self.request("/api/v1/incidents", headers=operator_headers)[0])
        self.assertEqual(403, self.request(f"/api/v1/incidents/{incident['id']}/acknowledge", "POST", {}, headers=operator_headers)[0])
        self.assertEqual(200, self.request(f"/api/v1/incidents/{incident['id']}/acknowledge", "POST", {}, cookie)[0])
        acknowledged = json.loads(self.request(f"/api/v1/incidents/{incident['id']}", cookie=cookie)[2])
        self.assertEqual("open", acknowledged["status"])
        self.assertEqual("siteadmin", acknowledged["acknowledged_by"])
        self.assertEqual(2, len(acknowledged["transitions"]))
        self.assertEqual("failure", json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]["recording_status"]["health"])
        self.restart_app()
        _, login_headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = login_headers.get("Set-Cookie").split(";", 1)[0]
        self.assertEqual(1, len(json.loads(self.request("/api/v1/incidents", cookie=cookie)[2])))
        self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "recording_success"}, cookie)
        self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
        for _ in range(30):
            acknowledged = json.loads(self.request(f"/api/v1/incidents/{incident['id']}", cookie=cookie)[2])
            if acknowledged["status"] == "resolved":
                break
            time.sleep(.1)
        self.assertEqual("resolved", acknowledged["status"])
        self.assertEqual("resolved", acknowledged["transitions"][-1]["event"])

    def test_server_outage_is_grouped_and_unknown_connector_error_is_not_camera_incident(self):
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        _, _, created = self.request("/api/v1/servers", "POST", {"name": "Fixture recorder", "host": "fixture.local", "adapter": "fixture", "fixture_profile": "recording_search_error"}, cookie)
        server_id = json.loads(created)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera_id = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]["id"]
        self.request(f"/api/v1/cameras/{camera_id}/recording-check", "POST", {}, cookie)
        time.sleep(.3)
        self.assertEqual([], json.loads(self.request("/api/v1/incidents", cookie=cookie)[2]))
        self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "server_unavailable"}, cookie)
        self.request(f"/api/v1/cameras/{camera_id}/recording-check", "POST", {}, cookie)
        for _ in range(30):
            incidents = json.loads(self.request("/api/v1/incidents", cookie=cookie)[2])
            if incidents:
                break
            time.sleep(.1)
        self.assertEqual(1, len(incidents))
        self.assertEqual("server", incidents[0]["entity_type"])
        self.assertEqual("server_unavailable", incidents[0]["reason"])
        self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "recording_success"}, cookie)
        self.request(f"/api/v1/cameras/{camera_id}/recording-check", "POST", {}, cookie)
        for _ in range(30):
            status = json.loads(self.request(f"/api/v1/incidents/{incidents[0]['id']}", cookie=cookie)[2])
            if status["status"] == "resolved":
                break
            time.sleep(.1)
        self.assertEqual("resolved", status["status"])
        self.assertEqual([], json.loads(self.request("/api/v1/incidents", cookie=cookie)[2]))

    def test_recording_warning_escalates_in_place_and_history_is_range_limited(self):
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        _, _, created = self.request("/api/v1/servers", "POST", {"name": "Quiet fixture", "host": "quiet.local", "adapter": "fixture", "fixture_profile": "recording_none"}, cookie)
        server_id = json.loads(created)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera_id = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]["id"]
        self.request(f"/api/v1/cameras/{camera_id}/recording-check", "POST", {}, cookie)
        for _ in range(30):
            incidents = json.loads(self.request("/api/v1/incidents", cookie=cookie)[2])
            if incidents:
                break
            time.sleep(.1)
        self.assertEqual("warning", incidents[0]["severity"])
        incident_id = incidents[0]["id"]
        self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "recording_invalid_media"}, cookie)
        self.request(f"/api/v1/cameras/{camera_id}/recording-check", "POST", {}, cookie)
        for _ in range(30):
            detail = json.loads(self.request(f"/api/v1/incidents/{incident_id}", cookie=cookie)[2])
            if detail["severity"] == "failure":
                break
            time.sleep(.1)
        self.assertEqual(incident_id, detail["id"])
        self.assertEqual("decode_failed", detail["reason"])
        self.assertEqual(["opened", "updated"], [event["event"] for event in detail["transitions"]])
        self.assertEqual("unknown", json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]["live_status"]["health"])
        history = json.loads(self.request("/api/v1/history?days=90", cookie=cookie)[2])
        self.assertEqual(incident_id, history["incidents"][0]["id"])
        self.assertEqual(400, self.request("/api/v1/history?days=91", cookie=cookie)[0])

    def test_empty_dashboard_and_api_docs_are_publicly_observable(self):
        self.assertEqual(401, self.request("/api/v1/dashboard")[0])
        self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        status, headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        self.assertEqual(200, status)
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        status, _, dashboard = self.request("/api/v1/dashboard", cookie=cookie)
        self.assertEqual(200, status)
        self.assertEqual([], json.loads(dashboard)["servers"])
        _, _, html = self.request("/")
        self.assertIn(b"Camera Health Monitor", html)
        _, _, js = self.request("/app.js")
        self.assertIn(b"/api/v1/${path}", js)
        self.assertIn(b'api("dashboard")', js)
        self.assertEqual(200, self.request("/openapi.json")[0])
        self.assertEqual(200, self.request("/docs")[0])
        self.assertEqual(200, self.request("/docs.js")[0])
        contract = json.loads(self.request("/openapi.json")[2])
        self.assertIn("requestBody", contract["paths"]["/setup/admin"]["post"])
        self.assertIn("sessionCookie", contract["paths"]["/dashboard"]["get"]["security"][0])
        self.assertIn("put", contract["paths"]["/branding"])
        self.assertIn("get", contract["paths"]["/incidents"])
        self.assertIn("post", contract["paths"]["/incidents/{incident_id}/acknowledge"])
        self.assertIn("/history", contract["paths"])
        self.assertIn("sessionCookie", contract["paths"]["/branding"]["put"]["security"][0])
        self.assertEqual(404, self.request("/api/v1/admin/credentials", "DELETE", cookie=cookie)[0])

    def test_api_tokens_are_show_once_scoped_expiring_revocable_and_attributed(self):
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        status, _, created = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "dashboard automation", "role": "administrator", "scopes": ["health:read"],
        }, cookie)
        self.assertEqual(201, status)
        issued = json.loads(created)
        secret = issued["token"]
        self.assertTrue(secret.startswith("chm_at_"))
        self.assertNotIn("token", json.loads(self.request("/api/v1/admin/api-tokens", cookie=cookie)[2])[0])
        self.assertEqual(200, self.request("/api/v1/dashboard", headers={"Authorization": f"Bearer {secret}"})[0])
        status, _, denied = self.request("/api/v1/servers", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(403, status)
        self.assertEqual("insufficient_scope", json.loads(denied)["error"])
        self.assertEqual(403, self.request("/api/v1/admin/auth/oidc", headers={"Authorization": f"Bearer {secret}"})[0])
        self.assertEqual(400, self.request("/api/v1/admin/api-tokens", "POST", {"name": "bad", "role": "administrator", "scopes": ["health:read", "superuser"]}, cookie)[0])
        status, _, mutation_token = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "branding automation", "role": "administrator", "scopes": ["branding:write"],
        }, cookie)
        mutation_secret = json.loads(mutation_token)["token"]
        branding = json.loads(self.request("/api/v1/branding")[2])
        self.assertEqual(200, self.request("/api/v1/branding", "PUT", branding,
                                            headers={"Authorization": f"Bearer {mutation_secret}"})[0])
        status, _, audit = self.request("/api/v1/admin/audit", cookie=cookie)
        self.assertEqual(200, status)
        self.assertEqual("api_token", json.loads(audit)[0]["actor_type"])
        self.assertNotIn(secret.encode(), audit)
        token_id = issued["id"]
        self.assertEqual(204, self.request(f"/api/v1/admin/api-tokens/{token_id}", "DELETE", cookie=cookie)[0])
        self.assertEqual(401, self.request("/api/v1/dashboard", headers={"Authorization": f"Bearer {secret}"})[0])

    def test_api_token_role_ceiling_and_expiration_reject_without_redirect(self):
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        self.assertEqual(400, self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "operator", "role": "operator", "scopes": ["branding:write"],
        }, cookie)[0])
        # Use a whole-second expiry and wait until that exact instant has passed.
        expires_epoch = int(time.time()) + 2
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_epoch))
        status, _, created = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "expiring", "role": "operator", "scopes": ["health:read"], "expires_at": expires_at,
        }, cookie)
        self.assertEqual(201, status)
        created_payload = json.loads(created)
        self.assertTrue(created_payload["expires_at"].endswith("+00:00"))
        secret = created_payload["token"]
        time.sleep(max(0, expires_epoch - time.time() + 0.1))
        status, headers, _ = self.request("/api/v1/dashboard", headers={"Authorization": f"Bearer {secret}"})
        self.assertEqual(401, status)
        self.assertNotIn("Location", headers)

    def test_simultaneous_first_run_requests_cannot_create_a_second_admin(self):
        def create(name):
            return self.request("/api/v1/setup/admin", "POST", {"username": name, "password": "A-secure-password-2026"})[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, ["admin-one", "admin-two"]))
        self.assertEqual([201, 409], sorted(results))

    def test_credential_change_and_password_redaction(self):
        self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        status, headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        self.assertEqual(200, status)
        status, headers, body = self.request("/api/v1/admin/credentials", "PUT", {"current_password": "A-secure-password-2026", "username": "siteadmin", "new_password": "Another-secure-password-2026"}, cookie)
        self.assertEqual(200, status)
        self.assertNotIn(b"password", body.lower())
        self.assertEqual(200, self.request("/api/v1/auth/me", cookie=headers.get("Set-Cookie").split(";", 1)[0])[0])
        self.assertEqual(401, self.request("/api/v1/auth/me", cookie=cookie)[0])
        self.assertEqual(401, self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})[0])
        self.assertEqual(200, self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "Another-secure-password-2026"})[0])

    def test_shared_branding_is_public_but_admin_only_to_change_and_survives_restart(self):
        status, _, body = self.request("/api/v1/branding")
        self.assertEqual(200, status)
        original = json.loads(body)
        self.assertEqual("Camera Health Monitor", original["app_name"])
        self.assertEqual(401, self.request("/api/v1/branding", "PUT", {"app_name": "Changed"})[0])

        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        branding = {
            "app_name": "Village Camera Watch",
            "colors": {theme: {"accent": "#123456", "background": "#101010", "surface": "#202020", "text": "#fefefe"} for theme in ("light", "dark")},
            "sso_button_text": "Continue with Village Login",
        }
        status, _, body = self.request("/api/v1/branding", "PUT", branding, cookie)
        self.assertEqual(200, status)
        persisted = json.loads(body)
        self.assertEqual({**branding, "colors": {theme: {key: value.upper() for key, value in colors.items()} for theme, colors in branding["colors"].items()}}, {key: persisted[key] for key in branding})
        self.assertEqual(200, self.request("/api/v1/dashboard", cookie=cookie)[0])
        invalid_colors = json.loads(json.dumps(branding))
        invalid_colors["colors"]["dark"]["accent"] = "red; background:url(javascript:alert(1))"
        self.assertEqual(400, self.request("/api/v1/branding", "PUT", invalid_colors, cookie)[0])
        self.assertEqual("Village Camera Watch", json.loads(self.request("/api/v1/branding")[2])["app_name"])

        self.proc.terminate(); self.proc.wait(timeout=5)
        env = os.environ.copy(); env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port)})
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try: self.request("/api/v1/branding"); break
            except Exception: time.sleep(.1)
        self.assertEqual("Village Camera Watch", json.loads(self.request("/api/v1/branding")[2])["app_name"])

    def test_branding_image_validation_and_safe_serving(self):
        self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        _, headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        cookie = headers.get("Set-Cookie").split(";", 1)[0]
        invalid = base64.b64encode(b"<svg onload=alert(1)></svg>").decode()
        self.assertEqual(400, self.request("/api/v1/branding/assets/light_logo", "PUT", {"data": invalid}, cookie)[0])
        # A complete, minimal PNG fixture (1x1) is accepted and served as inert image bytes.
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
        png_bytes = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00")) + chunk(b"IEND", b"")
        png = base64.b64encode(png_bytes).decode()
        status, _, result = self.request("/api/v1/branding/assets/light_logo", "PUT", {"data": png}, cookie)
        self.assertEqual(200, status)
        url = json.loads(result)["url"]
        status, headers, image = self.request(url)
        self.assertEqual(200, status)
        self.assertEqual("image/png", headers.get("Content-Type"))
        self.assertEqual("nosniff", headers.get("X-Content-Type-Options"))
        self.assertEqual(png_bytes, image)
        self.assertEqual(400, self.request("/api/v1/branding/assets/light_logo", "PUT", {"data": invalid}, cookie)[0])
        self.assertEqual(png_bytes, self.request(url)[2])
        current = json.loads(self.request("/api/v1/branding")[2])
        rejected = {"app_name": "Not saved", "sso_button_text": "Login", "colors": current["colors"], "asset_uploads": {"light_logo": invalid}}
        self.assertEqual(400, self.request("/api/v1/branding", "PUT", rejected, cookie)[0])
        self.assertEqual(png_bytes, self.request(url)[2])
        self.assertEqual(current["app_name"], json.loads(self.request("/api/v1/branding")[2])["app_name"])
        self.assertEqual(404, self.request("/api/v1/branding/assets/../../app.py")[0])

    def test_browser_preference_is_local_and_settings_markup_exposes_preview_discard_reset(self):
        _, _, html = self.request("/")
        _, _, js = self.request("/app.js")
        self.assertIn(b"data-theme", html)
        self.assertIn(b"localStorage", js)
        self.assertIn(b"branding-dialog", js)
        self.assertIn(b"Discard changes", js)
        self.assertIn(b"Reset branding", js)


    def login(self):
        self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        status, headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        self.assertEqual(200, status)
        return headers.get("Set-Cookie").split(";", 1)[0]

    def test_server_crud_redacts_credentials_and_preserves_inventory_identity(self):
        cookie = self.login()
        secret = "fixture-secret-do-not-return"
        status, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Recorder A", "host": "recorder-a.local", "port": 22609,
            "username": "monitor", "password": secret, "adapter": "fixture"
        }, cookie)
        self.assertEqual(201, status)
        server = json.loads(body)
        self.assertNotIn(secret, body.decode())
        self.assertTrue(server["credentials_configured"])
        server_id = server["id"]
        status, _, body = self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        self.assertEqual(200, status)
        self.assertEqual(1, json.loads(body)["discovered"])
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        camera_id = camera["id"]
        self.assertEqual(server_id, camera["server_id"])
        self.assertEqual("camera-1", camera["remote_id"])
        self.assertEqual("untested", camera["capabilities"]["live_delivery"]["status"])
        self.assertEqual({"live_interval_minutes": 5, "recording_interval_minutes": 60, "recording_lookback_hours": 24, "recording_expected": True}, camera["settings"])
        self.assertEqual(200, self.request(f"/api/v1/cameras/{camera_id}", "PUT", {"overrides": {"recording_lookback_hours": 48}}, cookie)[0])
        self.assertEqual(200, self.request(f"/api/v1/servers/{server_id}", cookie=cookie)[0])
        status, _, updated = self.request(f"/api/v1/servers/{server_id}", "PUT", {"name": "Renamed recorder", "password": ""}, cookie)
        self.assertEqual(200, status)
        self.assertNotIn(secret, updated.decode())
        self.assertTrue(json.loads(updated)["credentials_configured"])
        rediscovered_camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.assertEqual(camera_id, rediscovered_camera["id"])
        self.assertEqual({"recording_lookback_hours": 48}, rediscovered_camera["overrides"])
        self.assertEqual("Renamed recorder", json.loads(self.request("/api/v1/servers", cookie=cookie)[2])[0]["name"])
        self.proc.terminate()
        self.proc.wait(timeout=5)
        env = os.environ.copy()
        env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port), "CHM_ENABLE_FIXTURE": "true", "CHM_DISCOVERY_INTERVAL_SECONDS": "3600"})
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        cookie = self.login()
        persisted = json.loads(self.request(f"/api/v1/servers/{server_id}", cookie=cookie)[2])
        self.assertEqual("Renamed recorder", persisted["name"])
        self.assertTrue(persisted["credentials_configured"])
        self.assertEqual(camera_id, json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]["id"])
        self.assertEqual(204, self.request(f"/api/v1/servers/{server_id}", "DELETE", cookie=cookie)[0])
        self.assertEqual([], json.loads(self.request("/api/v1/cameras", cookie=cookie)[2]))

    def test_multiple_servers_isolate_duplicate_remote_camera_ids(self):
        cookie = self.login()
        server_ids = []
        for label in ("A", "B"):
            status, _, body = self.request("/api/v1/servers", "POST", {
                "name": f"Recorder {label}", "host": f"recorder-{label.lower()}.local", "adapter": "fixture"
            }, cookie)
            self.assertEqual(201, status)
            server_ids.append(json.loads(body)["id"])
        for server_id in server_ids:
            self.assertEqual(200, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)[0])
        cameras = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])
        self.assertEqual(2, len(cameras))
        self.assertEqual({"camera-1"}, {camera["remote_id"] for camera in cameras})
        self.assertEqual(set(server_ids), {camera["server_id"] for camera in cameras})
        self.assertEqual(2, len({camera["id"] for camera in cameras}))

    def test_exacq_connection_probe_and_discovery_report_sanitized_failure(self):
        cookie = self.login()
        status, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Production recorder", "host": "127.0.0.1", "web_port": 1, "adapter": "exacq"
        }, cookie)
        self.assertEqual(201, status)
        server_id = json.loads(body)["id"]
        status, _, body = self.request(f"/api/v1/servers/{server_id}/capabilities", "POST", {}, cookie)
        self.assertEqual(502, status)
        caps = json.loads(body)["capabilities"]
        self.assertEqual("failed", caps["web_service"]["status"])
        self.assertEqual("untested", caps["camera_discovery"]["status"])
        self.assertEqual(502, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)[0])
        current = next(s for s in json.loads(self.request("/api/v1/servers", cookie=cookie)[2]) if s["id"] == server_id)
        self.assertEqual("failed", current["capabilities"]["camera_discovery"]["status"])
        self.assertNotIn("username", current)
        self.assertNotIn("password", current)

    def test_fixture_errors_and_disappeared_camera_are_visible_and_preserve_history(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Fixture recorder", "host": "fixture.local", "adapter": "fixture", "fixture_profile": "discovery_error"
        }, cookie)
        server_id = json.loads(body)["id"]
        self.assertEqual(502, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)[0])
        failed = json.loads(self.request(f"/api/v1/servers/{server_id}/capabilities", "GET", cookie=cookie)[2])
        self.assertEqual("failed", failed["capabilities"]["camera_discovery"]["status"])
        self.assertEqual(200, self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "success"}, cookie)[0])
        self.assertEqual(200, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)[0])
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.assertFalse(camera["disappeared"])
        self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "no_cameras"}, cookie)
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.assertTrue(camera["disappeared"])

    def test_fixture_capability_probe_reports_each_capability_independently(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Fixture recorder", "host": "fixture.local", "adapter": "fixture", "fixture_profile": "capability_error"
        }, cookie)
        server_id = json.loads(body)["id"]
        result = json.loads(self.request(f"/api/v1/servers/{server_id}/capabilities", "POST", {}, cookie)[2])
        self.assertEqual("failed", result["capabilities"]["live_delivery"]["status"])
        self.assertEqual("untested", result["capabilities"]["recording_search"]["status"])
        self.assertEqual("untested", result["capabilities"]["recorded_playback"]["status"])

    def test_periodic_inventory_refresh_discovers_fixture_cameras(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        env = os.environ.copy()
        env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port), "CHM_ENABLE_FIXTURE": "true", "CHM_DISCOVERY_INTERVAL_SECONDS": "1"})
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {"name": "Periodic", "host": "fixture.local", "adapter": "fixture"}, cookie)
        server_id = json.loads(body)["id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            server = json.loads(self.request(f"/api/v1/servers/{server_id}", cookie=cookie)[2])
            if server["capabilities"]["camera_discovery"]["status"] == "verified":
                break
            time.sleep(.1)
        self.assertEqual("verified", server["capabilities"]["camera_discovery"]["status"])
        self.assertEqual(1, len(json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])))

    def test_live_feed_requires_camera_access_and_reports_unavailable_fixture(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Live feed fixture", "host": "live-feed.local", "adapter": "fixture",
        }, cookie)
        server_id = json.loads(body)["id"]
        self.assertEqual(200, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)[0])
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.assertEqual(401, self.request(f"/api/v1/cameras/{camera['id']}/live-feed")[0])
        status, _, response_body = self.request(f"/api/v1/cameras/{camera['id']}/live-feed", cookie=cookie)
        self.assertEqual(503, status)
        self.assertEqual("live_feed_unavailable", json.loads(response_body)["error"])

    def test_live_check_decodes_sample_and_exposes_pollable_result(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Fixture recorder", "host": "fixture.local", "adapter": "fixture"
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]

        _, _, limited_body = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "read-only automation", "role": "operator", "scopes": ["health:read"],
        }, cookie)
        limited_token = json.loads(limited_body)["token"]
        self.assertEqual(403, self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {},
                                            headers={"Authorization": f"Bearer {limited_token}"})[0])
        _, _, runner_body = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "live check automation", "role": "operator", "scopes": ["checks:run", "health:read"],
        }, cookie)
        runner_token = json.loads(runner_body)["token"]
        bearer = {"Authorization": f"Bearer {runner_token}"}
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {}, headers=bearer)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        self.assertIn(json.loads(body)["status"], ("queued", "running"))
        result = None
        deadline = time.time() + 8
        while time.time() < deadline:
            status, _, body = self.request(f"/api/v1/live-checks/{job_id}", headers=bearer)
            self.assertEqual(200, status)
            result = json.loads(body)
            if result["status"] in ("succeeded", "failed", "cancelled", "unsupported"):
                break
            time.sleep(.05)
        self.assertEqual("succeeded", result["status"])
        self.assertTrue(result["result"]["decoded"])
        self.assertGreaterEqual(result["result"]["frames_decoded"], 1)
        self.assertIn("sample_timestamp", result["result"])
        self.assertEqual("0.000000", result["result"]["frame_timestamp"])
        self.assertIsNone(result["error"])
        self.assertEqual([], list(Path(self.temp.name).glob("chm-live-*")))
        audit = json.loads(self.request("/api/v1/admin/audit", cookie=cookie)[2])
        check_audit = next(event for event in audit if event["action"] == "live_check.started")
        self.assertEqual("api_token", check_audit["actor_type"])
        self.assertEqual("live check automation", check_audit["actor_name"])

        self.assertEqual(401, self.request(f"/api/v1/live-checks/{job_id}")[0])

    def test_live_check_invalid_media_fails_decode_and_exacq_connection_failure_is_reported(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Fixture recorder", "host": "fixture.local", "adapter": "fixture", "fixture_profile": "invalid_media"
        }, cookie)
        fixture_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{fixture_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        deadline = time.time() + 8
        while time.time() < deadline:
            result = json.loads(self.request(f"/api/v1/live-checks/{job_id}", cookie=cookie)[2])
            if result["status"] in ("succeeded", "failed", "cancelled", "unsupported"):
                break
            time.sleep(.05)
        self.assertEqual("failed", result["status"])
        self.assertEqual("decode_failed", result["error"]["code"])
        self.assertEqual([], list(Path(self.temp.name).glob("chm-live-*")))

        _, _, body = self.request("/api/v1/servers", "POST", {"name": "Real", "host": "127.0.0.1", "web_port": 1}, cookie)
        exacq_id = json.loads(body)["id"]
        self.assertEqual(502, self.request(f"/api/v1/servers/{exacq_id}/discover", "POST", {}, cookie)[0])
        self.assertFalse(any(camera["server_id"] == exacq_id for camera in json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])))

    def test_live_check_prevents_overlap_and_can_be_cancelled(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Slow fixture", "host": "fixture.local", "adapter": "fixture", "fixture_profile": "live_slow"
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {}, cookie)
        self.assertEqual(409, status)
        self.assertEqual(job_id, json.loads(body)["job_id"])
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
        self.assertEqual(409, status)
        self.assertEqual(job_id, json.loads(body)["job_id"])
        self.assertEqual(202, self.request(f"/api/v1/live-checks/{job_id}", "DELETE", cookie=cookie)[0])
        deadline = time.time() + 4
        while time.time() < deadline:
            job = json.loads(self.request(f"/api/v1/live-checks/{job_id}", cookie=cookie)[2])
            if job["status"] == "cancelled":
                break
            time.sleep(.05)
        self.assertEqual("cancelled", job["status"])

    def test_monitoring_api_exposes_persistent_intervals_and_separate_current_success(self):
        self.assertEqual(401, self.request("/api/v1/monitoring")[0])
        cookie = self.login()
        _, _, token_body = self.request("/api/v1/admin/api-tokens", "POST", {
            "name": "history only", "role": "operator", "scopes": ["history:read"],
        }, cookie)
        token = json.loads(token_body)["token"]
        self.assertEqual(403, self.request("/api/v1/monitoring", headers={"Authorization": f"Bearer {token}"})[0])
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Scheduled fixture", "host": "scheduled.local", "adapter": "fixture",
            "defaults": {"live_interval_minutes": 5, "recording_interval_minutes": 60, "recording_lookback_hours": 24},
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        status, _, updated = self.request(f"/api/v1/cameras/{camera['id']}", "PUT", {
            "overrides": {"live_interval_minutes": 2, "recording_interval_minutes": 15},
        }, cookie)
        self.assertEqual(200, status)
        self.assertEqual(2, json.loads(updated)["settings"]["live_interval_minutes"])
        status, _, monitoring = self.request("/api/v1/monitoring", cookie=cookie)
        self.assertEqual(200, status)
        details = json.loads(monitoring)
        self.assertIn(camera["id"], {row["camera_id"] for row in details["cameras"]})
        camera_status = next(row for row in details["cameras"] if row["camera_id"] == camera["id"])
        self.assertEqual(120, camera_status["intervals_seconds"]["live"])
        self.assertEqual(900, camera_status["intervals_seconds"]["recording"])
        self.assertIn("last_success_at", camera_status["live"])
        self.assertIn("current_health", camera_status["live"])

    def test_scheduled_live_failure_waits_for_clock_driven_confirmation(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Scheduled failing fixture", "host": "scheduled-failure.local", "adapter": "fixture",
            "fixture_profile": "success",
            "defaults": {"live_interval_minutes": 1, "recording_interval_minutes": 60, "recording_lookback_hours": 24},
        }, cookie)
        server_id = json.loads(body)["id"]
        self.assertEqual(200, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)[0])
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        status, _, manual = self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        manual_id = json.loads(manual)["id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            manual_status = json.loads(self.request(f"/api/v1/live-checks/{manual_id}", cookie=cookie)[2])
            if manual_status["status"] == "succeeded":
                break
            time.sleep(.1)
        self.assertEqual("succeeded", manual_status["status"])
        self.request(f"/api/v1/servers/{server_id}", "PUT", {"fixture_profile": "invalid_media"}, cookie)
        # Let the autonomous scheduler reach the next due time. No page remains open.
        deadline = time.time() + 3
        scheduled = None
        while time.time() < deadline:
            before = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            scheduled = next(row for row in before["cameras"] if row["camera_id"] == camera["id"])
            if scheduled["next_due_at"]["live"]:
                break
            time.sleep(.1)
        due_epoch = datetime.fromisoformat(scheduled["next_due_at"]["live"].replace("Z", "+00:00")).timestamp()
        self.set_clock(due_epoch + 1)
        pending = None
        deadline = time.time() + 8
        while time.time() < deadline:
            status = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            pending = next(row for row in status["cameras"] if row["camera_id"] == camera["id"])
            if pending["live"]["state"] == "pending_confirmation":
                break
            time.sleep(.1)
        self.assertEqual("pending_confirmation", pending["live"]["state"])
        self.assertEqual("unknown", pending["live"]["current_health"])
        self.assertIsNotNone(pending["live"]["last_success_at"])
        self.advance_clock(31)
        deadline = time.time() + 8
        while time.time() < deadline:
            status = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            current = next(row for row in status["cameras"] if row["camera_id"] == camera["id"])
            if current["live"]["state"] == "failure":
                break
            time.sleep(.1)
        self.assertEqual("failure", current["live"]["state"])

    def test_scheduled_live_confirmation_success_recovers_and_timeout_is_reported(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Flaky fixture", "host": "flaky.local", "adapter": "fixture", "fixture_profile": "live_flaky",
            "defaults": {"live_interval_minutes": 1, "recording_interval_minutes": 60, "recording_lookback_hours": 24},
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        deadline = time.time() + 3
        while time.time() < deadline:
            schedule = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            row = next(item for item in schedule["cameras"] if item["camera_id"] == camera["id"])
            if row["next_due_at"]["live"]:
                break
            time.sleep(.1)
        self.set_clock(datetime.fromisoformat(row["next_due_at"]["live"].replace("Z", "+00:00")).timestamp() + 1)
        deadline = time.time() + 8
        while time.time() < deadline:
            status = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            current = next(item for item in status["cameras"] if item["camera_id"] == camera["id"])
            if current["live"]["state"] == "pending_confirmation":
                break
            time.sleep(.1)
        self.assertEqual("pending_confirmation", current["live"]["state"])
        self.advance_clock(31)
        deadline = time.time() + 8
        while time.time() < deadline:
            status = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            current = next(item for item in status["cameras"] if item["camera_id"] == camera["id"])
            if current["live"]["state"] == "healthy":
                break
            time.sleep(.1)
        self.assertEqual("healthy", current["live"]["state"])
        self.assertIsNotNone(current["live"]["last_success_at"])

        _, _, timeout_body = self.request("/api/v1/servers", "POST", {
            "name": "Timeout fixture", "host": "timeout.local", "adapter": "fixture", "fixture_profile": "live_timeout",
        }, cookie)
        timeout_server = json.loads(timeout_body)["id"]
        self.request(f"/api/v1/servers/{timeout_server}/discover", "POST", {}, cookie)
        timeout_camera = next(item for item in json.loads(self.request("/api/v1/cameras", cookie=cookie)[2]) if item["server_id"] == timeout_server)
        status, _, job_body = self.request(f"/api/v1/cameras/{timeout_camera['id']}/live-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        job_id = json.loads(job_body)["id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            job = json.loads(self.request(f"/api/v1/live-checks/{job_id}", cookie=cookie)[2])
            if job["status"] in ("failed", "succeeded", "cancelled"):
                break
            time.sleep(.1)
        self.assertEqual("timeout", job["error"]["code"])

    def test_restart_skips_missed_monitoring_runs_and_keeps_the_next_schedule(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Restart fixture", "host": "restart.local", "adapter": "fixture",
            "defaults": {"live_interval_minutes": 5, "recording_interval_minutes": 60, "recording_lookback_hours": 24},
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        status = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
        row = next(item for item in status["cameras"] if item["camera_id"] == camera["id"])
        self.assertIsNotNone(row["next_due_at"]["live"])
        downtime_clock = float(self.clock_file.read_text()) + 24 * 3600
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.set_clock(downtime_clock)
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=self.env, cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        cookie = self.login()
        deadline = time.time() + 4
        while time.time() < deadline:
            status = json.loads(self.request("/api/v1/monitoring", cookie=cookie)[2])
            row = next(item for item in status["cameras"] if item["camera_id"] == camera["id"])
            next_due = datetime.fromisoformat(row["next_due_at"]["live"].replace("Z", "+00:00")).timestamp()
            if next_due > downtime_clock:
                break
            time.sleep(.1)
        self.assertGreater(next_due, downtime_clock)
        self.assertIsNone(row["active_job_id"])

    def test_recording_check_reports_no_recent_motion_as_warning_and_persists_separately(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Quiet fixture", "host": "quiet.local", "adapter": "fixture", "fixture_profile": "recording_none"
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        deadline = time.time() + 8
        while time.time() < deadline:
            result = json.loads(self.request(f"/api/v1/recording-checks/{job_id}", cookie=cookie)[2])
            if result["status"] in ("completed", "failed"):
                break
            time.sleep(.05)
        self.assertEqual("completed", result["status"])
        self.assertEqual("warning", result["result"]["health"])
        self.assertEqual("no_recent_recording", result["result"]["reason"])

    def test_camera_can_disable_missing_recording_alert_without_hiding_result(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Quiet fixture", "host": "quiet.local", "adapter": "fixture", "fixture_profile": "recording_none"
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = next(item for item in json.loads(self.request("/api/v1/cameras", cookie=cookie)[2]) if item["server_id"] == server_id)
        self.assertEqual(200, self.request(f"/api/v1/cameras/{camera['id']}", "PUT", {"overrides": {"recording_expected": False}}, cookie)[0])
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            result = json.loads(self.request(f"/api/v1/recording-checks/{job_id}", cookie=cookie)[2])
            if result["status"] == "completed":
                break
            time.sleep(.05)
        self.assertEqual("warning", result["result"]["health"])
        self.assertEqual("no_recent_recording", result["result"]["reason"])
        incidents = json.loads(self.request("/api/v1/incidents", cookie=cookie)[2])
        self.assertFalse(any(item.get("entity_id") == camera["id"] and item.get("status") == "open" for item in incidents))
        updated = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.assertEqual("warning", updated["recording_status"]["health"])
        self.assertIsNone(updated["recording_status"]["newest_recording_at"])
        self.assertEqual("unknown", updated["live_status"]["health"])

    def test_recording_check_decodes_newest_in_window_and_reports_bad_media_and_permissions(self):
        cookie = self.login()
        for profile, expected, reason in (("recording_success", "healthy", None), ("recording_invalid_media", "failure", "decode_failed"), ("recording_permission_error", "unknown", "permission_denied")):
            _, _, body = self.request("/api/v1/servers", "POST", {
                "name": profile, "host": f"{profile}.local", "adapter": "fixture", "fixture_profile": profile
            }, cookie)
            server_id = json.loads(body)["id"]
            self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
            camera = next(c for c in json.loads(self.request("/api/v1/cameras", cookie=cookie)[2]) if c["server_id"] == server_id)
            status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
            self.assertEqual(202, status)
            job_id = json.loads(body)["id"]
            deadline = time.time() + 8
            while time.time() < deadline:
                result = json.loads(self.request(f"/api/v1/recording-checks/{job_id}", cookie=cookie)[2])
                if result["status"] in ("completed", "failed"):
                    break
                time.sleep(.05)
            self.assertEqual("completed", result["status"])
            self.assertEqual(expected, result["result"]["health"])
            if expected == "healthy":
                self.assertIsNotNone(result["result"]["newest_recording_at"])
                self.assertTrue(result["result"]["decoded"])
                self.assertEqual("recording-newest.mp4", result["result"]["evidence"]["sample_name"])
            if reason:
                self.assertEqual(reason, result["result"]["reason"])
        self.assertEqual([], list(Path(self.temp.name).glob("chm-recording-*")))

    def test_recording_lookback_validation_and_server_batch_check_without_inventory(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {"name": "Real", "host": "127.0.0.1", "web_port": 1}, cookie)
        server_id = json.loads(body)["id"]
        status, _, body = self.request(f"/api/v1/servers/{server_id}/recording-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        self.assertEqual([], json.loads(body)["jobs"])
        self.assertEqual(400, self.request(f"/api/v1/cameras/not-real", "PUT", {"overrides": {"recording_lookback_hours": 0}}, cookie)[0])

    def test_recording_window_includes_exact_boundary_and_camera_override_changes_window(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {
            "name": "Boundary fixture", "host": "boundary.local", "adapter": "fixture",
            "fixture_profile": "recording_boundary", "defaults": {"recording_lookback_hours": 12}
        }, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        camera = json.loads(self.request("/api/v1/cameras", cookie=cookie)[2])[0]
        self.assertEqual(12, camera["settings"]["recording_lookback_hours"])
        self.assertEqual(200, self.request(f"/api/v1/cameras/{camera['id']}", "PUT", {"overrides": {"recording_lookback_hours": 6}}, cookie)[0])
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/recording-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        deadline = time.time() + 8
        while time.time() < deadline:
            result = json.loads(self.request(f"/api/v1/recording-checks/{job_id}", cookie=cookie)[2])
            if result["status"] == "completed": break
            time.sleep(.05)
        self.assertEqual(6, result["lookback_hours"])
        self.assertEqual("healthy", result["result"]["health"])
        self.assertEqual("recording-window-boundary.mp4", result["result"]["evidence"]["sample_name"])

    def test_server_recording_job_starts_jobs_for_present_cameras_and_docs_describe_api(self):
        cookie = self.login()
        _, _, body = self.request("/api/v1/servers", "POST", {"name": "Server fixture", "host": "server.local", "adapter": "fixture"}, cookie)
        server_id = json.loads(body)["id"]
        self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, cookie)
        status, _, body = self.request(f"/api/v1/servers/{server_id}/recording-check", "POST", {}, cookie)
        self.assertEqual(202, status)
        batch = json.loads(body)
        self.assertEqual(server_id, batch["server_id"])
        self.assertEqual(1, len(batch["jobs"]))
        spec = json.loads(self.request("/openapi.json")[2])
        self.assertIn("/cameras/{camera_id}/recording-check", spec["paths"])
        self.assertIn("/servers/{server_id}/recording-check", spec["paths"])

    def test_live_check_openapi_contract_and_authorization(self):
        contract = json.loads(self.request("/openapi.json")[2])
        self.assertIn("/cameras/{camera_id}/live-check", contract["paths"])
        self.assertIn("/live-checks/{job_id}", contract["paths"])
        self.assertEqual(401, self.request("/api/v1/live-checks/nope")[0])


if __name__ == "__main__":
    unittest.main()
