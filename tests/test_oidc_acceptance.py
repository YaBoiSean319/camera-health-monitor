"""Public REST acceptance coverage for configurable OIDC sign-in and roles."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]


class ProviderHandler(BaseHTTPRequestHandler):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issued_claims = {"sub": "person-1", "preferred_username": "operator@example.test", "groups": ["camera-ops"]}
    token_expired = False
    invalid_signature = False

    def log_message(self, *args):
        pass

    def json(self, payload, status=200):
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        if self.path == "/.well-known/openid-configuration":
            return self.json({"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "jwks_uri": base + "/jwks"})
        if self.path == "/jwks":
            nums = self.private_key.public_key().public_numbers()
            import base64
            enc = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8, "big")).rstrip(b"=").decode()
            return self.json({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key", "n": enc(nums.n), "e": enc(nums.e)}]})
        if self.path.startswith("/authorize?"):
            params = parse_qs(urlparse(self.path).query)
            self.server.expected_nonce = params["nonce"][0]
            self.server.expected_challenge = params["code_challenge"][0]
            redirect = params["redirect_uri"][0]
            state = params["state"][0]
            from urllib.parse import urlencode
            self.send_response(302)
            self.send_header("Location", redirect + "?" + urlencode({"code": "controlled-code", "state": state}))
            self.end_headers()
            return
        return self.json({"error": "not_found"}, 404)

    def do_POST(self):
        if self.path != "/token":
            return self.json({"error": "not_found"}, 404)
        params = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
        challenge = __import__("base64").urlsafe_b64encode(__import__("hashlib").sha256(params.get("code_verifier", [""])[0].encode()).digest()).rstrip(b"=").decode()
        if params.get("code") != ["controlled-code"] or challenge != self.server.expected_challenge or params.get("client_secret") != ["provider-secret"]:
            return self.json({"error": "invalid_grant"}, 400)
        import base64, hashlib, hmac
        b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        header = b64(json.dumps({"alg": "RS256", "kid": "test-key"}, separators=(",", ":")).encode())
        claims = dict(self.issued_claims)
        claims.update({"iss": f"http://127.0.0.1:{self.server.server_port}", "aud": "camera-monitor", "exp": int(time.time()) + 300, "iat": int(time.time()), "nonce": self.server.expected_nonce})
        if self.token_expired:
            claims["exp"] = int(time.time()) - 1
        body = b64(json.dumps(claims, separators=(",", ":")).encode())
        signing = f"{header}.{body}".encode()
        signature = self.private_key.sign(signing, __import__("cryptography").hazmat.primitives.asymmetric.padding.PKCS1v15(), __import__("cryptography").hazmat.primitives.hashes.SHA256())
        if self.invalid_signature:
            signature = bytes([signature[0] ^ 0x01]) + signature[1:]
        return self.json({"id_token": f"{header}.{body}.{b64(signature)}", "token_type": "Bearer"})


class OIDCAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = HTTPServer(("127.0.0.1", 0), ProviderHandler)
        cls.provider.expected_nonce = ""
        cls.provider_thread = threading.Thread(target=cls.provider.serve_forever, daemon=True)
        cls.provider_thread.start()
        cls.provider.expected_challenge = ""
        cls.issuer = f"http://127.0.0.1:{cls.provider.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.provider.shutdown()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.port = 19071 + (id(self) % 1000)
        env = os.environ.copy()
        env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port), "CHM_COOKIE_SECURE": "false", "CHM_ENABLE_FIXTURE": "true"})
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(60):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        else:
            raise RuntimeError("application did not start")
        status, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        self.admin_cookie = headers.get("Set-Cookie").split(";", 1)[0]

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.temp.cleanup()

    def request(self, path, method="GET", body=None, cookie=None):
        import urllib.request, urllib.error
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
             headers={"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {})})
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=4) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers, err.read()

    def cookie(self, headers, name):
        for value in headers.get_all("Set-Cookie", []):
            pair = value.split(";", 1)[0]
            if pair.startswith(name + "="):
                return pair
        return None

    def configure_oidc(self, cookie=None):
        return self.request("/api/v1/admin/auth/oidc", "PUT", {
            "issuer": self.issuer, "client_id": "camera-monitor", "client_secret": "provider-secret",
            "role_claim": "groups", "administrator_values": ["camera-admins"],
            "operator_values": ["camera-ops"],
        }, cookie or self.admin_cookie)

    def test_admin_can_configure_provider_without_secret_in_readback(self):
        self.assertEqual(200, self.configure_oidc()[0])
        status, _, body = self.request("/api/v1/admin/auth/oidc", cookie=self.admin_cookie)
        self.assertEqual(200, status)
        config = json.loads(body)
        self.assertTrue(config["enabled"])
        self.assertTrue(config["client_secret_configured"])
        self.assertNotIn("provider-secret", body.decode())
        self.assertNotIn("client_secret\":\"", body.decode())
        db_bytes = (Path(self.temp.name) / "camera-health-monitor.sqlite3").read_bytes()
        self.assertNotIn(b"provider-secret", db_bytes)
        status, _, body = self.request("/api/v1/admin/auth/oidc", cookie="chm_session=invalid")
        self.assertEqual(401, status)

    def test_operator_callback_gets_operator_session_and_cannot_change_credentials(self):
        self.assertEqual(200, self.configure_oidc()[0])
        status, headers, _ = self.request("/api/v1/auth/oidc/login")
        self.assertEqual(302, status)
        location = headers["Location"]
        from urllib.parse import urlparse, parse_qs
        args = parse_qs(urlparse(location).query)
        self.assertEqual("S256", args["code_challenge_method"][0])
        self.provider.expected_challenge = args["code_challenge"][0]
        callback = args["redirect_uri"][0]
        self.assertTrue(callback.endswith("/api/v1/auth/oidc/callback"))
        self.provider.expected_nonce = args["nonce"][0]
        callback_url = callback + "?code=controlled-code&state=" + args["state"][0]
        state_cookie = self.cookie(headers, "chm_oidc_state")
        self.assertIsNotNone(state_cookie)
        status, headers, body = self.request(urlparse(callback_url).path + "?" + urlparse(callback_url).query, cookie=state_cookie)
        self.assertEqual(302, status, body.decode())
        oidc_cookie = self.cookie(headers, "chm_session")
        status, _, body = self.request("/api/v1/auth/me", cookie=oidc_cookie)
        self.assertEqual(200, status)
        self.assertEqual("operator", json.loads(body)["role"])
        self.assertEqual(403, self.request("/api/v1/admin/credentials", "PUT", {"current_password": "x", "username": "x"}, oidc_cookie)[0])
        self.assertEqual(403, self.request("/api/v1/admin/auth/oidc", cookie=oidc_cookie)[0])
        self.assertEqual(200, self.request("/api/v1/dashboard", cookie=oidc_cookie)[0])
        status, _, body = self.request("/api/v1/servers", "POST", {"name": "Production", "host": "127.0.0.1", "web_port": 1}, self.admin_cookie)
        self.assertEqual(201, status)
        server_id = json.loads(body)["id"]
        self.assertEqual(403, self.request("/api/v1/servers", "POST", {"name": "Unauthorized", "host": "bad.example"}, oidc_cookie)[0])
        self.assertEqual(403, self.request(f"/api/v1/servers/{server_id}", "PUT", {"name": "Tampered"}, oidc_cookie)[0])
        self.assertEqual(502, self.request(f"/api/v1/servers/{server_id}/discover", "POST", {}, oidc_cookie)[0])
        status, _, body = self.request("/api/v1/servers", "POST", {"name": "Fixture", "host": "fixture.local", "adapter": "fixture"}, self.admin_cookie)
        self.assertEqual(201, status)
        fixture_id = json.loads(body)["id"]
        self.assertEqual(200, self.request(f"/api/v1/servers/{fixture_id}/discover", "POST", {}, self.admin_cookie)[0])
        camera = next(camera for camera in json.loads(self.request("/api/v1/cameras", cookie=oidc_cookie)[2]) if camera["server_id"] == fixture_id)
        status, _, body = self.request(f"/api/v1/cameras/{camera['id']}/live-check", "POST", {}, oidc_cookie)
        self.assertEqual(202, status)
        job_id = json.loads(body)["id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            outcome = json.loads(self.request(f"/api/v1/live-checks/{job_id}", cookie=oidc_cookie)[2])
            if outcome["status"] in ("succeeded", "failed", "cancelled"):
                break
            time.sleep(.05)
        self.assertEqual("succeeded", outcome["status"])

    def test_administrator_group_maps_to_administrator(self):
        self.assertEqual(200, self.configure_oidc()[0])
        ProviderHandler.issued_claims = {"sub": "admin-person", "preferred_username": "camera-admin@example.test", "groups": ["camera-admins"]}
        _, headers, _ = self.request("/api/v1/auth/oidc/login")
        from urllib.parse import urlparse, parse_qs
        args = parse_qs(urlparse(headers["Location"]).query)
        self.provider.expected_nonce = args["nonce"][0]
        self.provider.expected_challenge = args["code_challenge"][0]
        callback = args["redirect_uri"][0] + "?code=controlled-code&state=" + args["state"][0]
        status, headers, body = self.request(urlparse(callback).path + "?" + urlparse(callback).query, cookie=self.cookie(headers, "chm_oidc_state"))
        self.assertEqual(302, status, body.decode())
        oidc_cookie = self.cookie(headers, "chm_session")
        status, _, body = self.request("/api/v1/auth/me", cookie=oidc_cookie)
        self.assertEqual(200, status)
        self.assertEqual("administrator", json.loads(body)["role"])
        self.assertEqual(200, self.request("/api/v1/admin/auth/oidc", cookie=oidc_cookie)[0])
        ProviderHandler.issued_claims = {"sub": "person-1", "preferred_username": "operator@example.test", "groups": ["camera-ops"]}

    def test_unmatched_provider_group_is_denied_and_local_admin_remains_available(self):
        self.assertEqual(200, self.configure_oidc()[0])
        ProviderHandler.issued_claims = {"sub": "outside", "preferred_username": "outsider", "groups": ["other"]}
        status, headers, _ = self.request("/api/v1/auth/oidc/login")
        from urllib.parse import urlparse, parse_qs
        args = parse_qs(urlparse(headers["Location"]).query)
        self.provider.expected_nonce = args["nonce"][0]
        self.provider.expected_challenge = args["code_challenge"][0]
        cb = args["redirect_uri"][0] + "?code=controlled-code&state=" + args["state"][0]
        status, _, _ = self.request(urlparse(cb).path + "?" + urlparse(cb).query, cookie=self.cookie(headers, "chm_oidc_state"))
        self.assertEqual(403, status)
        status, headers, _ = self.request("/api/v1/auth/login", "POST", {"username": "siteadmin", "password": "A-secure-password-2026"})
        self.assertEqual(200, status)
        ProviderHandler.issued_claims = {"sub": "person-1", "preferred_username": "operator@example.test", "groups": ["camera-ops"]}

    def test_expired_or_badly_signed_id_token_is_rejected(self):
        self.assertEqual(200, self.configure_oidc()[0])
        from urllib.parse import urlparse, parse_qs
        for flag in ("token_expired", "invalid_signature"):
            setattr(ProviderHandler, flag, True)
            _, headers, _ = self.request("/api/v1/auth/oidc/login")
            args = parse_qs(urlparse(headers["Location"]).query)
            self.provider.expected_nonce = args["nonce"][0]
            self.provider.expected_challenge = args["code_challenge"][0]
            callback = args["redirect_uri"][0] + "?code=controlled-code&state=" + args["state"][0]
            status, _, _ = self.request(urlparse(callback).path + "?" + urlparse(callback).query, cookie=self.cookie(headers, "chm_oidc_state"))
            self.assertEqual(401, status)
            setattr(ProviderHandler, flag, False)

    def test_callback_rejects_missing_or_mismatched_state(self):
        self.assertEqual(200, self.configure_oidc()[0])
        status, headers, _ = self.request("/api/v1/auth/oidc/login")
        self.assertEqual(302, status)
        self.assertEqual(400, self.request("/api/v1/auth/oidc/callback?code=controlled-code&state=wrong")[0])
        from urllib.parse import urlparse, parse_qs
        args = parse_qs(urlparse(headers["Location"]).query)
        callback = args["redirect_uri"][0] + "?code=controlled-code&state=" + args["state"][0]
        self.assertEqual(400, self.request(urlparse(callback).path + "?" + urlparse(callback).query)[0])

    @unittest.skipUnless(__import__("importlib").util.find_spec("playwright"), "Install Playwright and Chromium for browser acceptance")
    def test_browser_exposes_admin_mapping_and_sso_sign_in(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(self.base, wait_until="networkidle")
            page.get_by_label("Username").fill("siteadmin")
            page.get_by_label("Password").fill("A-secure-password-2026")
            page.get_by_role("button", name="Sign in").click()
            page.get_by_role("button", name="Single sign-on").click()
            form = page.locator("#oidc-form")
            form.locator('[name="enabled"]').check()
            form.locator('[name="issuer"]').fill(self.issuer)
            form.locator('[name="client_id"]').fill("camera-monitor")
            form.locator('[name="client_secret"]').fill("provider-secret")
            form.locator('[name="administrator_values"]').fill("camera-admins")
            form.locator('[name="operator_values"]').fill("camera-ops")
            page.get_by_role("button", name="Save single sign-on").click()
            page.get_by_role("button", name="Sign out").click()
            page.get_by_role("link", name="Sign in with single sign-on").click()
            page.get_by_text("operator@example.test · operator").wait_for()
            self.assertFalse(page.get_by_role("button", name="Single sign-on").count())
            browser.close()


if __name__ == "__main__":
    unittest.main()
