"""Public API acceptance tests for exclusions and maintenance suppression."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReceiverHandler(BaseHTTPRequestHandler):
    events = []
    def do_POST(self):
        type(self).events.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")))))
        self.send_response(204); self.end_headers()
    def log_message(self, *_):
        pass


class MaintenanceAcceptance(unittest.TestCase):
    port_counter = 19270

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock_file = Path(self.temp.name) / "clock"
        self.clock_file.write_text(str(time.time()))
        ReceiverHandler.events = []
        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), ReceiverHandler)
        threading.Thread(target=self.receiver.serve_forever, daemon=True).start()
        type(self).port_counter += 1
        self.port = type(self).port_counter
        self.env = os.environ.copy()
        self.env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port),
                         "CHM_ENABLE_FIXTURE": "true", "CHM_SCHEDULER_ENABLED": "false",
                         "CHM_DISCOVERY_INTERVAL_SECONDS": "3600", "CHM_TEST_CLOCK_FILE": str(self.clock_file)})
        self.start_app()
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username":"admin","password":"password-123456"})
        self.cookie = headers.get("Set-Cookie").split(";",1)[0]
        _, _, server = self.request("/api/v1/servers", "POST", {"name":"fixture","host":"fixture.local","adapter":"fixture","fixture_profile":"recording_invalid_media"}, self.cookie)
        self.server_id = json.loads(server)["id"]
        self.request(f"/api/v1/servers/{self.server_id}/discover", "POST", {}, self.cookie)
        self.camera = json.loads(self.request("/api/v1/cameras", cookie=self.cookie)[2])[0]

    def start_app(self):
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=self.env, cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(60):
            try:
                self.request("/api/v1/setup/status")
                return
            except Exception:
                time.sleep(.1)
        raise RuntimeError("application did not start")

    def tearDown(self):
        self.proc.terminate(); self.proc.wait(timeout=5)
        self.receiver.shutdown(); self.receiver.server_close()
        self.temp.cleanup()

    def request(self, path, method="GET", body=None, cookie=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type":"application/json", **({"Cookie":cookie} if cookie else {}), **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def wait_for(self, check):
        for _ in range(60):
            result = check()
            if result:
                return result
            time.sleep(.1)
        self.fail("expected API state did not arrive")

    def run_recording_check(self):
        status, _, body = self.request(f"/api/v1/cameras/{self.camera['id']}/recording-check", "POST", {}, self.cookie)
        self.assertEqual(202, status, body)
        return self.wait_for(lambda: (lambda job: job if job["status"] == "completed" else None)(json.loads(self.request(f"/api/v1/recording-checks/{json.loads(body)['id']}", cookie=self.cookie)[2])))

    def api_now(self):
        return float(self.clock_file.read_text())

    def iso(self, epoch):
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat()

    def add_incident_receiver(self):
        status, _, body = self.request("/api/v1/webhooks", "POST", {
            "name":"maintenance tests","url":f"http://127.0.0.1:{self.receiver.server_port}/events",
            "events":["incident.opened","incident.updated","incident.resolved"]}, self.cookie)
        self.assertEqual(201,status,body)

    def test_exclusion_is_visible_persistent_and_does_not_hide_check_evidence(self):
        self.add_incident_receiver()
        camera_id = self.camera["id"]
        status, _, body = self.request(f"/api/v1/cameras/{camera_id}/exclusion", "PUT", {"excluded":True,"reason":"Camera disconnected for renovation"}, self.cookie)
        self.assertEqual(200, status, body)
        self.assertTrue(json.loads(body)["excluded"])
        job = self.run_recording_check()
        self.assertEqual("failure", job["result"]["health"])
        incidents = json.loads(self.request("/api/v1/incidents", cookie=self.cookie)[2])
        self.assertEqual(1, len(incidents)); self.assertTrue(incidents[0]["suppressed"])
        time.sleep(.15)
        self.assertEqual([], ReceiverHandler.events)
        camera = json.loads(self.request("/api/v1/cameras", cookie=self.cookie)[2])[0]
        self.assertEqual("decode_failed", camera["recording_status"]["reason"])
        self.assertEqual("Camera disconnected for renovation", camera["exclusion"]["reason"])
        self.proc.terminate(); self.proc.wait(timeout=5); self.start_app()
        _, headers, _ = self.request("/api/v1/auth/login", "POST", {"username":"admin","password":"password-123456"})
        self.cookie = headers.get("Set-Cookie").split(";",1)[0]
        camera = json.loads(self.request("/api/v1/cameras", cookie=self.cookie)[2])[0]
        self.assertTrue(camera["exclusion"]["excluded"])
        status, _, body = self.request(f"/api/v1/cameras/{camera_id}/exclusion", "PUT", {"excluded":False}, self.cookie)
        self.assertEqual(200, status, body)
        incidents = json.loads(self.request("/api/v1/incidents", cookie=self.cookie)[2])
        self.assertEqual(1, len(incidents))
        self.assertFalse(incidents[0]["suppressed"])
        self.wait_for(lambda: bool(ReceiverHandler.events))
        self.assertEqual(["incident.opened"], [event["type"] for event in ReceiverHandler.events])

    def test_maintenance_suppresses_failure_and_recovery_then_end_rechecks_latest_state(self):
        now = self.api_now()
        request = {"entity_type":"camera","entity_id":self.camera["id"],"reason":"Camera replacement","starts_at":self.iso(now-5),"ends_at":self.iso(now+3600)}
        status, _, body = self.request("/api/v1/maintenance", "POST", request, self.cookie)
        self.assertEqual(201, status, body)
        window = json.loads(body)
        self.assertEqual("active", window["state"])
        # Repeating the exact request is idempotent; a different overlapping one conflicts.
        self.assertEqual(200, self.request("/api/v1/maintenance", "POST", request, self.cookie)[0])
        overlap = {**request,"starts_at":self.iso(now),"ends_at":self.iso(now+1800)}
        self.assertEqual(409, self.request("/api/v1/maintenance", "POST", overlap, self.cookie)[0])
        self.run_recording_check()
        incidents = json.loads(self.request("/api/v1/incidents", cookie=self.cookie)[2])
        self.assertEqual(1, len(incidents)); self.assertTrue(incidents[0]["suppressed"])
        # A healthy result during maintenance resolves silently and is kept as evidence.
        self.request(f"/api/v1/servers/{self.server_id}", "PUT", {"fixture_profile":"recording_success"}, self.cookie)
        self.run_recording_check()
        history = json.loads(self.request("/api/v1/incidents?status=all", cookie=self.cookie)[2])
        self.assertEqual("resolved", next(i for i in history if i["id"] == incidents[0]["id"])["status"])
        self.assertEqual([], json.loads(self.request("/api/v1/incidents", cookie=self.cookie)[2]))
        ended_status, _, ended_body = self.request(f"/api/v1/maintenance/{window['id']}", "DELETE", cookie=self.cookie)
        self.assertEqual(200, ended_status, ended_body)
        self.assertEqual("ended", json.loads(self.request("/api/v1/maintenance", cookie=self.cookie)[2])[0]["state"])

    def test_expiry_server_scope_role_checks_and_validation(self):
        self.add_incident_receiver()
        now = self.api_now()
        # Leave a small margin so ISO timestamp microsecond rounding cannot make
        # this immediate window appear to start just after the frozen test clock.
        bad = {"entity_type":"server","entity_id":self.server_id,"reason":"repair","starts_at":self.iso(now-5),"ends_at":self.iso(now+10)}
        self.assertEqual(400, self.request("/api/v1/maintenance", "POST", {**bad,"ends_at":self.iso(now-1)}, self.cookie)[0])
        _, _, token_body = self.request("/api/v1/admin/api-tokens", "POST", {"name":"operator","role":"operator","scopes":["health:read","maintenance:read"]}, self.cookie)
        operator = json.loads(token_body)["token"]
        self.assertEqual(403, self.request("/api/v1/maintenance", "POST", bad, headers={"Authorization":f"Bearer {operator}"})[0])
        self.assertEqual(200, self.request("/api/v1/maintenance", cookie=None, headers={"Authorization":f"Bearer {operator}"})[0])
        _, _, body = self.request("/api/v1/maintenance", "POST", bad, self.cookie)
        self.assertEqual(200, self.request("/api/v1/maintenance", "POST", bad, self.cookie)[0])
        window = json.loads(body)
        self.proc.terminate(); self.proc.wait(timeout=5); self.start_app()
        _, headers, _ = self.request("/api/v1/auth/login","POST",{"username":"admin","password":"password-123456"})
        self.cookie=headers.get("Set-Cookie").split(";",1)[0]
        persisted=next(item for item in json.loads(self.request("/api/v1/maintenance",cookie=self.cookie)[2]) if item["id"]==window["id"])
        self.assertEqual("active",persisted["state"])
        self.run_recording_check()
        suppressed = json.loads(self.request("/api/v1/incidents", cookie=self.cookie)[2])
        self.assertTrue(suppressed)
        self.assertTrue(all(item["suppressed"] for item in suppressed), suppressed)
        self.clock_file.write_text(str(now+11))
        windows = json.loads(self.request("/api/v1/maintenance", cookie=self.cookie)[2])
        self.assertEqual("ended", next(w for w in windows if w["id"]==window["id"])["state"])
        incidents = json.loads(self.request("/api/v1/incidents", cookie=self.cookie)[2])
        self.assertEqual(1, len(incidents))
        self.wait_for(lambda: bool(ReceiverHandler.events))
        self.assertEqual(["incident.opened"], [event["type"] for event in ReceiverHandler.events])

    def test_recovery_during_maintenance_resolves_without_sending_recovery_event(self):
        self.add_incident_receiver()
        self.run_recording_check()
        self.wait_for(lambda: bool(ReceiverHandler.events))
        self.assertEqual(["incident.opened"], [event["type"] for event in ReceiverHandler.events])
        now=self.api_now()
        status,_,body=self.request("/api/v1/maintenance","POST",{
            "entity_type":"camera","entity_id":self.camera["id"],"reason":"Repair in progress",
            "starts_at":self.iso(now-5),"ends_at":self.iso(now+3600)},self.cookie)
        self.assertEqual(201,status,body)
        self.request(f"/api/v1/servers/{self.server_id}","PUT",{"fixture_profile":"recording_success"},self.cookie)
        self.run_recording_check()
        history=json.loads(self.request("/api/v1/incidents?status=all",cookie=self.cookie)[2])
        self.assertEqual("resolved",history[0]["status"])
        time.sleep(.15)
        self.assertEqual(["incident.opened"],[event["type"] for event in ReceiverHandler.events])

    def test_openapi_documents_maintenance_contract(self):
        contract = json.loads(self.request("/openapi.json")[2])
        self.assertIn("/maintenance", contract["paths"])
        self.assertIn("/maintenance/{window_id}", contract["paths"])
        self.assertIn("/cameras/{camera_id}/exclusion", contract["paths"])


if __name__ == "__main__":
    unittest.main()
