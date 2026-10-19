"""Public API acceptance tests for durable, signed webhook delivery."""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class Receiver(BaseHTTPRequestHandler):
    received = []
    fail = False

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).received.append((dict(self.headers), body))
        self.send_response(503 if type(self).fail else 204)
        self.end_headers()

    def log_message(self, *_):
        pass


class WebhookAcceptance(unittest.TestCase):
    port_counter = 19110

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        Receiver.received = []
        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        Receiver.fail = False
        threading.Thread(target=self.receiver.serve_forever, daemon=True).start()
        type(self).port_counter += 1
        self.port = type(self).port_counter
        env = os.environ.copy()
        env.update({"CHM_DATA_DIR": self.temp.name, "CHM_HOST": "127.0.0.1", "CHM_PORT": str(self.port),
                    "CHM_ENABLE_FIXTURE": "true", "CHM_DISCOVERY_INTERVAL_SECONDS": "3600",
                    "CHM_SCHEDULER_ENABLED": "false"})
        self.env=env
        self.proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env, cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status")
                break
            except Exception:
                time.sleep(.1)
        _, headers, _ = self.request("/api/v1/setup/admin", "POST", {"username":"admin", "password":"password-123456"})
        self.cookie = headers.get("Set-Cookie").split(";",1)[0]

    def tearDown(self):
        self.proc.terminate(); self.proc.wait(timeout=5)
        self.receiver.shutdown(); self.receiver.server_close()
        self.temp.cleanup()

    def request(self, path, method="GET", body=None, cookie=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type":"application/json", **({"Cookie":cookie} if cookie else {})})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_admin_can_create_test_sign_and_operator_can_only_read_sanitized_history(self):
        secret = "a-webhook-signing-secret-long-enough"
        endpoint = f"http://127.0.0.1:{self.receiver.server_port}/receiver"
        status, _, body = self.request("/api/v1/webhooks", "POST", {
            "name":"automation", "url":endpoint, "events":["incident.opened"],
            "signing_secret":secret, "enabled":True,
        }, self.cookie)
        self.assertEqual(201, status, body)
        receiver = json.loads(body)
        self.assertNotIn(secret, body.decode())
        status, _, test_body = self.request(f"/api/v1/webhooks/{receiver['id']}/test", "POST", {}, self.cookie)
        self.assertEqual(200, status, test_body)
        event = json.loads(Receiver.received[-1][1])
        headers = {key.lower():value for key,value in Receiver.received[-1][0].items()}
        self.assertEqual("test", event["type"])
        self.assertEqual("1", headers["x-chm-event-version"])
        signed = headers["x-chm-timestamp"].encode() + b"." + Receiver.received[-1][1]
        self.assertEqual("sha256=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest(), headers["x-chm-signature"])
        status, _, deliveries = self.request(f"/api/v1/webhooks/{receiver['id']}/deliveries", cookie=self.cookie)
        self.assertEqual(200, status)
        self.assertEqual("delivered", json.loads(deliveries)[0]["state"])

    def test_failed_delivery_retries_after_restart_with_same_event_id(self):
        endpoint=f"http://127.0.0.1:{self.receiver.server_port}/retry"
        status,_,body=self.request("/api/v1/webhooks","POST",{"name":"retry","url":endpoint,"events":["incident.opened"]},self.cookie)
        self.assertEqual(201,status);receiver=json.loads(body)
        Receiver.fail=True
        _,_,result=self.request(f"/api/v1/webhooks/{receiver['id']}/test","POST",{},self.cookie)
        first=json.loads(result);event_id=first["event_id"]
        self.assertEqual("pending",first["state"])
        self.assertEqual(1,first["attempt_count"])
        self.proc.terminate();self.proc.wait(timeout=5)
        self.proc=subprocess.Popen([sys.executable,str(ROOT/"app.py")],env=self.env,cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                self.request("/api/v1/setup/status");break
            except Exception:time.sleep(.1)
        _,headers,_=self.request("/api/v1/auth/login","POST",{"username":"admin","password":"password-123456"})
        self.cookie=headers.get("Set-Cookie").split(";",1)[0]
        Receiver.fail=False
        deadline=time.time()+8
        while time.time()<deadline:
            rows=json.loads(self.request(f"/api/v1/webhooks/{receiver['id']}/deliveries",cookie=self.cookie)[2])
            if rows and rows[0]["state"]=="delivered":break
            time.sleep(.15)
        self.assertEqual("delivered",rows[0]["state"])
        self.assertEqual(event_id,rows[0]["event_id"])
        self.assertGreaterEqual(rows[0]["attempt_count"],2)

    def test_bad_destination_and_non_admin_mutation_are_rejected(self):
        self.assertEqual(400, self.request("/api/v1/webhooks", "POST", {"name":"bad","url":"file:///etc/passwd","events":["incident.opened"]}, self.cookie)[0])
        _, _, token_body = self.request("/api/v1/admin/api-tokens", "POST", {"name":"operator","role":"operator","scopes":["health:read","webhooks:read"]}, self.cookie)
        token=json.loads(token_body)["token"]
        read_req=urllib.request.Request(self.base+"/api/v1/webhooks",headers={"Authorization":"Bearer "+token})
        with urllib.request.urlopen(read_req) as response: self.assertEqual([],json.loads(response.read()))
        read_req=urllib.request.Request(self.base+"/api/v1/webhooks/00000000-0000-0000-0000-000000000000/deliveries",headers={"Authorization":"Bearer "+token})
        try: urllib.request.urlopen(read_req)
        except urllib.error.HTTPError as e: self.assertEqual(404,e.code)
        req=urllib.request.Request(self.base+"/api/v1/webhooks",data=b'{"name":"x"}',method="POST",headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
        try:
            urllib.request.urlopen(req)
            code=200
        except urllib.error.HTTPError as e: code=e.code
        self.assertEqual(403,code)

    def test_liveness_readiness_and_admin_heartbeat_settings(self):
        self.assertEqual(200, self.request("/healthz")[0])
        self.assertEqual({"status": "ready"}, json.loads(self.request("/readyz")[2]))
        self.assertEqual(401, self.request("/api/v1/monitoring")[0])
        status, _, result = self.request("/api/v1/webhooks", "POST", {
            "name": "external monitor", "url": f"http://127.0.0.1:{self.receiver.server_port}/heartbeat",
            "events": ["monitoring.heartbeat"], "enabled": True,
        }, self.cookie)
        self.assertEqual(201, status, result)
        receiver_id = json.loads(result)["id"]
        status, _, result = self.request("/api/v1/monitoring/heartbeat", "PUT", {
            "enabled": True, "receiver_id": receiver_id, "interval_seconds": 60,
        }, self.cookie)
        self.assertEqual(200, status, result)
        public = json.loads(result)
        self.assertEqual(receiver_id, public["receiver_id"])
        self.assertNotIn("last_sent_epoch", public)
        self.assertEqual(200, self.request("/api/v1/monitoring/heartbeat", cookie=self.cookie)[0])
        deadline = time.time() + 5
        while time.time() < deadline and not any(json.loads(body).get("type") == "monitoring.heartbeat" for _, body in Receiver.received):
            time.sleep(.1)
        self.assertTrue(any(json.loads(body).get("type") == "monitoring.heartbeat" for _, body in Receiver.received))

    def test_incident_filter_delivers_one_open_and_one_recovery_with_stable_schema(self):
        endpoint=f"http://127.0.0.1:{self.receiver.server_port}/incidents"
        status,_,body=self.request("/api/v1/webhooks","POST",{"name":"incidents","url":endpoint,"events":["incident.opened","incident.resolved"]},self.cookie)
        self.assertEqual(201,status);receiver=json.loads(body)
        _,_,server_body=self.request("/api/v1/servers","POST",{"name":"Fixture","host":"fixture.local","adapter":"fixture","fixture_profile":"recording_invalid_media"},self.cookie)
        server=json.loads(server_body);self.request(f"/api/v1/servers/{server['id']}/discover","POST",{},self.cookie)
        camera=json.loads(self.request("/api/v1/cameras",cookie=self.cookie)[2])[0]
        def check():
            status,_,job_body=self.request(f"/api/v1/cameras/{camera['id']}/recording-check","POST",{},self.cookie)
            self.assertEqual(202,status);job=json.loads(job_body)
            deadline=time.time()+5
            while time.time()<deadline:
                current=json.loads(self.request(f"/api/v1/recording-checks/{job['id']}",cookie=self.cookie)[2])
                if current["status"]=="completed":return
                time.sleep(.05)
            self.fail("recording check did not complete")
        check()
        deadline=time.time()+4
        while time.time()<deadline:
            candidate=json.loads(self.request(f"/api/v1/webhooks/{receiver['id']}/deliveries",cookie=self.cookie)[2])
            if candidate and candidate[0]["state"]=="delivered":break
            time.sleep(.1)
        rows=json.loads(self.request(f"/api/v1/webhooks/{receiver['id']}/deliveries",cookie=self.cookie)[2])
        self.assertEqual(["incident.opened"],[row["event_type"] for row in rows])
        opened=json.loads(Receiver.received[-1][1])
        self.assertEqual(1,opened["version"]);self.assertEqual("incident.opened",opened["type"])
        self.assertEqual(camera["id"],opened["data"]["camera_id"])
        self.assertEqual("decode_failed",opened["data"]["reason"])
        check()
        time.sleep(.3)
        rows=json.loads(self.request(f"/api/v1/webhooks/{receiver['id']}/deliveries",cookie=self.cookie)[2])
        self.assertEqual(1,len([r for r in rows if r["event_type"]=="incident.opened"]))
        self.request(f"/api/v1/servers/{server['id']}","PUT",{"fixture_profile":"recording_success"},self.cookie)
        check()
        deadline=time.time()+4
        while time.time()<deadline:
            rows=json.loads(self.request(f"/api/v1/webhooks/{receiver['id']}/deliveries",cookie=self.cookie)[2])
            if any(row["event_type"]=="incident.resolved" and row["state"]=="delivered" for row in rows):break
            time.sleep(.1)
        self.assertEqual(1,len([r for r in rows if r["event_type"]=="incident.resolved"]))
        self.assertNotIn("password",json.dumps(rows).lower())


if __name__ == "__main__":
    unittest.main()
