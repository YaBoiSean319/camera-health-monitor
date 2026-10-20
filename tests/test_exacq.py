import json
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import exacq


class ExacqFixtureServer(ThreadingHTTPServer):
    allow_reuse_address = True


class ExacqHandler(BaseHTTPRequestHandler):
    jpeg = b""
    bad_password = False
    requests_seen = []
    playback_counter = 0
    freeze_playback = False
    no_recordings = False

    def log_message(self, *_args):
        pass

    def send_json(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        self.requests_seen.append(("POST", urlsplit(self.path).path, form))
        if urlsplit(self.path).path == "/login.web":
            if self.bad_password or form.get("p") != ["synthetic-password"]:
                return self.send_json({"success": False, "errorText": "Login failed"})
            return self.send_json({"success": True, "sessionId": "synthetic-session", "version": "21.12.8.0"})
        return self.send_json({"success": False}, 404)

    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query.replace(";", "&"))
        self.requests_seen.append(("GET", parsed.path, query))
        if parsed.path == "/config.web":
            return self.send_json({"success": True, "Cameras": [
                {"id": 101, "name": "Lobby", "parentId": 5, "disabled": 0, "state": 0,
                 "frameRate": 15, "resolution": {"width": 1280, "height": 720}, "streamFormats": ["native"]},
                {"id": 102, "name": "Disabled camera", "parentId": 5, "disabled": 1, "state": 1},
            ]})
        if parsed.path == "/server.web/devices":
            return self.send_json({"success": True, "devices": [
                {"id": 5, "enabled": True, "host": "192.0.2.3", "type": "SyntheticCam", "model": "Mock-1",
                 "firmware": "1.0", "isConnected": True, "cameras": [{"cameraId": 101}]},
                {"id": 6, "enabled": False, "isConnected": False, "cameras": [{"cameraId": 102}]},
                {"id": 7, "enabled": False, "isConnected": False, "cameras": []},
            ]})
        if parsed.path == "/status.web":
            return self.send_json({"success": True, "statuses": [{"serverStatus": 2, "motion": [], "loss": []}]})
        if parsed.path == "/video.web":
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(self.jpeg)))
            self.end_headers()
            return self.wfile.write(self.jpeg)
        if parsed.path == "/search.web":
            if self.no_recordings:
                return self.send_json({"search_id": "synthetic-search", "frames": 0, "videoInfo": []})
            now = datetime.now(timezone.utc)
            start = (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self.send_json({"search_id": "synthetic-search", "frames": 12,
                                   "videoInfo": [{"deviceId": "101", "clips": [{"startTime": start, "endTime": end}]}]})
        if parsed.path == "/search.web/status":
            return self.send_json({"success": True, "status": {"status": 2, "frames": {"total": 12, "retrieved": 12}}})
        if parsed.path in ("/playspeed.web/0", "/playspeed.web/1"):
            data = b"0"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if parsed.path == "/step.web/0":
            return self.send_json({"frame": "0"})
        if parsed.path == "/timestamp.web":
            if not self.freeze_playback:
                type(self).playback_counter += 1
            return self.send_json({"time": datetime.fromtimestamp(1_600_000_000 + self.playback_counter, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        self.send_error(404)


class ExacqClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.jpg"
            subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-i",
                            "tests/fixtures/live-sample.mp4", "-frames:v", "1", "-f", "image2", str(path)],
                           check=True, timeout=10)
            ExacqHandler.jpeg = path.read_bytes()

    def setUp(self):
        ExacqHandler.bad_password = False
        ExacqHandler.requests_seen = []
        ExacqHandler.playback_counter = 0
        ExacqHandler.freeze_playback = False
        ExacqHandler.no_recordings = False
        self.server = ExacqFixtureServer(("127.0.0.1", 0), ExacqHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.config = {"host": "127.0.0.1", "web_scheme": "http", "web_port": self.server.server_port}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def client(self):
        return exacq.ExacqClient(self.config, "monitor", "synthetic-password")

    def test_authentication_and_discovery_map_camera_device_metadata_safely(self):
        result = self.client().discover()
        self.assertEqual("21.12.8.0", result["version"])
        self.assertEqual(["101", "102"], [camera["remote_id"] for camera in result["cameras"]])
        lobby = result["cameras"][0]
        self.assertEqual("SyntheticCam", lobby["metadata"]["manufacturer"])
        self.assertEqual("connected", lobby["connection_state"])
        self.assertFalse(lobby["disabled"])
        self.assertEqual("disabled", result["cameras"][1]["connection_state"])
        self.assertTrue(result["cameras"][1]["disabled"])
        self.assertNotIn("synthetic-session", json.dumps(result))
        self.assertNotIn("synthetic-password", json.dumps(result))
        sent = next(form for method, path, form in ExacqHandler.requests_seen if method == "POST" and path == "/login.web")
        self.assertEqual(["synthetic-password"], sent["p"])

    def test_live_sample_decodes_multiple_jpegs_and_qualifies_capture_freshness(self):
        result = self.client().check_live("101")
        self.assertTrue(result["decoded"])
        self.assertEqual(3, result["frames_decoded"])
        self.assertFalse(result["freshness_verified"])
        self.assertIsNone(result["sample_timestamp"])

    def test_live_feed_frame_uses_authenticated_camera_stream(self):
        client = self.client()
        frame = client.live_frame("101", "browser-stream")
        self.assertTrue(frame.startswith(b"\xff\xd8"))
        method, path, query = next(item for item in ExacqHandler.requests_seen if item[0] == "GET" and item[1] == "/video.web")
        self.assertEqual("101", query["camera"][0])
        self.assertEqual("browser-stream", query["stream"][0])
        self.assertEqual("synthetic-session", query["s"][0])
        self.assertEqual("1280", query["w"][0])
        self.assertEqual("720", query["h"][0])

    def test_recording_search_selects_newest_clip_and_decodes_playback_frame(self):
        result = self.client().check_recording("101", 24)
        self.assertEqual("healthy", result["health"])
        self.assertTrue(result["decoded"])
        self.assertTrue(result["playback_verified"])
        self.assertGreaterEqual(result["evidence"]["playback_frames_decoded"], 2)
        self.assertEqual(12, result["evidence"]["frame_count"])
        paths = [path for method, path, _ in ExacqHandler.requests_seen if method == "GET"]
        self.assertIn("/search.web", paths)
        self.assertIn("/step.web/0", paths)
        self.assertIn("/timestamp.web", paths)
        self.assertIn("/playspeed.web/1", paths)

    def test_recorded_frame_without_advancing_timestamp_does_not_verify_playback(self):
        ExacqHandler.freeze_playback = True
        with self.assertRaises(exacq.ExacqError) as raised:
            self.client().check_recording("101", 24)
        self.assertEqual("playback_not_advancing", raised.exception.code)
        self.assertTrue(raised.exception.search_verified)

    def test_empty_motion_window_verifies_search_without_claiming_playback(self):
        ExacqHandler.no_recordings = True
        result = self.client().check_recording("101", 24)
        self.assertEqual("no_recent_recording", result["reason"])
        self.assertTrue(result["search_verified"])
        self.assertFalse(result["playback_verified"])

    def test_invalid_credentials_are_reported_without_echoing_server_details(self):
        ExacqHandler.bad_password = True
        with self.assertRaises(exacq.ExacqError) as raised:
            self.client().discover()
        self.assertEqual("permission_denied", raised.exception.code)
        self.assertNotIn("synthetic-password", raised.exception.safe_message)
        self.assertNotIn("Login failed", raised.exception.safe_message)


if __name__ == "__main__":
    unittest.main()
