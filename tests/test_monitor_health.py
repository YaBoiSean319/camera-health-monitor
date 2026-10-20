"""Deterministic tests for persisted monitor progress and external heartbeats."""

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app


class MonitorHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_paths = (app.DATA_DIR, app.DB_PATH)
        app.DATA_DIR = Path(self.temp.name)
        app.DB_PATH = app.DATA_DIR / "test.sqlite3"
        app.initialize()
        self.old_enabled = os.environ.get("CHM_SCHEDULER_ENABLED")
        self.old_tick = os.environ.get("CHM_SCHEDULER_TICK_SECONDS")
        os.environ["CHM_SCHEDULER_ENABLED"] = "true"
        os.environ["CHM_SCHEDULER_TICK_SECONDS"] = "1"

    def tearDown(self):
        app.DATA_DIR, app.DB_PATH = self.old_paths
        for key, value in (("CHM_SCHEDULER_ENABLED", self.old_enabled), ("CHM_SCHEDULER_TICK_SECONDS", self.old_tick)):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()

    def test_stall_fault_is_persistent_sanitized_and_emitted_once_until_recovery(self):
        app.monitor_progress(now_epoch=1000)
        self.assertEqual("healthy", app.monitor_health(now_epoch=1010)["state"])
        result = app.monitor_health(now_epoch=1040)
        self.assertEqual("fault", result["state"])
        self.assertEqual("scheduler_stalled", result["last_error_code"])
        app.monitor_health(now_epoch=1050)
        with app.connect_db() as db:
            faults = db.execute("SELECT event_type,payload_json FROM event_outbox WHERE event_type='monitoring.fault'").fetchall()
            self.assertEqual(1, len(faults))
            payload = json.loads(faults[0]["payload_json"])
            self.assertEqual(1, payload["version"])
            self.assertEqual("monitoring.fault", payload["type"])
        app.monitor_progress(now_epoch=1060)
        self.assertEqual("healthy", app.monitor_health(now_epoch=1061)["state"])
        with app.connect_db() as db:
            events = [row[0] for row in db.execute("SELECT event_type FROM event_outbox ORDER BY created_at,event_type")]
            self.assertEqual(1, events.count("monitoring.fault"))
            self.assertEqual(1, events.count("monitoring.recovered"))

    def test_arbitrary_exception_text_never_enters_monitor_diagnostics(self):
        app.monitor_fault("database password was top-secret")
        with app.connect_db() as db:
            row = db.execute("SELECT * FROM monitor_diagnostics WHERE id=1").fetchone()
        self.assertEqual("scheduler_cycle_failed", row["last_error_code"])
        self.assertNotIn("top-secret", json.dumps(dict(row)))

    def test_heartbeat_is_interval_gated_and_only_queued_to_selected_receiver(self):
        with app.connect_db() as db:
            for receiver_id in ("selected", "other"):
                db.execute("INSERT INTO webhook_receivers(id,name,url,events_json,enabled,created_at,updated_at) VALUES(?,?,?,?,1,'now','now')",
                           (receiver_id, receiver_id, "http://localhost:9090/", json.dumps(["monitoring.heartbeat"])))
        app.save_setting("monitoring_heartbeat", {"enabled": True, "receiver_id": "selected", "interval_seconds": 60, "last_sent_epoch": None})
        self.assertTrue(app.heartbeat_tick(now_epoch=2000))
        self.assertFalse(app.heartbeat_tick(now_epoch=2059))
        self.assertTrue(app.heartbeat_tick(now_epoch=2060))
        with app.connect_db() as db:
            deliveries = db.execute("SELECT receiver_id,event_type FROM webhook_deliveries ORDER BY id").fetchall()
            self.assertEqual([("selected", "monitoring.heartbeat"), ("selected", "monitoring.heartbeat")], [tuple(row) for row in deliveries])
            event = json.loads(db.execute("SELECT payload_json FROM event_outbox WHERE event_type='monitoring.heartbeat' ORDER BY created_at LIMIT 1").fetchone()[0])
            self.assertEqual(1, event["version"])

    def test_camera_auth_failure_opens_one_server_incident_not_a_camera_incident(self):
        with app.connect_db() as db:
            app.update_incident(db, "camera", "camera-1", "server-1", "live", "unknown", "permission_denied", "2026-01-01T00:00:00Z")
            self.assertEqual(1, db.execute("SELECT COUNT(*) FROM monitoring_incidents WHERE entity_type='server' AND reason='authentication_failed'").fetchone()[0])
            self.assertEqual(0, db.execute("SELECT COUNT(*) FROM monitoring_incidents WHERE entity_type='camera'").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
