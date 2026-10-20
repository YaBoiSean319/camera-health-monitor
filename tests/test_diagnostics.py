"""Safety and retention guarantees for opt-in operational traces."""

import json
import os
import tempfile
import unittest
from pathlib import Path

import app


class DiagnosticEventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_paths = (app.DATA_DIR, app.DB_PATH)
        self.old_env = {key: os.environ.get(key) for key in (
            "CHM_DIAGNOSTICS_ENABLED", "CHM_DIAGNOSTIC_MAX_EVENTS", "CHM_DIAGNOSTIC_RETENTION_DAYS")}
        app.DATA_DIR = Path(self.temp.name)
        app.DB_PATH = app.DATA_DIR / "diagnostics.sqlite3"
        app.initialize()

    def tearDown(self):
        app.DATA_DIR, app.DB_PATH = self.old_paths
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()

    def test_tracing_is_off_by_default_and_redacts_unsafe_metadata(self):
        os.environ.pop("CHM_DIAGNOSTICS_ENABLED", None)
        app.diagnostic_event("recording_check", "search", "failed", error_category="HTTP 404 /secret?session=abc")
        with app.connect_db() as db:
            self.assertEqual(0, db.execute("SELECT COUNT(*) FROM diagnostic_events").fetchone()[0])

        os.environ["CHM_DIAGNOSTICS_ENABLED"] = "true"
        app.diagnostic_event("recording_check", "search", "failed", correlation_id="job-1",
                             http_status=404, error_category="http_error; private-url?session=abc",
                             duration_ms=42)
        with app.connect_db() as db:
            row = dict(db.execute("SELECT * FROM diagnostic_events").fetchone())
        serialized = json.dumps(row)
        self.assertEqual("job-1", row["correlation_id"])
        self.assertEqual(404, row["http_status"])
        self.assertNotIn("private-url", serialized)
        self.assertNotIn("session", serialized)

    def test_event_count_is_bounded(self):
        os.environ["CHM_DIAGNOSTICS_ENABLED"] = "true"
        os.environ["CHM_DIAGNOSTIC_MAX_EVENTS"] = "100"
        for index in range(120):
            app.diagnostic_event("recording_check", "search", "succeeded", correlation_id=f"job-{index}")
        with app.connect_db() as db:
            self.assertLessEqual(db.execute("SELECT COUNT(*) FROM diagnostic_events").fetchone()[0], 100)
            self.assertEqual("job-119", db.execute("SELECT correlation_id FROM diagnostic_events ORDER BY id DESC LIMIT 1").fetchone()[0])

    def test_expired_events_are_removed_when_recording_new_event(self):
        os.environ["CHM_DIAGNOSTICS_ENABLED"] = "true"
        os.environ["CHM_DIAGNOSTIC_RETENTION_DAYS"] = "1"
        with app.connect_db() as db:
            db.execute("INSERT INTO diagnostic_events(correlation_id,action,stage,outcome,created_at) VALUES(?,?,?,?,?)",
                       ("old", "recording_check", "search", "failed", "2000-01-01T00:00:00+00:00"))
        app.diagnostic_event("recording_check", "search", "succeeded", correlation_id="new")
        with app.connect_db() as db:
            ids = [row[0] for row in db.execute("SELECT correlation_id FROM diagnostic_events")]
        self.assertEqual(["new"], ids)

    def test_detailed_job_fields_require_administrator_role_and_scope(self):
        operator_session = {"role": "operator", "auth_type": "session"}
        admin_without_scope = {"role": "administrator", "auth_type": "api_token", "scopes": ["health:read"]}
        admin_with_scope = {"role": "administrator", "auth_type": "api_token", "scopes": ["diagnostics:read"]}
        self.assertFalse(app.can_read_diagnostics(operator_session))
        self.assertFalse(app.can_read_diagnostics(admin_without_scope))
        self.assertTrue(app.can_read_diagnostics(admin_with_scope))
        job = {"id": "job", "camera_id": "cam", "server_id": "srv", "status": "completed",
               "created_at": None, "started_at": None, "completed_at": None, "lookback_hours": 24,
               "result": {}, "error": None, "diagnostics": {"stage": "search", "http_status": 404}}
        self.assertNotIn("diagnostics", app.recording_check_public(job))
        self.assertEqual(404, app.recording_check_public(job, include_diagnostics=True)["diagnostics"]["http_status"])


if __name__ == "__main__":
    unittest.main()
