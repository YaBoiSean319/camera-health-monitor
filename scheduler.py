"""Persistent, staggered schedule bookkeeping for camera checks.

The scheduler stores only the next due time, never a queue of missed runs. A restart
therefore resumes at the next future slot rather than replaying work from downtime.
"""

import sqlite3
import threading
import time


class MonitoringSchedule:
    def __init__(self, database_path, clock=time.time):
        self.database_path = str(database_path)
        self.clock = clock
        self._lock = threading.RLock()
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS monitoring_schedule (
                camera_id TEXT NOT NULL, check_type TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL, next_due_at REAL NOT NULL,
                last_started_at REAL, last_completed_at REAL,
                PRIMARY KEY(camera_id, check_type))""")

    def _connect(self):
        db = sqlite3.connect(self.database_path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _intervals(camera):
        settings = camera.get("settings", {})
        return {"live": max(60, int(settings.get("live_interval_minutes", 5)) * 60),
                "recording": max(60, int(settings.get("recording_interval_minutes", 60)) * 60)}

    def synchronize(self, cameras, now=None, reset_missed=False):
        """Ensure every present camera has one schedule per check type.

        Existing future times are preserved. `reset_missed=True` is for process startup:
        it moves overdue slots to a future interval, deliberately discarding backlog.
        """
        now = self.clock() if now is None else float(now)
        desired = {}
        for camera in cameras:
            for check_type, interval in self._intervals(camera).items():
                desired[(camera["id"], check_type)] = interval
        offsets = {}
        for check_type in ("live", "recording"):
            ids = sorted(key[0] for key in desired if key[1] == check_type)
            for index, camera_id in enumerate(ids):
                interval = desired[(camera_id, check_type)]
                slot = index * interval // max(1, len(ids))
                if check_type == "recording":
                    slot = min(interval - 1, slot + interval // 2)
                offsets[(camera_id, check_type)] = slot
        with self._lock, self._connect() as db:
            existing = {(row["camera_id"], row["check_type"]): row for row in
                        db.execute("SELECT * FROM monitoring_schedule").fetchall()}
            for key, interval in desired.items():
                row = existing.get(key)
                if row is None:
                    # Do not run the entire fleet immediately after setup. Use a
                    # deterministic slot in the first interval, at least one second out.
                    due = now + max(1, offsets[key])
                    db.execute("INSERT INTO monitoring_schedule(camera_id,check_type,interval_seconds,next_due_at) VALUES(?,?,?,?)",
                               (key[0], key[1], interval, due))
                else:
                    due = row["next_due_at"]
                    if row["interval_seconds"] != interval:
                        due = now + max(1, offsets[key])
                    elif reset_missed and due <= now:
                        due = now + interval
                    db.execute("UPDATE monitoring_schedule SET interval_seconds=?,next_due_at=? WHERE camera_id=? AND check_type=?",
                               (interval, due, key[0], key[1]))
            for key in existing.keys() - desired.keys():
                db.execute("DELETE FROM monitoring_schedule WHERE camera_id=? AND check_type=?", key)

    def claim_due(self, now=None, limit=100):
        """Claim due checks once, advancing their next time before returning them."""
        now = self.clock() if now is None else float(now)
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM monitoring_schedule WHERE next_due_at<=? ORDER BY next_due_at,camera_id,check_type LIMIT ?",
                              (now, limit)).fetchall()
            for row in rows:
                db.execute("UPDATE monitoring_schedule SET next_due_at=?,last_started_at=? WHERE camera_id=? AND check_type=? AND next_due_at<=?",
                           (now + row["interval_seconds"], now, row["camera_id"], row["check_type"], now))
            return [dict(row) for row in rows]

    def complete(self, camera_id, check_type, completed_at=None):
        with self._lock, self._connect() as db:
            db.execute("UPDATE monitoring_schedule SET last_completed_at=? WHERE camera_id=? AND check_type=?",
                       (self.clock() if completed_at is None else float(completed_at), camera_id, check_type))

    def snapshot(self):
        with self._lock, self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM monitoring_schedule ORDER BY camera_id,check_type").fetchall()]
