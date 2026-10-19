import tempfile
import unittest
from pathlib import Path

from scheduler import MonitoringSchedule


class MonitoringScheduleTests(unittest.TestCase):
    def test_intervals_are_staggered_and_due_checks_advance_without_backlog(self):
        with tempfile.TemporaryDirectory() as directory:
            schedule = MonitoringSchedule(Path(directory) / "schedule.sqlite3", clock=lambda: 1000)
            cameras = [
                {"id": "cam-a", "settings": {"live_interval_minutes": 5, "recording_interval_minutes": 60}},
                {"id": "cam-b", "settings": {"live_interval_minutes": 5, "recording_interval_minutes": 60}},
            ]
            schedule.synchronize(cameras)
            status = schedule.snapshot()
            live_due = [row["next_due_at"] for row in status if row["check_type"] == "live"]
            self.assertEqual(2, len(live_due))
            self.assertNotEqual(*live_due)
            self.assertEqual([], schedule.claim_due(1000))
            due = schedule.claim_due(max(live_due))
            self.assertEqual(2, len(due))
            later = schedule.claim_due(max(live_due) + 24 * 3600)
            self.assertEqual(4, len(later))
            next_due = schedule.snapshot()
            self.assertTrue(all(row["next_due_at"] > max(live_due) + 24 * 3600 - 300 for row in next_due))

    def test_restarts_skip_missed_periods_and_keep_only_one_next_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule.sqlite3"
            schedule = MonitoringSchedule(path, clock=lambda: 1000)
            schedule.synchronize([{"id": "cam-a", "settings": {"live_interval_minutes": 5, "recording_interval_minutes": 60}}])
            before = schedule.snapshot()[0]["next_due_at"]
            restarted = MonitoringSchedule(path, clock=lambda: before + 12 * 3600)
            restarted.synchronize([{"id": "cam-a", "settings": {"live_interval_minutes": 5, "recording_interval_minutes": 60}}], reset_missed=True)
            rows = restarted.snapshot()
            self.assertEqual(2, len(rows))
            self.assertTrue(all(row["next_due_at"] > before + 12 * 3600 for row in rows))
            self.assertEqual([], restarted.claim_due(before + 12 * 3600))


if __name__ == "__main__":
    unittest.main()
