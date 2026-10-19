"""Camera Health Monitor's initial, dependency-free deployment slice."""

import base64
import hashlib
import hmac
import getpass
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
import urllib.parse
import urllib.request
import urllib.error
import socket
import ipaddress
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import oidc
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, make_server
import branding
from scheduler import MonitoringSchedule

DATA_DIR = Path(os.environ.get("CHM_DATA_DIR", "./data"))
DB_PATH = DATA_DIR / "camera-health-monitor.sqlite3"
COOKIE_SECURE = os.environ.get("CHM_COOKIE_SECURE", "false").lower() == "true"
SESSIONS = {}
SESSION_LOCK = threading.RLock()
LOGIN_ATTEMPTS = {}
LOGIN_LOCK = threading.Lock()
SESSION_TTL = 8 * 60 * 60
PBKDF2_ROUNDS = 310_000
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 10
OIDC_TRANSACTIONS = {}
OIDC_TRANSACTION_LOCK = threading.Lock()
API_SCOPES = {
    "operator": {"health:read", "history:read", "incidents:acknowledge", "checks:run", "maintenance:read", "webhooks:read"},
    "administrator": {"health:read", "history:read", "incidents:acknowledge", "checks:run", "maintenance:read", "maintenance:write", "servers:read", "servers:write", "cameras:read", "cameras:write", "webhooks:read", "webhooks:write", "branding:write", "auth:manage", "tokens:manage"},
}
LIVE_CHECKS = {}
LIVE_CHECKS_BY_CAMERA = {}
LIVE_CHECK_LOCK = threading.RLock()
LIVE_CHECK_LIMIT = max(1, min(int(os.environ.get("CHM_LIVE_CHECK_CONCURRENCY", "4")), 8))
LIVE_CHECK_TIMEOUT = max(2, min(int(os.environ.get("CHM_LIVE_CHECK_TIMEOUT_SECONDS", "15")), 60))
LIVE_CHECK_EXECUTOR = ThreadPoolExecutor(max_workers=LIVE_CHECK_LIMIT, thread_name_prefix="live-check")
LIVE_CHECK_SLOTS = threading.BoundedSemaphore(LIVE_CHECK_LIMIT)
RECORDING_CHECKS = {}
RECORDING_CHECKS_BY_CAMERA = {}
RECORDING_CHECK_LOCK = threading.RLock()
RECORDING_CHECK_EXECUTOR = ThreadPoolExecutor(max_workers=LIVE_CHECK_LIMIT, thread_name_prefix="recording-check")
RECORDING_CHECK_SLOTS = threading.BoundedSemaphore(LIVE_CHECK_LIMIT)
CAMERA_WORK_LOCK = threading.RLock()
CAMERA_WORK_BY_CAMERA = {}
SCHEDULER_WAKE = threading.Event()


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect_db() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY CHECK(id = 1), username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        db.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value_json TEXT NOT NULL)""")
        db.execute("INSERT OR IGNORE INTO settings(key, value_json) VALUES ('branding', ?)",
                   (json.dumps(branding.DEFAULTS),))
        db.execute("INSERT OR IGNORE INTO settings(key, value_json) VALUES ('oidc', ?)", (json.dumps({"enabled": False, "issuer": "", "client_id": "", "client_secret": "", "role_claim": "groups", "administrator_values": [], "operator_values": []}),))
        db.execute("INSERT OR IGNORE INTO settings(key,value_json) VALUES('webhook_reminders',?)",(json.dumps({"enabled":False,"interval_hours":24}),))
        db.execute("INSERT OR IGNORE INTO settings(key,value_json) VALUES('monitoring_heartbeat',?)",(json.dumps({"enabled":False,"receiver_id":None,"interval_seconds":300,"last_sent_epoch":None}),))
        db.execute("""CREATE TABLE IF NOT EXISTS monitor_diagnostics (
            id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL DEFAULT 'starting',
            last_progress_epoch REAL, last_progress_at TEXT, last_error_code TEXT,
            updated_at TEXT NOT NULL)""")
        db.execute("INSERT OR IGNORE INTO monitor_diagnostics(id,state,updated_at) VALUES(1,'starting',?)", (utc_now(),))
        db.execute("""CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL CHECK(role IN ('operator','administrator')), scopes_json TEXT NOT NULL,
            created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at REAL, revoked_at TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT NOT NULL, actor_name TEXT NOT NULL,
            actor_type TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL,
            resource_id TEXT, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS servers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER,
            username TEXT NOT NULL DEFAULT '', password_ciphertext TEXT NOT NULL DEFAULT '',
            adapter TEXT NOT NULL, fixture_profile TEXT NOT NULL DEFAULT 'success', enabled INTEGER NOT NULL DEFAULT 1,
            defaults_json TEXT NOT NULL DEFAULT '{}', capabilities_json TEXT NOT NULL,
            discovery_status TEXT NOT NULL DEFAULT 'untested', discovery_detail TEXT NOT NULL DEFAULT '',
            last_discovery_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        db.execute("""CREATE TABLE IF NOT EXISTS cameras (
            id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            remote_id TEXT NOT NULL, name TEXT NOT NULL, disappeared INTEGER NOT NULL DEFAULT 0,
            settings_json TEXT NOT NULL DEFAULT '{}', overrides_json TEXT NOT NULL DEFAULT '{}', history_json TEXT NOT NULL DEFAULT '[]',
            discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(server_id, remote_id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS recording_check_state (
            camera_id TEXT PRIMARY KEY REFERENCES cameras(id) ON DELETE CASCADE,
            checked_at TEXT NOT NULL, result_json TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS live_check_state (
            camera_id TEXT PRIMARY KEY REFERENCES cameras(id) ON DELETE CASCADE,
            checked_at TEXT NOT NULL, result_json TEXT NOT NULL,
            last_success_at TEXT, confirmation_due_at REAL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS monitoring_check_state (
            camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
            check_type TEXT NOT NULL, current_state TEXT NOT NULL DEFAULT 'idle',
            current_job_id TEXT, last_attempt_at TEXT, last_success_at TEXT,
            PRIMARY KEY(camera_id,check_type))""")
        db.execute("UPDATE monitoring_check_state SET current_state='interrupted',current_job_id=NULL WHERE current_state='running'")
        db.execute("""CREATE TABLE IF NOT EXISTS monitoring_incidents (
            id TEXT PRIMARY KEY, entity_type TEXT NOT NULL CHECK(entity_type IN ('camera','server')),
            entity_id TEXT NOT NULL, server_id TEXT NOT NULL, check_type TEXT NOT NULL,
            reason TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','resolved')),
            opened_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT,
            acknowledged_at TEXT, acknowledged_by TEXT, evidence_json TEXT NOT NULL DEFAULT '{}', suppressed INTEGER NOT NULL DEFAULT 0)""")
        incident_columns = {row["name"] for row in db.execute("PRAGMA table_info(monitoring_incidents)").fetchall()}
        if "suppressed" not in incident_columns:
            db.execute("ALTER TABLE monitoring_incidents ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0")
        db.execute("CREATE INDEX IF NOT EXISTS incidents_recent ON monitoring_incidents(status, updated_at DESC)")
        db.execute("""CREATE TABLE IF NOT EXISTS incident_transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES monitoring_incidents(id) ON DELETE CASCADE,
            event TEXT NOT NULL, from_state TEXT, to_state TEXT NOT NULL, reason TEXT, actor TEXT, created_at TEXT NOT NULL)""")
        # Durable event seam for the webhook delivery worker (implemented separately).
        db.execute("""CREATE TABLE IF NOT EXISTS event_outbox (
            event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL, delivery_state TEXT NOT NULL DEFAULT 'pending')""")
        db.execute("""CREATE TABLE IF NOT EXISTS webhook_receivers (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, events_json TEXT NOT NULL,
            secret_ciphertext TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, receiver_id TEXT NOT NULL REFERENCES webhook_receivers(id) ON DELETE CASCADE,
            event_id TEXT NOT NULL, event_type TEXT NOT NULL, state TEXT NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            next_attempt_at REAL NOT NULL DEFAULT 0, http_status INTEGER, error_code TEXT,
            UNIQUE(receiver_id,event_id))""")
        db.execute("CREATE INDEX IF NOT EXISTS webhook_deliveries_due ON webhook_deliveries(state,next_attempt_at)")
        db.execute("""CREATE TABLE IF NOT EXISTS camera_exclusions (
            camera_id TEXT PRIMARY KEY REFERENCES cameras(id) ON DELETE CASCADE,
            reason TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS maintenance_windows (
            id TEXT PRIMARY KEY, entity_type TEXT NOT NULL CHECK(entity_type IN ('camera','server')),
            entity_id TEXT NOT NULL, reason TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL,
            ended_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            UNIQUE(entity_type,entity_id,starts_at,ends_at))""")
        db.execute("CREATE INDEX IF NOT EXISTS maintenance_windows_scope ON maintenance_windows(entity_type,entity_id,starts_at,ends_at)")
        db.execute("UPDATE webhook_deliveries SET state='pending' WHERE state='sending'")
        db.execute("""DELETE FROM monitoring_incidents WHERE status='resolved' AND resolved_at < ?
                   AND id NOT IN (SELECT incident_id FROM incident_transitions WHERE created_at >= ?)""",
                   (retention_cutoff(), retention_cutoff()))


def retention_cutoff():
    return datetime.fromtimestamp(time.time() - 90 * 86400, timezone.utc).isoformat()


def incident_public(row, db=None):
    item = dict(row)
    item["evidence"] = json.loads(item.pop("evidence_json"))
    item["suppressed"] = bool(item.get("suppressed", 0))
    if db is None:
        with connect_db() as connection:
            transitions = connection.execute("SELECT event,from_state,to_state,reason,actor,created_at FROM incident_transitions WHERE incident_id=? ORDER BY id", (item["id"],)).fetchall()
    else:
        transitions = db.execute("SELECT event,from_state,to_state,reason,actor,created_at FROM incident_transitions WHERE incident_id=? ORDER BY id", (item["id"],)).fetchall()
    item["transitions"] = [dict(value) for value in transitions]
    return item


def maintenance_public(row, now=None):
    epoch = monitoring_now() if now is None else now
    start = parse_utc_timestamp(row["starts_at"])
    end = parse_utc_timestamp(row["ends_at"])
    active = bool(not row["ended_at"] and start and end and start.timestamp() <= epoch < end.timestamp())
    state = "active" if active else "scheduled" if not row["ended_at"] and start and start.timestamp() > epoch else "ended"
    return {"id":row["id"],"entity_type":row["entity_type"],"entity_id":row["entity_id"],"reason":row["reason"],
            "starts_at":row["starts_at"],"ends_at":row["ends_at"],"ended_at":row["ended_at"],"created_at":row["created_at"],
            "updated_at":row["updated_at"],"state":state}


def emit_incident_event(db, event_type, incident, at):
    if incident.get("suppressed"):
        return
    event_id = str(uuid.uuid4())
    identity={"server_name":None,"camera_id":incident.get("entity_id") if incident.get("entity_type")=="camera" else None,"camera_name":None,"camera_remote_id":None}
    server=db.execute("SELECT name FROM servers WHERE id=?",(incident["server_id"],)).fetchone()
    if server:identity["server_name"]=server["name"]
    if identity["camera_id"]:
        camera=db.execute("SELECT name,remote_id FROM cameras WHERE id=?",(identity["camera_id"],)).fetchone()
        if camera:identity.update(camera_name=camera["name"],camera_remote_id=camera["remote_id"])
    payload = {"id": event_id, "version": 1, "type": event_type, "created_at": at,
               "data": {"incident_id": incident["id"], "entity_type": incident["entity_type"],
                        "entity_id": incident["entity_id"], "server_id": incident["server_id"],
                        **identity,
                        "check_type": incident["check_type"], "reason": incident["reason"],
                        "severity": incident["severity"], "status": incident["status"],
                        "opened_at": incident.get("opened_at", at), "resolved_at": incident.get("resolved_at")}}
    group_active = incident["entity_type"] == "camera" and db.execute(
        "SELECT 1 FROM monitoring_incidents WHERE entity_type='server' AND entity_id=? AND status='open' LIMIT 1",
        (incident["server_id"],)).fetchone()
    if group_active:
        db.execute("UPDATE monitoring_incidents SET suppressed=1 WHERE id=?", (incident["id"],))
        return
    db.execute("INSERT OR IGNORE INTO event_outbox(event_id,event_type,payload_json,created_at) VALUES(?,?,?,?)",
               (event_id, event_type, json.dumps(payload), at))
    queue_event_deliveries(db,event_id,event_type,at)


def enqueue_event(db,event_type,data,at=None):
    event_id=str(uuid.uuid4());created=at or utc_now()
    payload={"id":event_id,"version":1,"type":event_type,"created_at":created,"data":data}
    db.execute("INSERT OR IGNORE INTO event_outbox(event_id,event_type,payload_json,created_at) VALUES(?,?,?,?)",(event_id,event_type,json.dumps(payload),created))
    queue_event_deliveries(db,event_id,event_type,created)
    return event_id


def _monitor_transition(db, state, error_code=None, now_epoch=None):
    """Persist one monitor fault/recovery edge; repeated observations do not flood events."""
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    now = datetime.fromtimestamp(now_epoch, timezone.utc).isoformat()
    row = db.execute("SELECT state FROM monitor_diagnostics WHERE id=1").fetchone()
    previous = row["state"] if row else "starting"
    db.execute("INSERT INTO monitor_diagnostics(id,state,last_progress_epoch,last_progress_at,last_error_code,updated_at) VALUES(1,?,?,?,?,?) "
               "ON CONFLICT(id) DO UPDATE SET state=excluded.state,last_progress_epoch=COALESCE(excluded.last_progress_epoch,monitor_diagnostics.last_progress_epoch),last_progress_at=COALESCE(excluded.last_progress_at,monitor_diagnostics.last_progress_at),last_error_code=excluded.last_error_code,updated_at=excluded.updated_at",
               (state, now_epoch if state == "healthy" else None, now if state == "healthy" else None, error_code, now))
    event_type = "monitoring.fault" if state == "fault" and previous != "fault" else "monitoring.recovered" if state == "healthy" and previous == "fault" else None
    if event_type:
        enqueue_event(db, event_type, {"component": "scheduled_monitor", "state": state,
                                       "reason": error_code or ("progress_resumed" if state == "healthy" else "progress_stalled"),
                                       "last_progress_at": now if state == "healthy" else None}, now)


def monitor_progress(now_epoch=None):
    with connect_db() as db:
        _monitor_transition(db, "healthy", now_epoch=now_epoch)


def monitor_fault(error_code="scheduler_cycle_failed", now_epoch=None):
    # Error details are deliberately reduced to a stable code; exception text may contain secrets.
    safe_code = error_code if error_code in ("scheduler_cycle_failed", "scheduler_stalled", "scheduler_database_error") else "scheduler_cycle_failed"
    with connect_db() as db:
        _monitor_transition(db, "fault", safe_code, now_epoch)


def monitor_health(now_epoch=None):
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    tick_seconds = max(0.25, min(float(os.environ.get("CHM_SCHEDULER_TICK_SECONDS", "1")), 30))
    enabled = os.environ.get("CHM_SCHEDULER_ENABLED", "true").lower() != "false"
    with connect_db() as db:
        row = db.execute("SELECT * FROM monitor_diagnostics WHERE id=1").fetchone()
        if row is None:
            return {"state": "starting" if enabled else "disabled", "last_progress_at": None, "last_error_code": None, "progress_age_seconds": None}
        last = row["last_progress_epoch"]
        age = max(0, int(now_epoch - last)) if last is not None else None
        stalled_after = max(30, tick_seconds * 3)
        if not enabled:
            state = "disabled"
        elif last is not None and now_epoch - last > stalled_after:
            state = "fault"
            _monitor_transition(db, "fault", "scheduler_stalled", now_epoch)
            row = db.execute("SELECT * FROM monitor_diagnostics WHERE id=1").fetchone()
        else:
            state = row["state"]
        return {"state": state, "last_progress_at": row["last_progress_at"], "progress_age_seconds": age,
                "stalled_after_seconds": int(stalled_after), "last_error_code": row["last_error_code"],
                "scheduler_enabled": enabled, "liveness": "alive"}


def heartbeat_tick(now_epoch=None):
    """Queue an optional receiver heartbeat through the normal durable webhook pipeline."""
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    config = setting("monitoring_heartbeat")
    if not config.get("enabled") or not config.get("receiver_id"):
        return False
    interval = int(config.get("interval_seconds", 300))
    previous = config.get("last_sent_epoch")
    if previous is not None and now_epoch - float(previous) < interval:
        return False
    with connect_db() as db:
        receiver = db.execute("SELECT id,enabled,events_json FROM webhook_receivers WHERE id=?", (config["receiver_id"],)).fetchone()
        if not receiver or not receiver["enabled"] or "monitoring.heartbeat" not in json.loads(receiver["events_json"]):
            return False
        created = datetime.fromtimestamp(now_epoch, timezone.utc).isoformat()
        event_id = enqueue_event(db, "monitoring.heartbeat", {"component": "camera_health_monitor", "state": "alive", "progress_at": created}, created)
        db.execute("DELETE FROM webhook_deliveries WHERE event_id=? AND receiver_id!=?", (event_id, config["receiver_id"]))
        db.execute("UPDATE event_outbox SET delivery_state='discarded' WHERE event_id=? AND NOT EXISTS(SELECT 1 FROM webhook_deliveries WHERE event_id=?)", (event_id, event_id))
    config["last_sent_epoch"] = now_epoch
    save_setting("monitoring_heartbeat", config)
    return True


def queue_event_deliveries(db,event_id,event_type,created_at):
    receivers=db.execute("SELECT id,events_json FROM webhook_receivers WHERE enabled=1").fetchall()
    for receiver in receivers:
        if event_type in json.loads(receiver["events_json"]):
            db.execute("INSERT OR IGNORE INTO webhook_deliveries(receiver_id,event_id,event_type,state,created_at,updated_at) VALUES(?,?,?,'pending',?,?)",(receiver["id"],event_id,event_type,utc_now(),utc_now()))
    if not db.execute("SELECT 1 FROM webhook_deliveries WHERE event_id=? LIMIT 1",(event_id,)).fetchone():
        db.execute("UPDATE event_outbox SET delivery_state='discarded' WHERE event_id=?",(event_id,))


def update_incident(db, entity_type, entity_id, server_id, check_type, health, reason, checked_at, evidence=None, actor=None):
    """Persist incident transitions. Unknown is deliberately non-actionable."""
    if entity_type == "camera" and reason in ("server_unavailable", "server_outage", "server_timeout", "monitoring_stalled"):
        update_incident(db, "server", server_id, server_id, "server", "failure", reason, checked_at,
                        {"detail": "Recorder access failed; camera health is not inferred from this result."}, actor)
        return
    if entity_type == "camera" and health in ("healthy", "warning", "failure"):
        update_incident(db, "server", server_id, server_id, "server", "healthy", "server_recovered", checked_at, {}, actor)
    # Maintenance applies at evaluation/commit time, not at the rounded check timestamp.
    suppressed = incident_notifications_suppressed(db, entity_type, entity_id, server_id)
    active = db.execute("SELECT * FROM monitoring_incidents WHERE entity_type=? AND entity_id=? AND check_type=? AND status='open' ORDER BY opened_at DESC LIMIT 1",
                        (entity_type, entity_id, check_type)).fetchone()
    if health in ("warning", "failure"):
        severity = "warning" if health == "warning" else "monitoring" if reason == "monitoring_stalled" else "failure"
        reason = reason or ("no_recent_recording" if severity == "warning" else "check_failed")
        now = checked_at or utc_now()
        if active:
            previous = dict(active)
            if suppressed:
                db.execute("UPDATE monitoring_incidents SET suppressed=1,reason=?,severity=?,updated_at=?,evidence_json=? WHERE id=?",
                           (reason or previous["reason"], "warning" if health == "warning" else "failure", now, json.dumps(evidence or {}), previous["id"]))
                if previous["suppressed"] == 0:
                    db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                               (previous["id"], "suppressed", "open", "suppressed", "maintenance_or_exclusion", actor, now))
                return
            group_active = entity_type == "camera" and db.execute("SELECT 1 FROM monitoring_incidents WHERE entity_type='server' AND entity_id=? AND status='open' LIMIT 1", (server_id,)).fetchone()
            if previous["suppressed"] and not group_active:
                db.execute("UPDATE monitoring_incidents SET suppressed=0,reason=?,severity=?,updated_at=?,evidence_json=? WHERE id=?",
                           (reason, severity, now, json.dumps(evidence or {}), previous["id"]))
                db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                           (previous["id"], "reevaluated", "suppressed", "open", "maintenance_ended", actor, now))
                previous.update(reason=reason, severity=severity, suppressed=0, status="open")
                emit_incident_event(db, "incident.opened", previous, now)
            elif previous["reason"] != reason or previous["severity"] != severity:
                db.execute("UPDATE monitoring_incidents SET reason=?,severity=?,updated_at=?,evidence_json=? WHERE id=?",
                           (reason, severity, now, json.dumps(evidence or {}), previous["id"]))
                db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                           (previous["id"], "updated", previous["severity"], severity, reason, actor, now))
                updated = dict(previous, reason=reason, severity=severity, status="open")
                emit_incident_event(db, "incident.updated", updated, now)
        else:
            incident_id = str(uuid.uuid4())
            db.execute("INSERT INTO monitoring_incidents(id,entity_type,entity_id,server_id,check_type,reason,severity,status,opened_at,updated_at,evidence_json,suppressed) VALUES(?,?,?,?,?,?,?,'open',?,?,?,?)",
                       (incident_id, entity_type, entity_id, server_id, check_type, reason, severity, now, now, json.dumps(evidence or {}), int(suppressed)))
            db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                       (incident_id, "opened", None, "open", reason, actor, now))
            emit_incident_event(db, "incident.opened", {"id": incident_id, "entity_type": entity_type, "entity_id": entity_id, "server_id": server_id, "check_type": check_type, "reason": reason, "severity": severity, "status": "open", "suppressed": suppressed}, now)
    elif health == "healthy" and active:
        now = checked_at or utc_now()
        if suppressed and not active["suppressed"]:
            db.execute("UPDATE monitoring_incidents SET suppressed=1 WHERE id=?", (active["id"],))
            db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                       (active["id"], "suppressed", "open", "suppressed", "maintenance_or_exclusion", actor, now))
        db.execute("UPDATE monitoring_incidents SET status='resolved',updated_at=?,resolved_at=? WHERE id=?", (now, now, active["id"]))
        db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                   (active["id"], "resolved", "open", "resolved", "recovered", actor, now))
        resolved = dict(active, status="resolved")
        emit_incident_event(db, "incident.resolved", dict(resolved, suppressed=bool(active["suppressed"] or suppressed)), now)
        if entity_type == "server":
            db.execute("UPDATE monitoring_incidents SET suppressed=0 WHERE entity_type='camera' AND server_id=? AND status='open'", (entity_id,))


def prune_history(db):
    cutoff = retention_cutoff()
    db.execute("DELETE FROM monitoring_incidents WHERE status='resolved' AND resolved_at < ?", (cutoff,))
    db.execute("DELETE FROM event_outbox WHERE created_at < ? AND delivery_state IN ('delivered','discarded')", (cutoff,))


def parse_utc_timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def incident_notifications_suppressed(db, entity_type, entity_id, server_id, at=None):
    now_epoch = monitoring_now()
    at_dt = parse_utc_timestamp(at) if at else None
    if at_dt:
        now_epoch = at_dt.timestamp()
    now_text = datetime.fromtimestamp(now_epoch, timezone.utc).isoformat()
    if entity_type == "camera" and db.execute("SELECT 1 FROM camera_exclusions WHERE camera_id=?", (entity_id,)).fetchone():
        return True
    scopes = [(entity_type, entity_id)]
    if entity_type == "camera":
        scopes.append(("server", server_id))
    for scope_type, scope_id in scopes:
        if db.execute("SELECT 1 FROM maintenance_windows WHERE entity_type=? AND entity_id=? AND ended_at IS NULL AND starts_at<=? AND ends_at>? LIMIT 1",
                      (scope_type, scope_id, now_text, now_text)).fetchone():
            return True
    return False


def reevaluate_latest_health(db, entity_type, entity_id, at, actor="maintenance"):
    if entity_type == "server":
        camera_rows = db.execute("SELECT id FROM cameras WHERE server_id=?", (entity_id,)).fetchall()
        # The server outage is the authoritative state for server-scoped maintenance.
        server_incident = db.execute("SELECT * FROM monitoring_incidents WHERE entity_type='server' AND entity_id=? AND status='open' ORDER BY opened_at DESC LIMIT 1", (entity_id,)).fetchone()
        if server_incident:
            health = "failure" if server_incident["reason"] != "server_recovered" else "healthy"
            update_incident(db, "server", entity_id, entity_id, "server", health, server_incident["reason"], at,
                            json.loads(server_incident["evidence_json"]), actor)
        rows = camera_rows
    else:
        rows = [db.execute("SELECT id FROM cameras WHERE id=?", (entity_id,)).fetchone()]
    for row in rows:
        if not row:
            continue
        camera_id = row["id"]
        camera = db.execute("SELECT server_id FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not camera:
            continue
        states = db.execute("SELECT result_json,checked_at FROM recording_check_state WHERE camera_id=?", (camera_id,)).fetchone()
        if states:
            result = json.loads(states["result_json"])
            update_incident(db, "camera", camera_id, camera["server_id"], "recording", result.get("health", "unknown"), result.get("reason"), states["checked_at"], result.get("evidence"), actor)
        live = db.execute("SELECT result_json,checked_at FROM live_check_state WHERE camera_id=?", (camera_id,)).fetchone()
        if live:
            result = json.loads(live["result_json"])
            update_incident(db, "camera", camera_id, camera["server_id"], "live", result.get("health", "unknown"), result.get("reason"), live["checked_at"], result.get("evidence"), actor)


def suppress_open_incidents(db, entity_type, entity_id, at, actor):
    if entity_type == "camera":
        rows = db.execute("SELECT * FROM monitoring_incidents WHERE entity_type='camera' AND entity_id=? AND status='open' AND suppressed=0", (entity_id,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM monitoring_incidents WHERE status='open' AND suppressed=0 AND (entity_id=? AND entity_type='server' OR server_id=? AND entity_type='camera')", (entity_id,entity_id)).fetchall()
    for row in rows:
        db.execute("UPDATE monitoring_incidents SET suppressed=1,updated_at=? WHERE id=?", (at,row["id"]))
        db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                   (row["id"],"suppressed","open","suppressed","maintenance_or_exclusion",actor,at))


def expire_maintenance(db, now=None):
    epoch = monitoring_now() if now is None else now
    now_text = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    expired = db.execute("SELECT * FROM maintenance_windows WHERE ended_at IS NULL AND ends_at<=?", (now_text,)).fetchall()
    for window in expired:
        db.execute("UPDATE maintenance_windows SET ended_at=?,updated_at=? WHERE id=? AND ended_at IS NULL", (now_text, now_text, window["id"]))
        reevaluate_latest_health(db, window["entity_type"], window["entity_id"], now_text)
    return len(expired)


def credential_cipher():
    key_path = DATA_DIR / "credential-encryption.key"
    try:
        key = key_path.read_bytes()
    except FileNotFoundError:
        key = Fernet.generate_key()
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = key_path.read_bytes()
        else:
            with os.fdopen(fd, "wb") as key_file:
                key_file.write(key)
    return Fernet(key)


WEBHOOK_EVENTS = ("incident.opened", "incident.updated", "incident.resolved", "job.completed",
                  "monitoring.fault", "monitoring.recovered", "monitoring.heartbeat", "incident.reminder")


def safe_receiver_url(value):
    """Validate an explicitly configured HTTP(S) receiver; private LAN receivers are supported."""
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            return False
        addresses = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)}
        if not addresses:
            return False
        for address in addresses:
            ip = ipaddress.ip_address(address)
            blocked_metadata={ipaddress.ip_address("169.254.169.254"),ipaddress.ip_address("100.100.100.200"),ipaddress.ip_address("fd00:ec2::254")}
            if ip.is_link_local or ip in blocked_metadata:
                return False
        return True
    except (ValueError, OSError, socket.gaierror):
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_webhook(url, payload, secret):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    timestamp = str(int(time.time()))
    headers = {"Content-Type": "application/json", "User-Agent": "CameraHealthMonitor/1.0",
               "X-CHM-Event-Id": payload["id"], "X-CHM-Event-Type": payload["type"],
               "X-CHM-Event-Version": str(payload.get("version", 1)), "X-CHM-Timestamp": timestamp}
    if secret:
        digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        headers["X-CHM-Signature"] = "sha256=" + digest
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
    try:
        with opener.open(request, timeout=5) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    if not 200 <= status < 300:
        raise RuntimeError("receiver_rejected" if status < 500 else "receiver_unavailable")
    return status


def safe_delivery(row):
    return {key: row[key] for key in ("id", "receiver_id", "event_id", "event_type", "state", "attempt_count", "created_at", "updated_at", "http_status", "error_code")}


def webhook_public(row):
    return {"id":row["id"], "name":row["name"], "url":row["url"], "events":json.loads(row["events_json"]),
            "enabled":bool(row["enabled"]), "signing_secret_configured":bool(row["secret_ciphertext"]),
            "created_at":row["created_at"], "updated_at":row["updated_at"]}


def dispatch_webhook_delivery(delivery_id):
    with connect_db() as db:
        if db.execute("UPDATE webhook_deliveries SET state='sending' WHERE id=? AND state='pending'",(delivery_id,)).rowcount!=1:
            return
        row = db.execute("SELECT d.*,r.url,r.secret_ciphertext,r.enabled FROM webhook_deliveries d JOIN webhook_receivers r ON r.id=d.receiver_id WHERE d.id=?", (delivery_id,)).fetchone()
        if not row:
            return
        if not row["enabled"]:
            db.execute("UPDATE webhook_deliveries SET state='pending' WHERE id=?",(delivery_id,))
            return
        event = db.execute("SELECT payload_json FROM event_outbox WHERE event_id=?", (row["event_id"],)).fetchone()
        if event:
            payload = json.loads(event["payload_json"])
        else:
            payload = {"id": row["event_id"], "version": 1, "type": row["event_type"], "created_at": utc_now(),
                       "data": {"message": "Receiver test delivery"}}
        secret = credential_cipher().decrypt(row["secret_ciphertext"].encode()).decode() if row["secret_ciphertext"] else ""
        url = row["url"]
    try:
        if not safe_receiver_url(url):
            raise RuntimeError("destination_unavailable")
        status = send_webhook(url, payload, secret)
        with connect_db() as db:
            db.execute("UPDATE webhook_deliveries SET state='delivered',attempt_count=attempt_count+1,updated_at=?,next_attempt_at=0,http_status=?,error_code=NULL WHERE id=?", (utc_now(), status, delivery_id))
        delivery=db.execute("SELECT event_id FROM webhook_deliveries WHERE id=?",(delivery_id,)).fetchone()
        if delivery and db.execute("SELECT 1 FROM webhook_deliveries WHERE event_id=? AND state!='delivered' LIMIT 1",(delivery["event_id"],)).fetchone() is None:
            db.execute("UPDATE event_outbox SET delivery_state='delivered' WHERE event_id=?",(delivery["event_id"],))
    except Exception as error:
        code = str(error) if str(error) in ("destination_unavailable", "receiver_rejected", "receiver_unavailable") else "delivery_error"
        with connect_db() as db:
            row = db.execute("SELECT attempt_count FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
            if not row:
                return
            attempt = row["attempt_count"] + 1
            delay = min(3600, 2 ** min(attempt, 12))
            db.execute("UPDATE webhook_deliveries SET state='pending',attempt_count=?,updated_at=?,next_attempt_at=?,http_status=NULL,error_code=? WHERE id=?", (attempt, utc_now(), time.time()+delay, code, delivery_id))


def webhook_worker():
    while True:
        try:
            now = time.time()
            try:
                heartbeat_tick(now)
            except (sqlite3.Error, OSError, ValueError):
                # External heartbeat cannot stall normal webhook dispatch.
                pass
            with connect_db() as db:
                reminder_setting=db.execute("SELECT value_json FROM settings WHERE key='webhook_reminders'").fetchone()
                reminders=json.loads(reminder_setting[0]) if reminder_setting else {"enabled":False,"interval_hours":24}
                if reminders.get("enabled"):
                    active=db.execute("SELECT * FROM monitoring_incidents WHERE status='open' AND suppressed=0").fetchall()
                    all_reminders=db.execute("SELECT payload_json,created_at FROM event_outbox WHERE event_type='incident.reminder'").fetchall()
                    reminded={}
                    for reminder in all_reminders:
                        try:
                            incident_id=json.loads(reminder["payload_json"])["data"]["incident_id"]
                            reminded[incident_id]=max(reminded.get(incident_id,0),datetime.fromisoformat(reminder["created_at"].replace("Z","+00:00")).timestamp())
                        except (ValueError,KeyError,TypeError):pass
                    for incident in active:
                        opened=datetime.fromisoformat(incident["opened_at"].replace("Z","+00:00")).timestamp()
                        last=reminded.get(incident["id"],opened)
                        if now-last>=86400:
                            enqueue_event(db,"incident.reminder",{"incident_id":incident["id"],"entity_type":incident["entity_type"],"entity_id":incident["entity_id"],"server_id":incident["server_id"],"check_type":incident["check_type"],"reason":incident["reason"],"severity":incident["severity"],"status":"open","opened_at":incident["opened_at"]})
                due = db.execute("SELECT id FROM webhook_deliveries WHERE state='pending' AND next_attempt_at<=? ORDER BY id LIMIT 20", (now,)).fetchall()
            for delivery in due:
                dispatch_webhook_delivery(delivery["id"])
        except Exception:
            pass
        time.sleep(1)


def empty_capabilities():
    why = "Not tested against this configured server. Confirm the installed version, enabled Web Service/API, account permissions, and playback interfaces before implementation can verify this capability."
    return {key: {"status": "untested", "detail": why} for key in
            ("camera_discovery", "live_delivery", "recording_search", "recorded_playback")}


def default_camera_settings():
    return {"live_interval_minutes": 5, "recording_interval_minutes": 60, "recording_lookback_hours": 24}


def validate_camera_settings(value):
    if not isinstance(value, dict):
        return None
    settings = default_camera_settings()
    for key, minimum, maximum in (("live_interval_minutes", 1, 1440), ("recording_interval_minutes", 1, 1440), ("recording_lookback_hours", 1, 720)):
        candidate = value.get(key, settings[key])
        if type(candidate) is not int or not minimum <= candidate <= maximum:
            return None
        settings[key] = candidate
    return settings


def validate_camera_overrides(value):
    if not isinstance(value, dict) or not set(value).issubset({"live_interval_minutes", "recording_interval_minutes", "recording_lookback_hours"}):
        return None
    ranges = {"live_interval_minutes": (1, 1440), "recording_interval_minutes": (1, 1440), "recording_lookback_hours": (1, 720)}
    for key, candidate in value.items():
        minimum, maximum = ranges[key]
        if type(candidate) is not int or not minimum <= candidate <= maximum:
            return None
    return value


def server_public(row):
    item = dict(row)
    item["credentials_configured"] = bool(item.pop("password_ciphertext", ""))
    item["enabled"] = bool(item["enabled"])
    item["capabilities"] = json.loads(item.pop("capabilities_json"))
    item.pop("fixture_profile", None)
    item.pop("discovery_detail", None)
    item["defaults"] = json.loads(item.pop("defaults_json"))
    return item


def camera_public(row):
    item = dict(row)
    item["disappeared"] = bool(item["disappeared"])
    item["overrides"] = json.loads(item.pop("overrides_json"))
    item["settings"] = json.loads(item.pop("settings_json"))
    item["history"] = json.loads(item.pop("history_json"))
    item["live_status"] = {"health": "unknown", "state": "not_checked", "checked_at": None, "last_success_at": None}
    try:
        with connect_db() as db:
            live = db.execute("SELECT checked_at,result_json,last_success_at,confirmation_due_at FROM live_check_state WHERE camera_id=?", (item["id"],)).fetchone()
            monitor_rows = db.execute("SELECT check_type,current_state,current_job_id,last_attempt_at,last_success_at FROM monitoring_check_state WHERE camera_id=?", (item["id"],)).fetchall()
            exclusion = db.execute("SELECT reason,updated_at FROM camera_exclusions WHERE camera_id=?", (item["id"],)).fetchone()
            windows = db.execute("SELECT * FROM maintenance_windows WHERE ended_at IS NULL AND ((entity_type='camera' AND entity_id=?) OR (entity_type='server' AND entity_id=?)) ORDER BY starts_at", (item["id"],item["server_id"])).fetchall()
        item["exclusion"] = {"excluded":bool(exclusion),"reason":exclusion["reason"] if exclusion else None,"updated_at":exclusion["updated_at"] if exclusion else None}
        item["maintenance"] = [maintenance_public(window) for window in windows]
        if live:
            item["live_status"] = json.loads(live["result_json"])
            item["live_status"].update({"checked_at": live["checked_at"], "last_success_at": live["last_success_at"],
                                         "state": "pending_confirmation" if live["confirmation_due_at"] else "current"})
        item["monitoring"] = {entry["check_type"]: {"state": entry["current_state"], "job_id": entry["current_job_id"],
                                                       "last_attempt_at": entry["last_attempt_at"], "last_success_at": entry["last_success_at"]}
                              for entry in monitor_rows}
    except sqlite3.Error:
        item["monitoring"] = {}
    state = None
    try:
        with connect_db() as db:
            state = db.execute("SELECT checked_at,result_json FROM recording_check_state WHERE camera_id=?", (item["id"],)).fetchone()
    except sqlite3.Error:
        state = None
    item["recording_status"] = json.loads(state["result_json"]) if state else {"health": "unknown", "state": "not_checked", "checked_at": None, "last_success_at": None, "newest_recording_at": None}
    for check_type, status, interval_key in (("live", item["live_status"], "live_interval_minutes"),
                                             ("recording", item["recording_status"], "recording_interval_minutes")):
        status.setdefault("state", "not_checked")
        checked_at = status.get("checked_at")
        if checked_at:
            try:
                checked_epoch = datetime.fromisoformat(checked_at.replace("Z", "+00:00")).timestamp()
                if time.time() - checked_epoch > item["settings"].get(interval_key, 5 if check_type == "live" else 60) * 60:
                    status["current_health"] = status.get("health", "unknown")
                    status["health"] = "unknown"
                    status["state"] = "stale"
            except (ValueError, TypeError):
                status["state"] = "unknown"
    item["live_status"].setdefault("current_health", item["live_status"].get("health", "unknown"))
    item["recording_status"].setdefault("current_health", item["recording_status"].get("health", "unknown"))
    item["capabilities"] = {"live_delivery": {"status": "untested", "detail": "Live retrieval and video decoding are not implemented in this release."},
                            "recording_search": {"status": "untested", "detail": "Recording search and playback decoding are not implemented in this release."}}
    return item


def live_check_public(job):
    return {key: job[key] for key in ("id", "camera_id", "server_id", "status", "created_at", "started_at", "completed_at", "result", "error")}


def recording_check_public(job):
    return {key: job[key] for key in ("id", "camera_id", "server_id", "status", "created_at", "started_at", "completed_at", "lookback_hours", "result", "error")}


def mark_monitoring_job(camera_id, check_type, job_id):
    now = utc_now()
    with connect_db() as db:
        db.execute("INSERT INTO monitoring_check_state(camera_id,check_type,current_state,current_job_id,last_attempt_at) VALUES(?,?,'running',?,?) ON CONFLICT(camera_id,check_type) DO UPDATE SET current_state='running',current_job_id=excluded.current_job_id,last_attempt_at=excluded.last_attempt_at",
                   (camera_id, check_type, job_id, now))


def persist_scheduled_result(camera_id, check_type, job):
    completed_at = job.get("completed_at") or utc_now()
    with connect_db() as db:
        camera = db.execute("SELECT server_id FROM cameras WHERE id=?", (camera_id,)).fetchone()
        if not camera:
            return
        server_id = camera["server_id"]
        state = db.execute("SELECT last_success_at FROM monitoring_check_state WHERE camera_id=? AND check_type=?", (camera_id, check_type)).fetchone()
        last_success = state["last_success_at"] if state else None
        result = job.get("result")
        if check_type == "recording":
            health = (result or {}).get("health", "unknown")
            last_success = (result or {}).get("last_success_at") or last_success
            db.execute("INSERT INTO monitoring_check_state(camera_id,check_type,current_state,last_success_at) VALUES(?,?,?,?) ON CONFLICT(camera_id,check_type) DO UPDATE SET current_state=excluded.current_state,current_job_id=NULL,last_success_at=COALESCE(excluded.last_success_at,monitoring_check_state.last_success_at)",
                       (camera_id, check_type, health, last_success))
            update_incident(db, "camera", camera_id, server_id, check_type, health,
                            (result or {}).get("reason"), (result or {}).get("checked_at") or completed_at,
                            (result or {}).get("evidence"))
        else:
            is_success = job.get("status") == "succeeded"
            prior = db.execute("SELECT result_json,last_success_at FROM live_check_state WHERE camera_id=?", (camera_id,)).fetchone()
            last_success = completed_at if is_success else (prior["last_success_at"] if prior else last_success)
            confirmation_retry = bool(job.get("confirmation_retry"))
            pending_due = None if is_success or confirmation_retry or not job.get("error") else monitoring_now() + 30
            error_code = ((job.get("error") or {}).get("code") or "check_failed")
            confirmed_decode_failure = bool(confirmation_retry and not is_success and error_code == "decode_failed")
            health = "healthy" if is_success else ("failure" if confirmed_decode_failure else "unknown")
            live_result = {"health": health, "reason": None if is_success else ((job.get("error") or {}).get("code") or "check_failed"),
                           "checked_at": completed_at, "last_success_at": last_success,
                           "detail": "Fixture decode succeeded; this does not verify Exacq." if is_success else "Live check failed; awaiting a 30-second confirmation attempt." if pending_due else "The live check failed twice."}
            db.execute("INSERT INTO live_check_state(camera_id,checked_at,result_json,last_success_at,confirmation_due_at) VALUES(?,?,?,?,?) ON CONFLICT(camera_id) DO UPDATE SET checked_at=excluded.checked_at,result_json=excluded.result_json,last_success_at=excluded.last_success_at,confirmation_due_at=excluded.confirmation_due_at",
                       (camera_id, completed_at, json.dumps(live_result), last_success, pending_due))
            db.execute("INSERT INTO monitoring_check_state(camera_id,check_type,current_state,last_success_at) VALUES(?,?,?,?) ON CONFLICT(camera_id,check_type) DO UPDATE SET current_state=excluded.current_state,current_job_id=NULL,last_success_at=COALESCE(excluded.last_success_at,monitoring_check_state.last_success_at)",
                       (camera_id, check_type, "pending_confirmation" if pending_due else health, last_success))
            update_incident(db, "camera", camera_id, server_id, check_type, health,
                            None if is_success else error_code, completed_at,
                            {"detail": live_result["detail"], "sample_timestamp": (job.get("result") or {}).get("sample_timestamp")})
        prune_history(db)
        if job.get("completed_at"):
            cam=db.execute("SELECT c.name,c.remote_id,c.server_id,s.name AS server_name FROM cameras c JOIN servers s ON s.id=c.server_id WHERE c.id=?",(camera_id,)).fetchone()
            if cam:
                result=job.get("result") or {}
                enqueue_event(db,"job.completed",{"job_id":job.get("id"),"job_type":check_type,"camera_id":camera_id,
                    "camera_name":cam["name"],"camera_remote_id":cam["remote_id"],"server_id":server_id,
                    "server_name":cam["server_name"],"status":job.get("status"),"completed_at":job.get("completed_at"),
                    "reason":(job.get("error") or {}).get("code") or result.get("reason")})
    if MONITORING_SCHEDULE is not None and job.get("scheduled"):
        MONITORING_SCHEDULE.complete(camera_id, check_type)


def start_recording_check(camera, server, scheduled=False):
    with CAMERA_WORK_LOCK, RECORDING_CHECK_LOCK:
        active = CAMERA_WORK_BY_CAMERA.get(camera["id"])
        if active:
            return None, active, "duplicate"
        active = RECORDING_CHECKS_BY_CAMERA.get(camera["id"])
        if active:
            return None, active, "duplicate"
        if len(RECORDING_CHECKS) >= 1000:
            return None, None, "capacity"
        if server["adapter"] != "fixture":
            return None, None, "integration_unverified"
        if not RECORDING_CHECK_SLOTS.acquire(blocking=False):
            return None, None, "capacity"
        settings = json.loads(camera["settings_json"])
        overrides = json.loads(camera["overrides_json"])
        lookback = overrides.get("recording_lookback_hours", settings.get("recording_lookback_hours", 24))
        job = {"id": str(uuid.uuid4()), "camera_id": camera["id"], "server_id": server["id"],
               "status": "queued", "created_at": utc_now(), "started_at": None, "completed_at": None,
               "lookback_hours": lookback, "result": None, "error": None, "cancel_event": threading.Event(), "scheduled": scheduled}
        RECORDING_CHECKS[job["id"]] = job
        RECORDING_CHECKS_BY_CAMERA[camera["id"]] = job["id"]
        CAMERA_WORK_BY_CAMERA[camera["id"]] = job["id"]
        if scheduled:
            mark_monitoring_job(camera["id"], "recording", job["id"])
        RECORDING_CHECK_EXECUTOR.submit(run_recording_check, job["id"], dict(camera), dict(server), lookback)
        return job, None, None


def run_recording_check(job_id, camera, server, lookback_hours):
    with RECORDING_CHECK_LOCK:
        job = RECORDING_CHECKS.get(job_id)
        if not job:
            RECORDING_CHECK_SLOTS.release()
            return
        job.update(status="running", started_at=utc_now())
    temp_path = None
    try:
        profile = server["fixture_profile"]
        checked_epoch = time.time()
        checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(checked_epoch))
        with connect_db() as db:
            previous = db.execute("SELECT result_json FROM recording_check_state WHERE camera_id=?", (camera["id"],)).fetchone()
        previous_result = json.loads(previous["result_json"]) if previous else {}
        prior_success = previous_result.get("last_success_at")
        if profile == "recording_permission_error":
            result = {"health": "unknown", "reason": "permission_denied", "checked_at": checked_at,
                      "last_success_at": prior_success, "newest_recording_at": None, "decoded": False,
                      "evidence": {"detail": "Fixture search returned permission denied; no camera failure is inferred."}}
        elif profile == "recording_search_error":
            result = {"health": "unknown", "reason": "connector_unavailable", "checked_at": checked_at,
                      "last_success_at": prior_success, "newest_recording_at": None, "decoded": False,
                      "evidence": {"detail": "Fixture recording search is unavailable."}}
        elif profile == "server_unavailable":
            result = {"health": "unknown", "reason": "server_unavailable", "checked_at": checked_at,
                      "last_success_at": prior_success, "newest_recording_at": None, "decoded": False,
                      "evidence": {"detail": "Fixture simulates recorder server unavailability; camera health is not inferred."}}
        else:
            recordings = []
            if profile not in ("recording_none",):
                if profile == "recording_boundary":
                    ages = [("recording-window-boundary.mp4", lookback_hours * 3600), ("recording-outside-window.mp4", lookback_hours * 3600 + 1)]
                else:
                    ages = [("recording-older.mp4", 4 * 3600), ("recording-newest.mp4", 3600)]
                for name, age in ages:
                    timestamp_epoch = checked_epoch - age
                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp_epoch))
                    if checked_epoch - timestamp_epoch <= lookback_hours * 3600:
                        recordings.append({"name": name, "timestamp": timestamp, "epoch": timestamp_epoch})
            if not recordings:
                result = {"health": "warning", "reason": "no_recent_recording", "checked_at": checked_at,
                          "last_success_at": prior_success, "newest_recording_at": None, "decoded": False,
                          "evidence": {"detail": f"No motion recording was found within the previous {lookback_hours} hours."}}
            else:
                newest = max(recordings, key=lambda recording: recording["epoch"])
                content = b"invalid recording bytes" if profile == "recording_invalid_media" else (Path(__file__).parent / "tests" / "fixtures" / "live-sample.mp4").read_bytes()
                with tempfile.NamedTemporaryFile(prefix="chm-recording-", suffix=".mp4", delete=False) as sample:
                    temp_path = sample.name
                    sample.write(content)
                process = subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-v", "error", "-i", temp_path,
                                           "-map", "0:v:0", "-frames:v", "1", "-f", "null", "-"],
                                          capture_output=True, text=True, timeout=LIVE_CHECK_TIMEOUT, check=False)
                if process.returncode != 0:
                    result = {"health": "failure", "reason": "decode_failed", "checked_at": checked_at,
                              "last_success_at": prior_success, "newest_recording_at": newest["timestamp"], "decoded": False,
                              "evidence": {"sample_name": newest["name"], "detail": "The newest recording sample could not be decoded."}}
                else:
                    result = {"health": "healthy", "reason": None, "checked_at": checked_at,
                              "last_success_at": checked_at, "newest_recording_at": newest["timestamp"], "decoded": True,
                              "evidence": {"sample_name": newest["name"], "decoder": "ffmpeg", "detail": "Fixture sample decoded; this does not verify Exacq compatibility."}}
        with connect_db() as db:
            db.execute("INSERT INTO recording_check_state(camera_id,checked_at,result_json) VALUES(?,?,?) ON CONFLICT(camera_id) DO UPDATE SET checked_at=excluded.checked_at,result_json=excluded.result_json",
                       (camera["id"], result["checked_at"], json.dumps(result)))
        with RECORDING_CHECK_LOCK:
            job.update(status="completed", result=result, completed_at=utc_now())
    except subprocess.TimeoutExpired:
        result = {"health": "unknown", "reason": "timeout", "checked_at": utc_now(), "last_success_at": None,
                  "newest_recording_at": None, "decoded": False, "evidence": {"detail": "Recording sample decode timed out."}}
        with connect_db() as db:
            db.execute("INSERT INTO recording_check_state(camera_id,checked_at,result_json) VALUES(?,?,?) ON CONFLICT(camera_id) DO UPDATE SET checked_at=excluded.checked_at,result_json=excluded.result_json",
                       (camera["id"], result["checked_at"], json.dumps(result)))
        with RECORDING_CHECK_LOCK:
            job.update(status="completed", result=result, completed_at=utc_now())
    except Exception:
        result = {"health": "unknown", "reason": "connector_unavailable", "checked_at": utc_now(), "last_success_at": None,
                  "newest_recording_at": None, "decoded": False, "evidence": {"detail": "Recording check could not complete."}}
        with connect_db() as db:
            db.execute("INSERT INTO recording_check_state(camera_id,checked_at,result_json) VALUES(?,?,?) ON CONFLICT(camera_id) DO UPDATE SET checked_at=excluded.checked_at,result_json=excluded.result_json",
                       (camera["id"], result["checked_at"], json.dumps(result)))
        with RECORDING_CHECK_LOCK:
            job.update(status="completed", result=result, completed_at=utc_now())
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        with RECORDING_CHECK_LOCK:
            RECORDING_CHECKS_BY_CAMERA.pop(camera["id"], None)
        with CAMERA_WORK_LOCK:
            if CAMERA_WORK_BY_CAMERA.get(camera["id"]) == job_id:
                CAMERA_WORK_BY_CAMERA.pop(camera["id"], None)
        persist_scheduled_result(camera["id"], "recording", job)
        RECORDING_CHECK_SLOTS.release()


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def monitoring_now():
    """Wall clock for schedules; a file override is used only by deterministic acceptance tests."""
    clock_file = os.environ.get("CHM_TEST_CLOCK_FILE")
    if clock_file:
        try:
            return float(Path(clock_file).read_text().strip())
        except (OSError, ValueError):
            pass
    return time.time()


def run_live_check(job_id, camera, server):
    cancelled_before_start = False
    with LIVE_CHECK_LOCK:
        job = LIVE_CHECKS.get(job_id)
        if not job or job["cancel_event"].is_set():
            if job:
                job.update(status="cancelled", completed_at=utc_now(), completed_epoch=time.time())
            LIVE_CHECKS_BY_CAMERA.pop(camera["id"], None)
            cancelled_before_start = True
        else:
            job.update(status="running", started_at=utc_now())
    if cancelled_before_start:
        with CAMERA_WORK_LOCK:
            if CAMERA_WORK_BY_CAMERA.get(camera["id"]) == job_id:
                CAMERA_WORK_BY_CAMERA.pop(camera["id"], None)
        if job:
            persist_scheduled_result(camera["id"], "live", job)
        LIVE_CHECK_SLOTS.release()
        return
    temp_path = None
    process = None
    try:
        if server["adapter"] != "fixture":
            raise RuntimeError("integration_unverified")
        if server["fixture_profile"] == "live_timeout":
            if job["cancel_event"].wait(LIVE_CHECK_TIMEOUT + 0.1):
                raise InterruptedError("cancelled")
            raise TimeoutError("Fixture live sample exceeded the configured check timeout.")
        if server["fixture_profile"] == "server_unavailable":
            raise RuntimeError("server_unavailable")
        if server["fixture_profile"] == "live_flaky" and not job.get("confirmation_retry"):
            raise ValueError("Fixture simulates one transient live decode failure.")
        if server["fixture_profile"] == "live_slow":
            if job["cancel_event"].wait(1.0):
                raise InterruptedError("cancelled")
        if server["fixture_profile"] == "invalid_media":
            content = b"this is not valid video media"
        else:
            content = (Path(__file__).parent / "tests" / "fixtures" / "live-sample.mp4").read_bytes()
        with tempfile.NamedTemporaryFile(prefix="chm-live-", suffix=".mp4", delete=False) as sample:
            temp_path = sample.name
            sample.write(content)
        with LIVE_CHECK_LOCK:
            if job["cancel_event"].is_set():
                raise InterruptedError("cancelled")
            process = subprocess.Popen(
                ["ffmpeg", "-nostdin", "-hide_banner", "-v", "error", "-i", temp_path,
                 "-map", "0:v:0", "-frames:v", "1", "-f", "null", "-"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            job["process"] = process
        try:
            _, stderr = process.communicate(timeout=LIVE_CHECK_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate()
            raise TimeoutError("Video decoding exceeded the configured time limit.")
        with LIVE_CHECK_LOCK:
            cancelled = job["cancel_event"].is_set()
        if cancelled:
            raise InterruptedError("cancelled")
        if process.returncode != 0:
            raise ValueError("FFmpeg could not decode a video frame." + (" " + stderr.strip()[:500] if stderr else ""))
        try:
            pts = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                                  "frame=best_effort_timestamp_time,pict_type", "-of", "csv=p=0", temp_path],
                                 capture_output=True, text=True, timeout=LIVE_CHECK_TIMEOUT, check=False).stdout.strip().splitlines()
            if not pts:
                raise ValueError("FFmpeg did not find a decodable video frame.")
            frame_timestamp = pts[0].split(",", 1)[0] or None
        except (subprocess.TimeoutExpired, OSError):
            frame_timestamp = None
        with LIVE_CHECK_LOCK:
            if job["cancel_event"].is_set():
                raise InterruptedError("cancelled")
        result = {"decoded": True, "frames_decoded": 1, "sample_timestamp": None,
                  "frame_timestamp": frame_timestamp,
                  "sample_timestamp_source": "unavailable", "decoder": "ffmpeg",
                  "detail": "Fixture sample decoded successfully; this does not verify the configured ExacqVision recorder."}
        with LIVE_CHECK_LOCK:
            job.update(status="succeeded", result=result, completed_at=utc_now())
    except InterruptedError:
        with LIVE_CHECK_LOCK:
            job.update(status="cancelled", completed_at=utc_now())
    except TimeoutError as error:
        with LIVE_CHECK_LOCK:
            job.update(status="failed", error={"code": "timeout", "message": str(error)}, completed_at=utc_now())
    except ValueError as error:
        with LIVE_CHECK_LOCK:
            job.update(status="failed", error={"code": "decode_failed", "message": str(error)}, completed_at=utc_now())
    except RuntimeError as error:
        with LIVE_CHECK_LOCK:
            code = "server_unavailable" if str(error) == "server_unavailable" else "check_failed"
            job.update(status="failed", error={"code": code, "message": "The configured recorder server is unavailabl