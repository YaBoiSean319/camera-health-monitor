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
            job.update(status="failed", error={"code": code, "message": "The configured recorder server is unavailable."}, completed_at=utc_now())
    except Exception:
        with LIVE_CHECK_LOCK:
            job.update(status="failed", error={"code": "check_failed", "message": "The live sample check failed."}, completed_at=utc_now())
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        with LIVE_CHECK_LOCK:
            if job_id in LIVE_CHECKS:
                LIVE_CHECKS[job_id].pop("process", None)
                LIVE_CHECKS_BY_CAMERA.pop(camera["id"], None)
                if LIVE_CHECKS[job_id]["status"] in ("succeeded", "failed", "cancelled", "unsupported"):
                    LIVE_CHECKS[job_id]["completed_epoch"] = time.time()
        with CAMERA_WORK_LOCK:
            if CAMERA_WORK_BY_CAMERA.get(camera["id"]) == job_id:
                CAMERA_WORK_BY_CAMERA.pop(camera["id"], None)
        persist_scheduled_result(camera["id"], "live", job)
        LIVE_CHECK_SLOTS.release()


def start_live_check(camera, server, scheduled=False, confirmation_retry=False):
    now = utc_now()
    with CAMERA_WORK_LOCK, LIVE_CHECK_LOCK:
        # Remove old terminal results so the process-local poll table remains bounded.
        cutoff = time.time() - 86400
        for old_id, old in list(LIVE_CHECKS.items()):
            if old.get("completed_epoch", 0) < cutoff and old["status"] in ("succeeded", "failed", "cancelled", "unsupported"):
                LIVE_CHECKS.pop(old_id, None)
        active = CAMERA_WORK_BY_CAMERA.get(camera["id"])
        if active:
            return None, active, "duplicate"
        if len(LIVE_CHECKS) >= 1000:
            return None, None, "capacity"
        if server["adapter"] != "fixture":
            return None, None, "integration_unverified"
        if not LIVE_CHECK_SLOTS.acquire(blocking=False):
            return None, None, "capacity"
        job_id = str(uuid.uuid4())
        job = {"id": job_id, "camera_id": camera["id"], "server_id": server["id"], "status": "queued",
               "created_at": now, "started_at": None, "completed_at": None, "completed_epoch": 0,
               "result": None, "error": None, "cancel_event": threading.Event(), "process": None,
               "scheduled": scheduled, "confirmation_retry": confirmation_retry}
        LIVE_CHECKS[job_id] = job
        LIVE_CHECKS_BY_CAMERA[camera["id"]] = job_id
        CAMERA_WORK_BY_CAMERA[camera["id"]] = job_id
        if scheduled:
            mark_monitoring_job(camera["id"], "live", job_id)
        LIVE_CHECK_EXECUTOR.submit(run_live_check, job_id, dict(camera), dict(server))
        return job, None, None


def create_server(db, data):
    name, host = data.get("name", ""), data.get("host", "")
    adapter, port = data.get("adapter", "exacq"), data.get("port")
    username, password = data.get("username", ""), data.get("password", "")
    fixture_profile = data.get("fixture_profile", "success")
    defaults = validate_camera_settings(data.get("defaults", default_camera_settings()))
    if (not isinstance(name, str) or not name.strip() or len(name.strip()) > 100
            or not isinstance(host, str) or not host.strip() or len(host.strip()) > 253
            or any(c.isspace() for c in host.strip()) or "://" in host
            or (port is not None and (type(port) is not int or not 1 <= port <= 65535))
            or adapter not in ("exacq", "fixture")
            or fixture_profile not in ("success", "discovery_error", "no_cameras", "capability_error", "invalid_media", "live_slow", "live_timeout", "live_flaky", "recording_none", "recording_success", "recording_invalid_media", "recording_permission_error", "recording_search_error", "recording_boundary", "server_unavailable")
            or not isinstance(username, str) or not isinstance(password, str) or defaults is None):
        return None
    if adapter == "fixture" and os.environ.get("CHM_ENABLE_FIXTURE", "false").lower() != "true":
        return None
    cipher = credential_cipher().encrypt(password.encode()).decode() if password else ""
    capabilities = empty_capabilities()
    if adapter == "fixture":
        capabilities["camera_discovery"] = {"status": "untested", "detail": "Fixture discovery has not run."}
    sid = str(uuid.uuid4())
    db.execute("""INSERT INTO servers(id,name,host,port,username,password_ciphertext,adapter,fixture_profile,defaults_json,capabilities_json)
        VALUES(?,?,?,?,?,?,?,?,?,?)""", (sid, name.strip(), host.strip(), port, username, cipher, adapter,
        fixture_profile if adapter == "fixture" else "success", json.dumps(defaults), json.dumps(capabilities)))
    return sid


def discover_server(db, server):
    capabilities = json.loads(server["capabilities_json"])
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if server["adapter"] != "fixture":
        detail = ("Discovery is unverified and is not attempted. Exacq's public material identifies integration tools, "
                  "but does not publish the installed server's API contract. Confirm version, Web Service/API setup, "
                  "account permissions, licensing, and a supported discovery interface before enabling this adapter.")
        capabilities["camera_discovery"] = {"status": "untested", "detail": detail}
        db.execute("UPDATE servers SET capabilities_json=?, discovery_status='untested', discovery_detail=?, last_discovery_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                   (json.dumps(capabilities), detail, now, server["id"]))
        return {"error": "integration_unverified", "message": detail, "status": "untested"}, 501
    profile = server["fixture_profile"]
    if profile == "discovery_error":
        detail = "Fixture discovery failed: simulated recorder permission denied."
        capabilities["camera_discovery"] = {"status": "failed", "detail": detail}
        db.execute("UPDATE servers SET capabilities_json=?, discovery_status='failed', discovery_detail=?, last_discovery_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                   (json.dumps(capabilities), detail, now, server["id"]))
        return {"error": "discovery_failed", "message": detail, "status": "failed"}, 502
    remote_cameras = [] if profile == "no_cameras" else [{"remote_id": "camera-1", "name": "Fixture Camera 1"}]
    previous_ids = {row[0] for row in db.execute("SELECT remote_id FROM cameras WHERE server_id=?", (server["id"],)).fetchall()}
    current_ids = {camera["remote_id"] for camera in remote_cameras}
    db.execute("UPDATE cameras SET disappeared=1 WHERE server_id=?", (server["id"],))
    for camera in remote_cameras:
        db.execute("""INSERT INTO cameras(id,server_id,remote_id,name,settings_json) VALUES(?,?,?,?,?)
            ON CONFLICT(server_id,remote_id) DO UPDATE SET name=excluded.name, disappeared=0, last_seen_at=CURRENT_TIMESTAMP""",
                   (str(uuid.uuid4()), server["id"], camera["remote_id"], camera["name"], server["defaults_json"]))
    detail = f"Fixture provider returned {len(current_ids)} camera(s). This is test data, not Exacq compatibility evidence."
    capabilities["camera_discovery"] = {"status": "verified", "detail": detail}
    db.execute("UPDATE servers SET capabilities_json=?, discovery_status='verified', discovery_detail=?, last_discovery_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
               (json.dumps(capabilities), detail, now, server["id"]))
    return {"server_id": server["id"], "discovered": len(current_ids), "added": len(current_ids - previous_ids),
            "disappeared": len(previous_ids - current_ids), "cameras": [dict(row) for row in db.execute(
                "SELECT id,remote_id,name,disappeared FROM cameras WHERE server_id=? ORDER BY remote_id", (server["id"],)).fetchall()],
            "capabilities": capabilities}, 200


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return base64.b64encode(digest).decode(), base64.b64encode(salt).decode()


def verify_password(password, digest, salt):
    if not isinstance(password, str):
        return False
    candidate, _ = hash_password(password, base64.b64decode(salt))
    return hmac.compare_digest(candidate, digest)


def response(start_response, status, payload=None, headers=()):
    if isinstance(payload, bytes):
        body = payload
    elif payload is None:
        body = b""
    else:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = [("Content-Type", "application/json; charset=utf-8"), *headers]
    start_response(f"{status} {HTTPStatus(status).phrase}", [("Content-Length", str(len(body))), ("Cache-Control", "no-store"), *headers])
    return [body]


def read_json(environ):
    try:
        length = min(int(environ.get("CONTENT_LENGTH") or 0), 1_000_000)
        value = json.loads(environ["wsgi.input"].read(length) or b"{}")
        return value if isinstance(value, dict) else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def admin_exists():
    with connect_db() as db:
        return db.execute("SELECT 1 FROM admins WHERE id = 1").fetchone() is not None


def current_admin(environ):
    authorization = environ.get("HTTP_AUTHORIZATION", "")
    if authorization:
        scheme, _, raw = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw:
            return None
        digest = hashlib.sha256(raw.encode()).hexdigest()
        with connect_db() as db:
            row = db.execute("SELECT * FROM api_tokens WHERE token_hash=? AND revoked_at IS NULL", (digest,)).fetchone()
        if not row or (row["expires_at"] is not None and row["expires_at"] <= time.time()):
            return None
        return {"id": f"token:{row['id']}", "username": row["name"], "role": row["role"], "auth_type": "api_token",
                "token_id": row["id"], "scopes": json.loads(row["scopes_json"])}
    cookie = SimpleCookie()
    cookie.load(environ.get("HTTP_COOKIE", ""))
    morsel = cookie.get("chm_session")
    token = morsel.value if morsel else None
    with SESSION_LOCK:
        session = SESSIONS.get(token)
    if not session or session["expires"] < time.time():
        if token:
            with SESSION_LOCK:
                SESSIONS.pop(token, None)
        return None
    if session.get("auth_type") == "oidc":
        return {"id": session["principal_id"], "username": session["username"], "role": session["role"], "auth_type": "oidc"}
    with connect_db() as db:
        row = db.execute("SELECT id, username FROM admins WHERE id = ?", (session["admin_id"],)).fetchone()
    return {**dict(row), "role": "administrator", "auth_type": "local"} if row else None


def issue_session(admin_id=None, *, username=None, role="administrator", auth_type="local", principal_id=None):
    token = secrets.token_urlsafe(32)
    identity = {"admin_id": admin_id, "username": username, "role": role, "auth_type": auth_type, "principal_id": principal_id}
    if auth_type == "local" and username is None:
        with connect_db() as db:
            row = db.execute("SELECT username FROM admins WHERE id=?", (admin_id,)).fetchone()
        identity["username"] = row["username"] if row else "administrator"
    with SESSION_LOCK:
        SESSIONS[token] = {**identity, "expires": time.time() + SESSION_TTL}
    flags = "; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800" + ("; Secure" if COOKIE_SECURE else "")
    return "chm_session=" + token + flags


def setting(name):
    with connect_db() as db:
        row = db.execute("SELECT value_json FROM settings WHERE key=?", (name,)).fetchone()
    result = json.loads(row[0]) if row else {}
    if name == "oidc" and result.get("client_secret", "").startswith("enc:v1:"):
        try:
            raw = base64.urlsafe_b64decode(result["client_secret"][7:])
            key_path = DATA_DIR / ".secret-key"
            key = key_path.read_bytes()
            result["client_secret"] = AESGCM(key).decrypt(raw[:12], raw[12:], b"chm-oidc-client-secret").decode()
        except (OSError, ValueError) as error:
            raise RuntimeError("Unable to decrypt the stored OIDC credential; restore the matching data volume") from error
    return result


def save_setting(name, value):
    if name == "oidc" and value.get("client_secret"):
        key_path = DATA_DIR / ".secret-key"
        if not key_path.exists():
            key_path.write_bytes(secrets.token_bytes(32))
            os.chmod(key_path, 0o600)
        key = key_path.read_bytes()
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(key).encrypt(nonce, value["client_secret"].encode(), b"chm-oidc-client-secret")
        value = {**value, "client_secret": "enc:v1:" + base64.urlsafe_b64encode(nonce + encrypted).decode()}
    with connect_db() as db:
        db.execute("INSERT INTO settings(key, value_json) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json", (name, json.dumps(value)))


def public_oidc_config(config):
    return {"enabled": bool(config.get("enabled")), "issuer": config.get("issuer", ""), "client_id": config.get("client_id", ""),
            "client_secret_configured": bool(config.get("client_secret")), "role_claim": config.get("role_claim", "groups"),
            "administrator_values": config.get("administrator_values", []), "operator_values": config.get("operator_values", [])}


def redirect_uri(environ):
    public = os.environ.get("CHM_PUBLIC_URL", "").rstrip("/")
    if public:
        parsed = urllib.parse.urlparse(public)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("CHM_PUBLIC_URL must be an HTTPS origin without a path")
        return public + "/api/v1/auth/oidc/callback"
    scheme = environ.get("wsgi.url_scheme", "http")
    host = environ.get("HTTP_HOST", "localhost")
    hostname = urllib.parse.urlparse(f"{scheme}://{host}").hostname
    if hostname not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("CHM_PUBLIC_URL must be set for non-loopback deployments")
    return f"{scheme}://{host}/api/v1/auth/oidc/callback"


def has_role(principal, required_role):
    """Central role hierarchy used by protected REST operations."""
    ranks = {"operator": 1, "administrator": 2}
    return bool(principal and ranks.get(principal.get("role"), 0) >= ranks.get(required_role, 99))


def has_scope(principal, scope):
    return bool(principal and (principal.get("auth_type") != "api_token" or scope in principal.get("scopes", [])))


def audit(principal, action, resource, resource_id=None, db=None):
    if not principal:
        return
    actor_type = "api_token" if principal.get("auth_type") == "api_token" else "user"
    values = (str(principal.get("id", "unknown")), principal.get("username", "unknown"), actor_type,
              action, resource, None if resource_id is None else str(resource_id), datetime.now(timezone.utc).isoformat())
    statement = "INSERT INTO audit_log(actor_id,actor_name,actor_type,action,resource,resource_id,created_at) VALUES(?,?,?,?,?,?,?)"
    if db:
        db.execute(statement, values)
    else:
        with connect_db() as connection:
            connection.execute(statement, values)


def token_expiry(value):
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("invalid_expiration")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise ValueError("invalid_expiration")


def openapi_document():
    def body(schema):
        return {"required": True, "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{schema}"}}}}
    principal = {"$ref": "#/components/schemas/Principal"}
    json_response = lambda description, schema: {"description": description, "content": {"application/json": {"schema": schema}}}
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Camera Health Monitor API", "version": "1.0.0", "description": "Versioned REST API used by the browser and automation clients."},
        "servers": [{"url": "/api/v1"}],
        "components": {
            "securitySchemes": {"sessionCookie": {"type": "apiKey", "in": "cookie", "name": "chm_session"}, "bearerToken": {"type": "http", "scheme": "bearer", "bearerFormat": "CHM API token"}},
            "schemas": {
                "Credentials": {"type": "object", "required": ["username", "password"], "properties": {"username": {"type": "string", "maxLength": 64}, "password": {"type": "string", "format": "password", "minLength": 12}}},
                "LoginCredentials": {"type": "object", "required": ["username", "password"], "properties": {"username": {"type": "string"}, "password": {"type": "string", "format": "password"}}},
                "CredentialChange": {"type": "object", "required": ["current_password", "username"], "properties": {"current_password": {"type": "string", "format": "password"}, "username": {"type": "string", "maxLength": 64}, "new_password": {"type": "string", "format": "password", "minLength": 12, "description": "Optional; omit or leave empty to keep the current password."}}},
                "Principal": {"type": "object", "required": ["id", "username", "role"], "properties": {"id": {"type": ["integer", "string"]}, "username": {"type": "string"}, "role": {"type": "string", "enum": ["operator", "administrator"]}, "auth_type": {"type": "string", "enum": ["local", "oidc", "api_token"]}, "scopes": {"type": "array", "items": {"type": "string"}, "readOnly": True}}},
                "SetupStatus": {"type": "object", "required": ["setup_required"], "properties": {"setup_required": {"type": "boolean"}}},
                "Dashboard": {"type": "object", "properties": {"principal": principal, "servers": {"type": "array", "items": {"type": "object"}}, "cameras": {"type": "array", "items": {"type": "object"}}, "summary": {"type": "object"}, "branding": {"type": "object"}}},
                "MonitoringStatus": {"type": "object", "description": "Process liveness is independent from scheduled-monitor progress. A live process can report a stalled monitor; per-camera health remains unknown for auth/permission/connector errors.", "properties": {"monitor": {"type": "object", "properties": {"state": {"type": "string", "enum": ["healthy", "fault", "starting", "disabled"]}, "last_progress_at": {"type": ["string", "null"], "format": "date-time"}, "progress_age_seconds": {"type": ["integer", "null"]}, "last_error_code": {"type": ["string", "null"], "description": "Sanitized diagnostic code only."}, "liveness": {"type": "string", "const": "alive"}}}, "scheduler": {"type": "object"}, "cameras": {"type": "array", "items": {"type": "object"}}}},
                "Incident": {"type": "object", "required": ["id", "entity_type", "entity_id", "server_id", "check_type", "reason", "severity", "status", "opened_at", "transitions"], "properties": {"id": {"type": "string", "format": "uuid"}, "entity_type": {"type": "string", "enum": ["camera", "server"]}, "entity_id": {"type": "string"}, "server_id": {"type": "string"}, "check_type": {"type": "string", "enum": ["live", "recording", "server", "monitoring"]}, "reason": {"type": "string"}, "severity": {"type": "string", "enum": ["warning", "failure", "monitoring"]}, "status": {"type": "string", "enum": ["open", "resolved"]}, "opened_at": {"type": "string", "format": "date-time"}, "updated_at": {"type": "string", "format": "date-time"}, "resolved_at": {"type": ["string", "null"], "format": "date-time"}, "acknowledged_at": {"type": ["string", "null"], "format": "date-time"}, "acknowledged_by": {"type": ["string", "null"]}, "evidence": {"type": "object", "description": "Sanitized diagnostic metadata only; never video or credentials."}, "transitions": {"type": "array", "items": {"type": "object"}}}},
                "MaintenanceInput": {"type":"object","required":["entity_type","entity_id","reason","starts_at","ends_at"],"properties":{"entity_type":{"type":"string","enum":["camera","server"]},"entity_id":{"type":"string"},"reason":{"type":"string","minLength":1,"maxLength":500},"starts_at":{"type":"string","format":"date-time"},"ends_at":{"type":"string","format":"date-time","description":"Must be after starts_at and in the future. starts_at may be in the past for an immediate window. Overlapping windows for the same entity are rejected with 409; an identical request returns the existing window."}}},
                "MaintenanceWindow": {"type":"object","properties":{"id":{"type":"string","format":"uuid"},"entity_type":{"type":"string","enum":["camera","server"]},"entity_id":{"type":"string"},"reason":{"type":"string"},"starts_at":{"type":"string","format":"date-time"},"ends_at":{"type":"string","format":"date-time"},"ended_at":{"type":["string","null"],"format":"date-time"},"state":{"type":"string","enum":["scheduled","active","ended"]}}},
                "WebhookEvent": {"type":"object","required":["id","version","type","created_at","data"],"properties":{"id":{"type":"string","format":"uuid"},"version":{"type":"integer","const":1},"type":{"type":"string","enum":list(WEBHOOK_EVENTS)+["test"]},"created_at":{"type":"string","format":"date-time"},"data":{"type":"object"}},"description":"Version 1 events contain sanitized metadata only. IDs remain stable across retries and restarts."},
                "WebhookReceiverInput": {"type":"object","required":["name","url","events"],"properties":{"name":{"type":"string","maxLength":100},"url":{"type":"string","format":"uri","description":"HTTP(S); private LAN receivers are supported. Redirects and cloud metadata link-local destinations are rejected."},"events":{"type":"array","minItems":1,"uniqueItems":True,"items":{"type":"string","enum":list(WEBHOOK_EVENTS)}},"signing_secret":{"type":"string","format":"password","minLength":16,"maxLength":256,"writeOnly":True},"enabled":{"type":"boolean","default":True}}},
                "WebhookReceiver": {"type":"object","properties":{"id":{"type":"string","format":"uuid"},"name":{"type":"string"},"url":{"type":"string","format":"uri"},"events":{"type":"array","items":{"type":"string"}},"enabled":{"type":"boolean"},"signing_secret_configured":{"type":"boolean","readOnly":True},"created_at":{"type":"string","format":"date-time"},"updated_at":{"type":"string","format":"date-time"}}},
                "WebhookDelivery": {"type":"object","properties":{"id":{"type":"integer"},"receiver_id":{"type":"string","format":"uuid"},"event_id":{"type":"string","format":"uuid"},"event_type":{"type":"string"},"state":{"type":"string","enum":["pending","delivered"]},"attempt_count":{"type":"integer"},"created_at":{"type":"string","format":"date-time"},"updated_at":{"type":"string","format":"date-time"},"http_status":{"type":["integer","null"]},"error_code":{"type":["string","null"],"description":"Sanitized error code; no URL, body, credentials or receiver response is retained."}}},
                "Branding": {"type": "object", "required": ["app_name", "colors", "sso_button_text"], "properties": {"app_name": {"type": "string", "maxLength": 80}, "sso_button_text": {"type": "string", "maxLength": 80}, "colors": {"type": "object", "required": ["light", "dark"], "properties": {theme: {"type": "object", "required": ["accent", "background", "surface", "text"], "properties": {key: {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"} for key in ("accent", "background", "surface", "text")}} for theme in ("light", "dark")}}, "assets": {"type": "object", "properties": {key: {"type": ["string", "null"], "readOnly": True} for key in branding.ASSET_KEYS}}, "asset_uploads": {"type": "object", "description": "Optional atomically validated image updates; null removes an image.", "additionalProperties": {"type": ["string", "null"], "contentEncoding": "base64"}}}},
                "BrandingImage": {"type": "object", "required": ["data"], "properties": {"data": {"type": "string", "contentEncoding": "base64", "description": "PNG or JPEG image data. Maximum 2 MiB and 2048px (favicon 512 KiB and 512px)."}}},
                "ApiTokenCreate": {"type": "object", "required": ["name", "role", "scopes"], "properties": {"name": {"type": "string", "maxLength": 80}, "role": {"type": "string", "enum": ["operator", "administrator"]}, "scopes": {"type": "array", "uniqueItems": True, "items": {"type": "string", "enum": sorted(set.union(*API_SCOPES.values()))}}, "expires_at": {"type": ["string", "null"], "format": "date-time"}}},
                "ApiTokenMetadata": {"type": "object", "required": ["id", "name", "role", "scopes", "created_at"], "properties": {"id": {"type": "integer"}, "name": {"type": "string"}, "role": {"type": "string"}, "scopes": {"type": "array", "items": {"type": "string"}}, "created_by": {"type": "string"}, "created_at": {"type": "string", "format": "date-time"}, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "revoked_at": {"type": ["string", "null"], "format": "date-time"}}},
                "CameraSettings": {"type": "object", "properties": {"live_interval_minutes": {"type": "integer", "minimum": 1, "maximum": 1440, "default": 5}, "recording_interval_minutes": {"type": "integer", "minimum": 1, "maximum": 1440, "default": 60}, "recording_lookback_hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24}}},
                "ServerInput": {"type": "object", "required": ["name", "host"], "properties": {"name": {"type": "string"}, "host": {"type": "string"}, "port": {"type": ["integer", "null"], "description": "Only specify after confirming the installed interface port."}, "username": {"type": "string"}, "password": {"type": "string", "format": "password", "description": "Write-only; blank on update retains stored credential."}, "defaults": {"$ref": "#/components/schemas/CameraSettings"}, "adapter": {"type": "string", "enum": ["exacq", "fixture"]}}},
                "ServerUpdate": {"type": "object", "properties": {"name": {"type": "string"}, "host": {"type": "string"}, "port": {"type": ["integer", "null"]}, "username": {"type": "string"}, "password": {"type": "string", "format": "password", "description": "Write-only; blank retains stored credential."}, "enabled": {"type": "boolean"}, "defaults": {"$ref": "#/components/schemas/CameraSettings"}}},
                "Server": {"type": "object", "properties": {"id": {"type": "string", "format": "uuid"}, "name": {"type": "string"}, "host": {"type": "string"}, "port": {"type": ["integer", "null"]}, "credentials_configured": {"type": "boolean"}, "capabilities": {"type": "object"}, "discovery_status": {"type": "string"}, "last_discovery_at": {"type": ["string", "null"]}}},
                "Capability": {"type": "object", "required": ["status", "detail"], "properties": {"status": {"type": "string", "enum": ["untested", "unknown", "unsupported", "failed", "verified"]}, "detail": {"type": "string"}}},
                "LiveCheckJob": {"type": "object", "required": ["id", "camera_id", "server_id", "status", "created_at", "result", "error"], "properties": {"id": {"type": "string", "format": "uuid"}, "camera_id": {"type": "string"}, "server_id": {"type": "string"}, "status": {"type": "string", "enum": ["queued", "running", "succeeded", "failed", "cancelled"]}, "created_at": {"type": "string", "format": "date-time"}, "started_at": {"type": ["string", "null"], "format": "date-time"}, "completed_at": {"type": ["string", "null"], "format": "date-time"}, "result": {"type": ["object", "null"], "properties": {"decoded": {"type": "boolean"}, "frames_decoded": {"type": "integer"}, "sample_timestamp": {"type": ["string", "null"], "description": "Wall-clock source capture timestamp, null when unavailable."}, "frame_timestamp": {"type": ["string", "null"], "description": "Container presentation timestamp; not wall-clock capture time."}, "sample_timestamp_source": {"type": "string"}, "decoder": {"type": "string"}, "detail": {"type": "string"}}}, "error": {"type": ["object", "null"], "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}}},
                "RecordingCheckJob": {"type": "object", "required": ["id", "camera_id", "server_id", "status", "lookback_hours", "result"], "properties": {"id": {"type": "string", "format": "uuid"}, "camera_id": {"type": "string"}, "server_id": {"type": "string"}, "status": {"type": "string", "enum": ["queued", "running", "completed"]}, "lookback_hours": {"type": "integer", "minimum": 1, "maximum": 720}, "created_at": {"type": "string", "format": "date-time"}, "started_at": {"type": ["string", "null"], "format": "date-time"}, "completed_at": {"type": ["string", "null"], "format": "date-time"}, "result": {"type": ["object", "null"], "properties": {"health": {"type": "string", "enum": ["healthy", "warning", "failure", "unknown"]}, "reason": {"type": ["string", "null"]}, "checked_at": {"type": "string", "format": "date-time"}, "last_success_at": {"type": ["string", "null"], "format": "date-time"}, "newest_recording_at": {"type": ["string", "null"], "format": "date-time"}, "decoded": {"type": "boolean"}, "evidence": {"type": "object"}}}, "error": {"type": ["object", "null"]}}},
            },
        },
        "paths": {
            "/setup/status": {"get": {"summary": "Check whether initial setup is required", "responses": {"200": json_response("Setup state", {"$ref": "#/components/schemas/SetupStatus"})}}},
            "/setup/admin": {"post": {"summary": "Create the first local administrator (single use)", "requestBody": body("Credentials"), "responses": {"201": json_response("Created and signed in", principal), "400": {"description": "Invalid credentials"}, "409": {"description": "Setup already completed"}}}},
            "/auth/login": {"post": {"summary": "Sign in with local administrator credentials", "requestBody": body("LoginCredentials"), "responses": {"200": json_response("Signed in", principal), "401": {"description": "Invalid credentials"}, "429": {"description": "Too many sign-in attempts"}}}},
            "/auth/oidc/login": {"get": {"summary": "Begin OpenID Connect sign-in", "responses": {"302": {"description": "Redirect to identity provider"}}}},
            "/auth/oidc/status": {"get": {"summary": "Read OIDC availability"}},
            "/auth/oidc/callback": {"get": {"summary": "Validate provider response"}},
            "/admin/auth/oidc": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read OIDC settings"}, "put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Configure OIDC role mappings"}},
            "/admin/api-tokens": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "List token metadata; secret values are never returned", "responses": {"200": {"description": "Metadata without token values"}}}, "post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Issue a scoped API token (secret shown once)", "requestBody": body("ApiTokenCreate"), "responses": {"201": {"description": "Issued token and one-time secret"}, "400": {"description": "Invalid role, scope or expiry"}, "403": {"description": "Insufficient role or scope"}}}},
            "/admin/api-tokens/{token_id}": {"parameters": [{"name": "token_id", "in": "path", "required": True, "schema": {"type": "integer"}}], "delete": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Revoke an API token", "responses": {"204": {"description": "Revoked"}, "404": {"description": "Not found or already revoked"}}}},
            "/admin/audit": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read recent redacted audit activity"}},
            "/auth/logout": {"post": {"security": [{"sessionCookie": []}], "summary": "Sign out", "responses": {"204": {"description": "Signed out"}}}},
            "/auth/me": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read the current principal", "responses": {"200": json_response("Current principal", principal), "401": {"description": "Sign in required"}}}},
            "/admin/credentials": {"put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Change local administrator credentials", "requestBody": body("CredentialChange"), "responses": {"200": json_response("Credentials changed", principal), "400": {"description": "Invalid credentials"}, "401": {"description": "Sign in required"}, "403": {"description": "Current password is incorrect"}}}},
            "/dashboard": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read dashboard summary (requires health:read for tokens)", "responses": {"200": json_response("Dashboard summary", {"$ref": "#/components/schemas/Dashboard"}), "401": {"description": "Sign in required"}, "403": {"description": "Insufficient scope"}}}},
            "/monitoring": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read scheduled monitoring status (requires health:read)", "responses": {"200": json_response("Scheduler progress and per-camera current/last-success state", {"$ref": "#/components/schemas/MonitoringStatus"}), "401": {"description": "Sign in required"}, "403": {"description": "Insufficient scope"}}}},
            "/monitoring/heartbeat": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read optional external monitor heartbeat settings (administrator)", "responses": {"200": json_response("Receiver and cadence; no secret is returned", {"type": "object"})}}, "put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Configure a reliable external heartbeat webhook (administrator)", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["enabled"], "properties": {"enabled": {"type": "boolean"}, "receiver_id": {"type": ["string", "null"], "format": "uuid"}, "interval_seconds": {"type": "integer", "minimum": 60, "maximum": 86400}}}}}}, "responses": {"200": {"description": "Saved"}, "400": {"description": "Invalid or incompatible receiver"}}}},
            "/incidents": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "List incidents (operators require health:read; status=open, resolved or all)", "parameters": [{"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open", "resolved", "all"], "default": "open"}}], "responses": {"200": json_response("Incident list with transitions and acknowledgment", {"type": "array", "items": {"$ref": "#/components/schemas/Incident"}})}}},
            "/incidents/{incident_id}": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read incident detail and transition history", "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}], "responses": {"200": json_response("Incident detail", {"$ref": "#/components/schemas/Incident"}), "404": {"description": "Not found"}}}},
            "/incidents/{incident_id}/acknowledge": {"post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Acknowledge review without changing health or suppressing recovery", "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}], "responses": {"200": json_response("Acknowledged incident", {"$ref": "#/components/schemas/Incident"}), "409": {"description": "Incident has already resolved"}}}},
            "/maintenance": {"get":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"List maintenance windows (maintenance:read; GET also finalizes expired windows and reevaluates latest results)","responses":{"200":json_response("Maintenance windows",{"type":"array","items":{"$ref":"#/components/schemas/MaintenanceWindow"}})}},"post":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Create a camera/server maintenance window (maintenance:write)","requestBody":body("MaintenanceInput"),"responses":{"201":json_response("Created window",{"$ref":"#/components/schemas/MaintenanceWindow"}),"200":json_response("Identical window already exists",{"$ref":"#/components/schemas/MaintenanceWindow"}),"400":{"description":"Invalid scope, reason or dates"},"404":{"description":"Camera/server not found"},"409":{"description":"Overlapping window"}}}},
            "/maintenance/{window_id}": {"delete":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"End maintenance now; repeat end requests return current ended state","responses":{"200":json_response("Ended window",{"$ref":"#/components/schemas/MaintenanceWindow"}),"404":{"description":"Window not found"}}}},
            "/cameras/{camera_id}/exclusion": {"get":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Read explicit monitoring exclusion (maintenance:read)"},"put":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Set or clear explicit camera exclusion (maintenance:write); exclusion skips scheduled checks","requestBody":{"required":True,"content":{"application/json":{"schema":{"type":"object","required":["excluded"],"properties":{"excluded":{"type":"boolean"},"reason":{"type":"string","maxLength":500}}}}}},"responses":{"200":{"description":"Current exclusion"},"400":{"description":"Invalid exclusion"},"404":{"description":"Camera not found"}}}},
            "/history": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read incident history (1–90 days; active incidents are always included)", "parameters": [{"name": "days", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 90, "default": 90}}], "responses": {"200": {"description": "Incident history and transitions"}}}},
            "/branding": {"get": {"summary": "Read shared branding", "responses": {"200": json_response("Shared appearance configuration", {"$ref": "#/components/schemas/Branding"})}}, "put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Replace shared branding settings (requires branding:write for tokens)", "requestBody": body("Branding"), "responses": {"200": json_response("Saved branding", {"$ref": "#/components/schemas/Branding"}), "400": {"description": "Invalid branding values"}, "401": {"description": "Sign in required"}}}},
            "/branding/assets/{asset}": {"parameters": [{"name": "asset", "in": "path", "required": True, "schema": {"type": "string", "enum": sorted(branding.ASSET_KEYS)}}], "get": {"summary": "Serve a validated branding image", "responses": {"200": {"description": "Inert PNG or JPEG image"}, "404": {"description": "No image configured"}}}, "put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Upload a branding image (branding:write)", "requestBody": body("BrandingImage"), "responses": {"200": json_response("Image saved", {"type": "object", "properties": {"asset": {"type": "string"}, "url": {"type": "string"}}}), "400": {"description": "Invalid image, size, dimensions or format"}, "401": {"description": "Sign in required"}}}, "delete": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Remove a branding image (branding:write)", "responses": {"200": {"description": "Image removed"}, "401": {"description": "Sign in required"}}}},
            "/servers": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "List configured recorder servers (servers:read)", "responses": {"200": json_response("Servers with secrets redacted", {"type": "array", "items": {"$ref": "#/components/schemas/Server"}})}}, "post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Add a recorder connection (servers:write)", "requestBody": body("ServerInput"), "responses": {"201": json_response("Created", {"$ref": "#/components/schemas/Server"}), "400": {"description": "Invalid server configuration"}}}},
            "/servers/{server_id}": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read a recorder connection (servers:read)", "responses": {"200": json_response("Server", {"$ref": "#/components/schemas/Server"})}}, "put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Update a recorder connection (servers:write)", "requestBody": body("ServerUpdate"), "responses": {"200": json_response("Updated server", {"$ref": "#/components/schemas/Server"})}}, "delete": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Remove a recorder and inventory (servers:write)", "responses": {"204": {"description": "Removed"}}}},
            "/servers/{server_id}/discover": {"post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Refresh camera inventory (checks:run)", "responses": {"200": json_response("Discovery result", {"type": "object"}), "501": {"description": "Exacq interface contract unverified"}, "502": {"description": "Discovery failed"}}}},
            "/servers/{server_id}/capabilities": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Read independent capability status (servers:read)", "responses": {"200": json_response("Capabilities", {"type": "object"})}}, "post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Probe capabilities (servers:write)", "responses": {"200": json_response("Capabilities", {"type": "object"})}}},
            "/cameras": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "List persistent camera inventory (cameras:read)", "responses": {"200": json_response("Camera inventory", {"type": "array", "items": {"type": "object"}})}}},
            "/cameras/{camera_id}/recording-check": {"post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Start an asynchronous recent recording search and sample decode (checks:run)", "responses": {"202": json_response("Queued recording check", {"$ref": "#/components/schemas/RecordingCheckJob"}), "409": {"description": "Camera unavailable or check already running"}, "429": {"description": "Check capacity reached"}, "501": {"description": "Exacq recording search/playback contract unverified"}}}},
            "/servers/{server_id}/recording-check": {"post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Start checks for all present cameras on a server (checks:run)", "responses": {"202": json_response("Queued per-camera jobs", {"type": "object"}), "501": {"description": "Exacq recording search/playback contract unverified"}}}},
            "/recording-checks/{job_id}": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Poll a recording-check result (health:read)", "responses": {"200": json_response("Recording-check state and evidence", {"$ref": "#/components/schemas/RecordingCheckJob"}), "404": {"description": "Check not found"}}}},
            "/cameras/{camera_id}/live-check": {"post": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Start an asynchronous live sample retrieval and decode check (checks:run)", "responses": {"202": json_response("Queued check", {"$ref": "#/components/schemas/LiveCheckJob"}), "404": {"description": "Camera not found"}, "409": {"description": "Camera unavailable or a check already running"}, "429": {"description": "Check capacity reached"}, "501": {"description": "Exacq interface contract unverified"}}}},
            "/live-checks/{job_id}": {"get": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Poll a live-check result (health:read)", "responses": {"200": json_response("Live-check state and decode result", {"$ref": "#/components/schemas/LiveCheckJob"}), "404": {"description": "Check not found"}}}, "delete": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Cancel an active live check (checks:run)", "responses": {"202": json_response("Cancellation requested", {"$ref": "#/components/schemas/LiveCheckJob"}), "409": {"description": "Check is already terminal"}}}},
            "/cameras/{camera_id}": {"put": {"security": [{"sessionCookie": []}, {"bearerToken": []}], "summary": "Update camera overrides (cameras:write)", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"overrides": {"type": "object"}}}}}}, "responses": {"200": json_response("Updated camera", {"type": "object"})}}},
            "/webhook-events": {"get":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"List versioned webhook event types (webhooks:read)","responses":{"200":json_response("Event catalog",{"type":"object","properties":{"version":{"type":"integer"},"events":{"type":"array","items":{"type":"string"}}}})}}},
            "/webhook-settings": {"get":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Read unresolved-reminder preference (administrator)","responses":{"200":json_response("Reminder setting; 24-hour cadence",{"type":"object","properties":{"enabled":{"type":"boolean"},"interval_hours":{"type":"integer","const":24}}})}},"put":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Enable or disable 24-hour unresolved incident reminders (administrator)","requestBody":{"required":True,"content":{"application/json":{"schema":{"type":"object","required":["enabled"],"properties":{"enabled":{"type":"boolean"}}}}}},"responses":{"200":{"description":"Saved"},"403":{"description":"Administrator role required"}}}},
            "/webhooks": {"get":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"List receivers (operators see sanitized configuration; webhooks:read)","responses":{"200":json_response("Receivers without secrets",{"type":"array","items":{"$ref":"#/components/schemas/WebhookReceiver"}})}},"post":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Create receiver (administrator; webhooks:write)","requestBody":body("WebhookReceiverInput"),"responses":{"201":json_response("Created receiver without secret",{"$ref":"#/components/schemas/WebhookReceiver"}),"400":{"description":"Invalid URL, event selection or secret"},"403":{"description":"Administrator role required"}}}},
            "/webhooks/{receiver_id}": {"put":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Update receiver; omit signing_secret to retain it, empty string to clear it","requestBody":body("WebhookReceiverInput"),"responses":{"200":json_response("Updated receiver",{"$ref":"#/components/schemas/WebhookReceiver"})}},"delete":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Delete receiver and delivery history","responses":{"204":{"description":"Deleted"}}}},
            "/webhooks/{receiver_id}/test": {"post":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Send a signed synthetic test event synchronously","responses":{"200":json_response("Sanitized test delivery result",{"$ref":"#/components/schemas/WebhookDelivery"}),"404":{"description":"Receiver not found"}}}},
            "/webhooks/{receiver_id}/deliveries": {"get":{"security":[{"sessionCookie":[]},{"bearerToken":[]}],"summary":"Read up to 200 sanitized delivery outcomes (operators may read)","responses":{"200":json_response("Delivery history without payloads or secrets",{"type":"array","items":{"$ref":"#/components/schemas/WebhookDelivery"}})}}},
        },
    }
    for path, operations in document["paths"].items():
        params = re.findall(r"\{([^}]+)\}", path)
        if params:
            for operation in operations.values():
                if isinstance(operation, dict):
                    declared = {(item.get("name"), item.get("in")) for item in operation.get("parameters", []) if isinstance(item, dict)}
                    operation.setdefault("parameters", []).extend({"name": param, "in": "path", "required": True, "schema": {"type": "string"}} for param in params if (param, "path") not in declared)
    return document


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    if path == "/" and method == "GET":
        return response(start_response, 200, (Path(__file__).parent / "web" / "index.html").read_bytes(), [("Content-Type", "text/html; charset=utf-8")])
    if path == "/app.js" and method == "GET":
        return response(start_response, 200, (Path(__file__).parent / "web" / "app.js").read_bytes(), [("Content-Type", "text/javascript; charset=utf-8")])
    if path == "/styles.css" and method == "GET":
        return response(start_response, 200, (Path(__file__).parent / "web" / "styles.css").read_bytes(), [("Content-Type", "text/css; charset=utf-8")])
    if path == "/docs.js" and method == "GET":
        return response(start_response, 200, (Path(__file__).parent / "web" / "docs.js").read_bytes(), [("Content-Type", "text/javascript; charset=utf-8")])
    if path == "/healthz" and method == "GET":
        return response(start_response, 200, {"status": "ok"})
    if path == "/readyz" and method == "GET":
        try:
            with connect_db() as db:
                db.execute("SELECT 1")
            return response(start_response, 200, {"status": "ready"})
        except sqlite3.Error:
            return response(start_response, 503, {"status": "not_ready"})
    if path == "/openapi.json" and method == "GET":
        return response(start_response, 200, openapi_document())
    if path == "/docs" and method == "GET":
        html = (Path(__file__).parent / "web" / "docs.html").read_bytes()
        return response(start_response, 200, html, [("Content-Type", "text/html; charset=utf-8")])
    if not path.startswith("/api/v1/"):
        return response(start_response, 404, {"error": "not_found"})
    route = path[len("/api/v1/"):]
    query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    body = read_json(environ) if method in ("POST", "PUT", "PATCH") else {}
    if body is None:
        return response(start_response, 400, {"error": "invalid_json"})
    if route == "setup/status" and method == "GET":
        return response(start_response, 200, {"setup_required": not admin_exists()})
    if route == "branding" and method == "GET":
        with connect_db() as db:
            return response(start_response, 200, branding.load(db))
    if route.startswith("branding/assets/"):
        asset_key = route.removeprefix("branding/assets/")
        if asset_key not in branding.ASSET_KEYS:
            return response(start_response, 404, {"error": "not_found"})
        asset_file = branding.asset_path(DATA_DIR, asset_key)
        if method == "GET":
            if not asset_file.is_file():
                return response(start_response, 404, {"error": "not_found"})
            data = asset_file.read_bytes()
            content_type = "image/png" if data.startswith(b"\x89PNG") else "image/jpeg"
            return response(start_response, 200, data, [("Content-Type", content_type), ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "default-src 'none'; sandbox"), ("Cache-Control", "public, max-age=300")])
        principal = current_admin(environ)
        if not principal:
            return response(start_response, 401, {"error": "unauthorized"})
        if not has_role(principal, "administrator"):
            return response(start_response, 403, {"error": "forbidden"})
        if not has_scope(principal, "branding:write"):
            return response(start_response, 403, {"error": "insufficient_scope", "required_scope": "branding:write"})
        if method == "DELETE":
            asset_file.unlink(missing_ok=True)
            with connect_db() as db:
                saved = branding.load(db)
                saved["assets"][asset_key] = None
                db.execute("UPDATE settings SET value_json=? WHERE key='branding'", (json.dumps(saved),))
            audit(principal, "branding.asset.removed", "branding_asset", asset_key)
            return response(start_response, 200, {"asset": asset_key, "url": None})
        if method == "PUT":
            try:
                image, content_type = branding.validate_image(body.get("data"), asset_key)
            except branding.BrandingError as error:
                return response(start_response, 400, {"error": str(error)})
            asset_file.parent.mkdir(parents=True, exist_ok=True)
            temporary = asset_file.with_suffix(".pending")
            temporary.write_bytes(image)
            temporary.replace(asset_file)
            url = f"/api/v1/branding/assets/{asset_key}"
            with connect_db() as db:
                saved = branding.load(db)
                saved["assets"][asset_key] = url
                db.execute("UPDATE settings SET value_json=? WHERE key='branding'", (json.dumps(saved),))
            audit(principal, "branding.asset.updated", "branding_asset", asset_key)
            return response(start_response, 200, {"asset": asset_key, "url": url})
        return response(start_response, 405, {"error": "method_not_allowed"})
    if route == "setup/admin" and method == "POST":
        raw_username, password = body.get("username", ""), body.get("password", "")
        if not isinstance(raw_username, str) or not isinstance(password, str):
            return response(start_response, 400, {"error": "invalid_credentials"})
        username = raw_username.strip()
        if not username or len(username) > 64 or len(password) < 12:
            return response(start_response, 400, {"error": "invalid_credentials", "message": "Use a username and a password with at least 12 characters."})
        digest, salt = hash_password(password)
        try:
            with connect_db() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO admins(id, username, password_hash, salt) VALUES(1, ?, ?, ?)", (username, digest, salt))
        except sqlite3.IntegrityError:
            return response(start_response, 409, {"error": "setup_complete", "message": "An administrator already exists."})
        principal = {"id": 1, "username": username, "role": "administrator"}
        return response(start_response, 201, principal, [("Set-Cookie", issue_session(1))])
    if route == "auth/oidc/login" and method == "GET":
        config = setting("oidc")
        if not config.get("enabled"):
            return response(start_response, 404, {"error": "oidc_disabled"})
        state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        try:
            callback = redirect_uri(environ)
        except ValueError:
            return response(start_response, 500, {"error": "public_url_not_configured"})
        with OIDC_TRANSACTION_LOCK:
            now = time.time()
            for key in [key for key, value in OIDC_TRANSACTIONS.items() if value["expires"] < now]:
                OIDC_TRANSACTIONS.pop(key, None)
            OIDC_TRANSACTIONS[state] = {"nonce": nonce, "verifier": verifier, "redirect_uri": callback, "expires": now + 300}
        try:
            target = oidc.authorization_url(config, callback, state, nonce, verifier)
        except oidc.OIDCError:
            return response(start_response, 502, {"error": "identity_provider_unavailable"})
        correlation_flags = "; HttpOnly; SameSite=Lax; Path=/api/v1/auth/oidc/callback; Max-Age=300" + ("; Secure" if COOKIE_SECURE else "")
        return response(start_response, 302, headers=[("Location", target), ("Set-Cookie", "chm_oidc_state=" + state + correlation_flags)])
    if route == "auth/oidc/status" and method == "GET":
        config = setting("oidc")
        return response(start_response, 200, {"enabled": bool(config.get("enabled")), "button_label": "Sign in with single sign-on"})
    if route == "auth/oidc/callback" and method == "GET":
        query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        state = query.get("state", [""])[0]
        code = query.get("code", [""])[0]
        state_cookie = SimpleCookie()
        state_cookie.load(environ.get("HTTP_COOKIE", ""))
        state_morsel = state_cookie.get("chm_oidc_state")
        with OIDC_TRANSACTION_LOCK:
            transaction = OIDC_TRANSACTIONS.pop(state, None) if state else None
        clear_state = "chm_oidc_state=; HttpOnly; SameSite=Lax; Path=/api/v1/auth/oidc/callback; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")
        if not transaction or not state_morsel or not hmac.compare_digest(state_morsel.value, state) or transaction["expires"] < time.time() or not code or query.get("error"):
            return response(start_response, 400, {"error": "invalid_oidc_callback"}, [("Set-Cookie", clear_state)])
        config = setting("oidc")
        try:
            claims = oidc.exchange_and_validate(config, code, transaction["redirect_uri"], transaction["verifier"], transaction["nonce"])
        except oidc.OIDCError:
            return response(start_response, 401, {"error": "invalid_identity_provider_response"}, [("Set-Cookie", clear_state)])
        role = oidc.mapped_role(claims, config.get("role_claim", "groups"), config.get("administrator_values", []), config.get("operator_values", []))
        if not role:
            return response(start_response, 403, {"error": "user_not_authorized"}, [("Set-Cookie", clear_state)])
        username = claims.get("preferred_username") or claims.get("email") or claims["sub"]
        principal_id = "oidc:" + hashlib.sha256((config["issuer"] + "\0" + claims["sub"]).encode()).hexdigest()[:24]
        cookie = issue_session(username=username, role=role, auth_type="oidc", principal_id=principal_id)
        return response(start_response, 302, headers=[("Location", "/"), ("Set-Cookie", cookie), ("Set-Cookie", clear_state)])
    if route == "auth/login" and method == "POST":
        username, password = body.get("username", ""), body.get("password", "")
        remote = environ.get("REMOTE_ADDR", "unknown")
        with LOGIN_LOCK:
            recent = [attempt for attempt in LOGIN_ATTEMPTS.get(remote, []) if attempt > time.time() - LOGIN_WINDOW_SECONDS]
            if len(recent) >= LOGIN_MAX_ATTEMPTS:
                LOGIN_ATTEMPTS[remote] = recent
                return response(start_response, 429, {"error": "too_many_attempts", "message": "Too many sign-in attempts. Try again later."})
        with connect_db() as db:
            admin = db.execute("SELECT * FROM admins WHERE id=1").fetchone()
        valid = bool(admin and isinstance(username, str) and isinstance(password, str)
                     and hmac.compare_digest(admin["username"], username)
                     and verify_password(password, admin["password_hash"], admin["salt"]))
        with LOGIN_LOCK:
            if valid:
                LOGIN_ATTEMPTS.pop(remote, None)
            else:
                LOGIN_ATTEMPTS[remote] = [*recent, time.time()]
        if not valid:
            return response(start_response, 401, {"error": "invalid_credentials", "message": "Username or password is incorrect."})
        return response(start_response, 200, {"id": 1, "username": admin["username"], "role": "administrator"}, [("Set-Cookie", issue_session(1))])
    if route == "auth/logout" and method == "POST":
        cookie = SimpleCookie(); cookie.load(environ.get("HTTP_COOKIE", ""))
        morsel = cookie.get("chm_session")
        if morsel:
            with SESSION_LOCK:
                SESSIONS.pop(morsel.value, None)
        flags = "; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if COOKIE_SECURE else "")
        return response(start_response, 204, headers=[("Set-Cookie", "chm_session=" + flags)])
    principal = current_admin(environ)
    if route == "auth/me" and method == "GET":
        return response(start_response, 200, principal) if principal else response(start_response, 401, {"error": "unauthorized"})
    if route == "admin/api-tokens" or route.startswith("admin/api-tokens/"):
        if not principal:
            return response(start_response, 401, {"error": "unauthorized"})
        if not has_role(principal, "administrator"):
            return response(start_response, 403, {"error": "forbidden"})
        if not has_scope(principal, "tokens:manage"):
            return response(start_response, 403, {"error": "insufficient_scope", "required_scope": "tokens:manage"})
        if route == "admin/api-tokens" and method == "GET":
            with connect_db() as db:
                rows = db.execute("SELECT id,name,role,scopes_json,created_by,created_at,expires_at,revoked_at FROM api_tokens ORDER BY id DESC").fetchall()
            public = [{"id": row["id"], "name": row["name"], "role": row["role"], "scopes": json.loads(row["scopes_json"]),
                       "created_by": row["created_by"], "created_at": row["created_at"], "expires_at": datetime.fromtimestamp(row["expires_at"], timezone.utc).isoformat() if row["expires_at"] is not None else None, "revoked_at": row["revoked_at"]} for row in rows]
            return response(start_response, 200, public)
        if route == "admin/api-tokens" and method == "POST":
            name, role, scopes = body.get("name"), body.get("role"), body.get("scopes")
            if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80 or not isinstance(role, str) or role not in API_SCOPES or not isinstance(scopes, list) or not scopes or not all(isinstance(scope, str) for scope in scopes):
                return response(start_response, 400, {"error": "invalid_token_configuration"})
            scopes = sorted(set(scopes))
            if not set(scopes).issubset(API_SCOPES[role]):
                return response(start_response, 400, {"error": "invalid_token_scopes", "allowed_scopes": sorted(API_SCOPES[role])})
            try:
                expires_at = token_expiry(body.get("expires_at"))
            except ValueError:
                return response(start_response, 400, {"error": "invalid_expiration"})
            if expires_at is not None and expires_at <= time.time():
                return response(start_response, 400, {"error": "expiration_must_be_future"})
            raw = "chm_at_" + secrets.token_urlsafe(32)
            created_at = datetime.now(timezone.utc).isoformat()
            with connect_db() as db:
                cursor = db.execute("INSERT INTO api_tokens(name,token_hash,role,scopes_json,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
                                    (name.strip(), hashlib.sha256(raw.encode()).hexdigest(), role, json.dumps(scopes), str(principal.get("id")), created_at, expires_at))
                token_id = cursor.lastrowid
            audit(principal, "api_token.created", "api_token", token_id)
            return response(start_response, 201, {"id": token_id, "name": name.strip(), "role": role, "scopes": scopes,
                                                   "created_at": created_at, "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat() if expires_at is not None else None, "token": raw})
        if route.startswith("admin/api-tokens/") and method == "DELETE":
            token_id = route.removeprefix("admin/api-tokens/")
            if not token_id.isdigit():
                return response(start_response, 404, {"error": "not_found"})
            with connect_db() as db:
                changed = db.execute("UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), int(token_id))).rowcount
            if not changed:
                return response(start_response, 404, {"error": "not_found"})
            audit(principal, "api_token.revoked", "api_token", token_id)
            return response(start_response, 204)
        return response(start_response, 405, {"error": "method_not_allowed"})
    if route == "admin/audit" and method == "GET":
        if not principal:
            return response(start_response, 401, {"error": "unauthorized"})
        if not has_role(principal, "administrator"):
            return response(start_response, 403, {"error": "forbidden"})
        if not has_scope(principal, "auth:manage"):
            return response(start_response, 403, {"error": "insufficient_scope", "required_scope": "auth:manage"})
        with connect_db() as db:
            rows = db.execute("SELECT actor_id,actor_name,actor_type,action,resource,resource_id,created_at FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
        return response(start_response, 200, [dict(row) for row in rows])
    scoped_routes = {
        ("dashboard", "GET"): "health:read",
        ("monitoring", "GET"): "health:read",
        ("incidents", "GET"): "health:read",
        ("history", "GET"): "history:read",
        ("branding", "PUT"): "branding:write",
        ("admin/credentials", "PUT"): "auth:manage",
        ("admin/auth/oidc", "GET"): "auth:manage",
        ("admin/auth/oidc", "PUT"): "auth:manage",
    }
    required_scope = scoped_routes.get((route, method))
    if route.startswith("incidents/"):
        required_scope = "incidents:acknowledge" if route.endswith("/acknowledge") and method == "POST" else "health:read"
    if route.startswith("branding/assets/") and method in ("PUT", "DELETE"):
        required_scope = "branding:write"
    if route == "servers" or route.startswith("servers/"):
        required_scope = "servers:read" if method == "GET" else "servers:write"
        if route.endswith(("/discover", "/recording-check")) and method == "POST":
            required_scope = "checks:run"
    if route == "cameras" or route.startswith("cameras/"):
        required_scope = "cameras:read" if method == "GET" else "cameras:write"
    if route.startswith("cameras/") and route.endswith("/live-check") and method == "POST":
        required_scope = "checks:run"
    if route.startswith("cameras/") and route.endswith("/recording-check") and method == "POST":
        required_scope = "checks:run"
    if route.startswith("live-checks/"):
        required_scope = "health:read" if method == "GET" else "checks:run"
    if route.startswith("recording-checks/"):
        required_scope = "health:read"
    if route == "maintenance":
        required_scope = "maintenance:read" if method == "GET" else "maintenance:write"
    if route.startswith("maintenance/"):
        required_scope = "maintenance:write"
    if route.startswith("cameras/") and route.endswith("/exclusion"):
        required_scope = "maintenance:read" if method == "GET" else "maintenance:write"
    if route == "webhooks" or route.startswith("webhooks/"):
        required_scope = "webhooks:read" if method == "GET" else "webhooks:write"
    if route in ("webhook-events","webhook-settings","monitoring/heartbeat"):
        required_scope = "webhooks:read"
        if route == "monitoring/heartbeat" and method == "PUT": required_scope = "webhooks:write"
    if required_scope and principal and not has_scope(principal, required_scope):
        return response(start_response, 403, {"error": "insufficient_scope", "required_scope": required_scope})
    if route == "webhook-events" and method == "GET":
        if not principal:return response(start_response,401,{"error":"unauthorized"})
        return response(start_response,200,{"version":1,"events":list(WEBHOOK_EVENTS)})
    if route == "webhook-settings":
        if not principal:return response(start_response,401,{"error":"unauthorized"})
        if not has_role(principal,"administrator"):return response(start_response,403,{"error":"forbidden"})
        if method=="GET":return response(start_response,200,setting("webhook_reminders"))
        if method=="PUT":
            enabled=body.get("enabled")
            if not isinstance(enabled,bool):return response(start_response,400,{"error":"invalid_enabled"})
            value={"enabled":enabled,"interval_hours":24};save_setting("webhook_reminders",value);audit(principal,"webhook.reminders.updated","webhook_settings")
            return response(start_response,200,value)
        return response(start_response,405,{"error":"method_not_allowed"})
    if route == "monitoring/heartbeat":
        if not principal: return response(start_response,401,{"error":"unauthorized"})
        if not has_role(principal,"administrator"): return response(start_response,403,{"error":"forbidden"})
        if method == "GET":
            value=setting("monitoring_heartbeat")
            return response(start_response,200,{key:value.get(key) for key in ("enabled","receiver_id","interval_seconds")})
        if method == "PUT":
            enabled=body.get("enabled")
            receiver_id=body.get("receiver_id")
            interval=body.get("interval_seconds",300)
            if not isinstance(enabled,bool) or not isinstance(interval,int) or isinstance(interval,bool) or not 60<=interval<=86400 or (enabled and not isinstance(receiver_id,str)):
                return response(start_response,400,{"error":"invalid_heartbeat_configuration"})
            if enabled:
                with connect_db() as db:
                    receiver=db.execute("SELECT enabled,events_json FROM webhook_receivers WHERE id=?",(receiver_id,)).fetchone()
                if not receiver or not receiver["enabled"] or "monitoring.heartbeat" not in json.loads(receiver["events_json"]):
                    return response(start_response,400,{"error":"heartbeat_receiver_must_enable_event","required_event":"monitoring.heartbeat"})
            value={"enabled":enabled,"receiver_id":receiver_id if enabled else None,"interval_seconds":interval,"last_sent_epoch":None}
            save_setting("monitoring_heartbeat",value);audit(principal,"monitoring.heartbeat.updated","monitoring_heartbeat")
            return response(start_response,200,{key:value.get(key) for key in ("enabled","receiver_id","interval_seconds")})
        return response(start_response,405,{"error":"method_not_allowed"})
    if route == "webhooks" or route.startswith("webhooks/"):
        if not principal:return response(start_response,401,{"error":"unauthorized"})
        if method == "GET":
            if not has_role(principal,"operator"):return response(start_response,403,{"error":"forbidden"})
            parts=route.split("/")
            with connect_db() as db:
                if len(parts)==1:
                    rows=db.execute("SELECT * FROM webhook_receivers ORDER BY created_at,name").fetchall()
                    return response(start_response,200,[webhook_public(row) for row in rows])
                if len(parts)==3 and parts[2]=="deliveries":
                    if not db.execute("SELECT 1 FROM webhook_receivers WHERE id=?",(parts[1],)).fetchone():return response(start_response,404,{"error":"not_found"})
                    rows=db.execute("SELECT * FROM webhook_deliveries WHERE receiver_id=? ORDER BY id DESC LIMIT 200",(parts[1],)).fetchall()
                    return response(start_response,200,[safe_delivery(row) for row in rows])
        if not has_role(principal,"administrator"):return response(start_response,403,{"error":"forbidden"})
        parts=route.split("/")
        if route=="webhooks" and method=="POST":
            name,url,events,secret=body.get("name"),body.get("url"),body.get("events"),body.get("signing_secret","")
            enabled=body.get("enabled",True)
            if not isinstance(name,str) or not name.strip() or len(name.strip())>100 or not safe_receiver_url(url):return response(start_response,400,{"error":"invalid_receiver"})
            if not isinstance(events,list) or not events or len(set(events))!=len(events) or any(event not in WEBHOOK_EVENTS for event in events):return response(start_response,400,{"error":"invalid_events","allowed":list(WEBHOOK_EVENTS)})
            if not isinstance(secret,str) or (secret and not 16<=len(secret)<=256):return response(start_response,400,{"error":"invalid_signing_secret"})
            if not isinstance(enabled,bool):return response(start_response,400,{"error":"invalid_enabled"})
            receiver_id,now=str(uuid.uuid4()),utc_now();cipher=credential_cipher().encrypt(secret.encode()).decode() if secret else ""
            with connect_db() as db:
                db.execute("INSERT INTO webhook_receivers(id,name,url,events_json,secret_ciphertext,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(receiver_id,name.strip(),url,json.dumps(events),cipher,int(enabled),now,now))
                row=db.execute("SELECT * FROM webhook_receivers WHERE id=?",(receiver_id,)).fetchone()
            audit(principal,"webhook.created","webhook",receiver_id)
            return response(start_response,201,webhook_public(row))
        if len(parts)==3 and parts[2]=="test" and method=="POST":
            with connect_db() as db:
                receiver=db.execute("SELECT * FROM webhook_receivers WHERE id=?",(parts[1],)).fetchone()
                if not receiver:return response(start_response,404,{"error":"not_found"})
                event_id,now=str(uuid.uuid4()),utc_now()
                payload={"id":event_id,"version":1,"type":"test","created_at":now,"data":{"message":"Receiver test delivery"}}
                db.execute("INSERT INTO event_outbox(event_id,event_type,payload_json,created_at) VALUES(?,'test',?,?)",(event_id,json.dumps(payload),now))
                db.execute("INSERT INTO webhook_deliveries(receiver_id,event_id,event_type,state,created_at,updated_at) VALUES(?,?, 'test','pending',?,?)",(parts[1],event_id,now,now))
                delivery_id=db.execute("SELECT last_insert_rowid()").fetchone()[0]
            dispatch_webhook_delivery(delivery_id)
            with connect_db() as db: delivery=db.execute("SELECT * FROM webhook_deliveries WHERE id=?",(delivery_id,)).fetchone()
            return response(start_response,200,safe_delivery(delivery))
        if len(parts)==2 and method in ("PUT","DELETE"):
            with connect_db() as db:
                current=db.execute("SELECT * FROM webhook_receivers WHERE id=?",(parts[1],)).fetchone()
                if not current:return response(start_response,404,{"error":"not_found"})
                if method=="DELETE":
                    db.execute("DELETE FROM webhook_receivers WHERE id=?",(parts[1],));audit(principal,"webhook.deleted","webhook",parts[1],db)
                    return response(start_response,204)
                name,url,events=body.get("name",current["name"]),body.get("url",current["url"]),body.get("events",json.loads(current["events_json"]))
                secret=body.get("signing_secret");enabled=body.get("enabled",bool(current["enabled"]))
                if not isinstance(name,str) or not name.strip() or len(name.strip())>100 or not safe_receiver_url(url):return response(start_response,400,{"error":"invalid_receiver"})
                if not isinstance(events,list) or not events or len(set(events))!=len(events) or any(event not in WEBHOOK_EVENTS for event in events):return response(start_response,400,{"error":"invalid_events"})
                if secret is not None and (not isinstance(secret,str) or (secret and not 16<=len(secret)<=256)):return response(start_response,400,{"error":"invalid_signing_secret"})
                if not isinstance(enabled,bool):return response(start_response,400,{"error":"invalid_enabled"})
                cipher=current["secret_ciphertext"] if secret is None else credential_cipher().encrypt(secret.encode()).decode() if secret else ""
                now=utc_now();db.execute("UPDATE webhook_receivers SET name=?,url=?,events_json=?,secret_ciphertext=?,enabled=?,updated_at=? WHERE id=?",(name.strip(),url,json.dumps(events),cipher,int(enabled),now,parts[1]))
                row=db.execute("SELECT * FROM webhook_receivers WHERE id=?",(parts[1],)).fetchone();audit(principal,"webhook.updated","webhook",parts[1],db)
            return response(start_response,200,webhook_public(row))
        return response(start_response,405,{"error":"method_not_allowed"})
    if route == "monitoring" and method == "GET":
        if not principal:
            return response(start_response, 401, {"error": "unauthorized"})
        if not has_role(principal, "operator"):
            return response(start_response, 403, {"error": "forbidden"})
        if not has_scope(principal, "health:read"):
            return response(start_response, 403, {"error": "insufficient_scope", "required_scope": "health:read"})
        with connect_db() as db:
            cameras = db.execute("SELECT c.*,s.enabled AS server_enabled,s.adapter,s.fixture_profile,s.name AS server_name FROM cameras c JOIN servers s ON s.id=c.server_id WHERE c.disappeared=0 ORDER BY s.name,c.name").fetchall()
        scheduler_view = MONITORING_SCHEDULE or MonitoringSchedule(DB_PATH)
        schedule_rows = scheduler_view.snapshot()
        existing_schedule_cameras = {row["camera_id"] for row in schedule_rows}
        missing_cameras = [{"id": row["id"], "settings": json.loads(row["settings_json"])} for row in cameras if row["id"] not in existing_schedule_cameras]
        if missing_cameras:
            scheduler_view.synchronize(missing_cameras, now=monitoring_now())
            schedule_rows = scheduler_view.snapshot()
        schedules = {(row["camera_id"], row["check_type"]): row for row in schedule_rows}
        camera_statuses = []
        for row in cameras:
            camera = dict(row)
            settings = json.loads(camera["settings_json"])
            public_camera = camera_public(camera)
            live = public_camera["live_status"]
            recording = public_camera["recording_status"]
            schedule = {}
            for check_type, interval_key in (("live", "live_interval_minutes"), ("recording", "recording_interval_minutes")):
                item = schedules.get((camera["id"], check_type))
                schedule[check_type] = {"interval_seconds": settings[interval_key] * 60,
                                        "next_due_at": datetime.fromtimestamp(item["next_due_at"], timezone.utc).isoformat() if item else None,
                                        "last_started_at": datetime.fromtimestamp(item["last_started_at"], timezone.utc).isoformat() if item and item["last_started_at"] else None,
                                        "last_completed_at": datetime.fromtimestamp(item["last_completed_at"], timezone.utc).isoformat() if item and item["last_completed_at"] else None}
            current = {}
            for check_type, result in (("live", live), ("recording", recording)):
                state = result.get("state", "not_checked")
                if state in ("not_checked", "current"):
                    state = result.get("health", "unknown")
                current[check_type] = {"state": state, "current_health": result.get("health", "unknown"),
                                       "checked_at": result.get("checked_at"), "last_success_at": result.get("last_success_at")}
            with CAMERA_WORK_LOCK:
                active_id = CAMERA_WORK_BY_CAMERA.get(camera["id"])
            camera_statuses.append({"camera_id": camera["id"], "camera_name": camera["name"], "server_id": camera["server_id"],
                                    "server_name": camera["server_name"], "intervals_seconds": {key: value["interval_seconds"] for key, value in schedule.items()},
                                    "next_due_at": {key: value["next_due_at"] for key, value in schedule.items()},
                                    "last_execution": {key: value["last_completed_at"] for key, value in schedule.items()},
                                    "active_job_id": active_id, "execution_state": public_camera.get("monitoring", {}),
                                    "live": current["live"], "recording": current["recording"]})
        tick_seconds = max(0.25, float(os.environ.get("CHM_SCHEDULER_TICK_SECONDS", "1")))
        diagnostics = monitor_health()
        return response(start_response, 200, {"monitor": diagnostics,
                                                    "scheduler": {"running": bool(MONITORING_LAST_TICK and time.time() - MONITORING_LAST_TICK < tick_seconds * 3 and os.environ.get("CHM_SCHEDULER_ENABLED", "true").lower() != "false"),
                                                              "tick_seconds": max(0.25, float(os.environ.get("CHM_SCHEDULER_TICK_SECONDS", "1"))),
                                                              "last_tick_at": datetime.fromtimestamp(MONITORING_LAST_TICK, timezone.utc).isoformat() if MONITORING_LAST_TICK else None,
                                                              "live_failure_confirmation_seconds": 30},
                                                    "cameras": camera_statuses})
    if route == "admin/auth/oidc":
        if not principal: return response(start_response, 401, {"error": "unauthorized"})
        if not has_role(principal, "administrator"): return response(start_response, 403, {"error": "forbidden"})
        if method == "GET": return response(start_response, 200, public_oidc_config(setting("oidc")))
        if method == "PUT":
            issuer, client_id, secret = body.get("issuer", ""), body.get("client_id", ""), body.get("client_secret", "")
            claim, admins, operators, enabled = body.get("role_claim", "groups"), body.get("administrator_values", []), body.get("operator_values", []), body.get("enabled", True)
            if not all(isinstance(v, str) for v in (issuer, client_id, secret, claim)) or not claim or len(claim)>128 or not isinstance(admins,list) or not all(isinstance(v,str) and v for v in admins) or not isinstance(operators,list) or not all(isinstance(v,str) and v for v in operators) or not isinstance(enabled,bool): return response(start_response,400,{"error":"invalid_oidc_configuration"})
            previous=setting("oidc"); secret=secret or previous.get("client_secret", "")
            if enabled and (not issuer or not client_id or not secret or not admins and not operators): return response(start_response,400,{"error":"incomplete_oidc_configuration"})
            updated={"enabled":enabled,"issuer":issuer,"client_id":client_id,"client_secret":secret,"role_claim":claim,"administrator_values":admins,"operator_values":operators}
            if enabled:
                try: oidc.discover(issuer)
                except oidc.OIDCError: return response(start_response,400,{"error":"invalid_oidc_issuer"})
            save_setting("oidc",updated); audit(principal, "auth.oidc.updated", "oidc")
            return response(start_response,200,public_oidc_config(updated))
    is_server_route = route == "servers" or route.startswith("servers/")
    is_camera_route = route == "cameras" or route.startswith("cameras/")
    is_incident_route = route == "incidents" or route.startswith("incidents/") or route == "history"
    is_live_check_route = route.startswith("live-checks/")
    is_recording_check_route = route.startswith("recording-checks/")
    if route in ("dashboard", "monitoring", "incidents", "history", "maintenance", "admin/credentials", "branding", "branding/assets") or route.startswith("maintenance/") or is_server_route or is_camera_route or is_incident_route or is_live_check_route or is_recording_check_route:
        if not principal:
            return response(start_response, 401, {"error": "unauthorized"})
        server_config_mutation = (route == "servers" and method == "POST") or (route.startswith("servers/") and method != "GET" and not route.endswith(("/discover", "/recording-check")))
        admin_mutation = route in ("admin/credentials", "branding", "branding/assets") or server_config_mutation or route == "maintenance" and method == "POST" or route.startswith("maintenance/") and method != "GET" or (route.startswith("cameras/") and method == "PUT")
        if admin_mutation and not has_role(principal, "administrator"):
            return response(start_response, 403, {"error": "forbidden"})
        if route.startswith("incidents/") and method == "POST" and not has_role(principal, "operator"):
            return response(start_response, 403, {"error": "forbidden"})
        if route in ("incidents", "history", "maintenance") and not has_role(principal, "operator"):
            return response(start_response, 403, {"error": "forbidden"})
        if route.startswith("cameras/") and route.endswith("/exclusion") and not has_role(principal,"operator"):
            return response(start_response,403,{"error":"forbidden"})
        if route in ("incidents", "history") or route.startswith("incidents/"):
            if route == "incidents" and method == "GET":
                status_filter = query.get("status", ["open"])[0]
                if status_filter not in ("open", "resolved", "all"):
                    return response(start_response, 400, {"error": "invalid_status"})
                with connect_db() as db:
                    if status_filter == "all":
                        rows = db.execute("SELECT * FROM monitoring_incidents ORDER BY updated_at DESC LIMIT 1000").fetchall()
                    else:
                        rows = db.execute("SELECT * FROM monitoring_incidents WHERE status=? ORDER BY updated_at DESC LIMIT 1000", (status_filter,)).fetchall()
                    result = [incident_public(row, db) for row in rows]
                return response(start_response, 200, result)
            if route == "history" and method == "GET":
                try:
                    days = int(query.get("days", ["90"])[0])
                except (TypeError, ValueError):
                    days = 0
                if not 1 <= days <= 90:
                    return response(start_response, 400, {"error": "invalid_days", "maximum": 90})
                cutoff = datetime.fromtimestamp(time.time() - days * 86400, timezone.utc).isoformat()
                with connect_db() as db:
                    rows = db.execute("SELECT * FROM monitoring_incidents WHERE status='open' OR updated_at>=? ORDER BY updated_at DESC LIMIT 2000", (cutoff,)).fetchall()
                    result = [incident_public(row, db) for row in rows]
                return response(start_response, 200, {"days": days, "incidents": result})
            parts = route.split("/")
            incident_id = parts[1] if len(parts) > 1 else ""
            if len(parts) == 2 and method == "GET":
                with connect_db() as db:
                    row = db.execute("SELECT * FROM monitoring_incidents WHERE id=?", (incident_id,)).fetchone()
                    if row:
                        item = incident_public(row, db)
                    else:
                        item = None
                return response(start_response, 200, item) if item else response(start_response, 404, {"error": "not_found"})
            if len(parts) == 3 and parts[2] == "acknowledge" and method == "POST":
                with connect_db() as db:
                    row = db.execute("SELECT * FROM monitoring_incidents WHERE id=?", (incident_id,)).fetchone()
                    if not row:
                        return response(start_response, 404, {"error": "not_found"})
                    if row["status"] != "open":
                        return response(start_response, 409, {"error": "incident_resolved"})
                    if row["acknowledged_at"]:
                        item = incident_public(row, db)
                    else:
                        now = utc_now()
                        reviewer = principal.get("username") or str(principal.get("id"))
                        db.execute("UPDATE monitoring_incidents SET acknowledged_at=?,acknowledged_by=?,updated_at=? WHERE id=? AND status='open'",
                                   (now, reviewer, now, incident_id))
                        db.execute("INSERT INTO incident_transitions(incident_id,event,from_state,to_state,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",
                                   (incident_id, "acknowledged", "open", "open", "reviewed", reviewer, now))
                        item = incident_public(db.execute("SELECT * FROM monitoring_incidents WHERE id=?", (incident_id,)).fetchone(), db)
                audit(principal, "incident.acknowledged", "incident", incident_id)
                return response(start_response, 200, item)
        if route == "maintenance" and method == "GET":
            with connect_db() as db:
                expire_maintenance(db)
                rows = db.execute("SELECT * FROM maintenance_windows ORDER BY starts_at DESC LIMIT 1000").fetchall()
            now = monitoring_now()
            return response(start_response, 200, [maintenance_public(row, now) for row in rows])
        if route == "maintenance" and method == "POST":
            entity_type, entity_id = body.get("entity_type"), body.get("entity_id")
            reason, starts_at, ends_at = body.get("reason"), body.get("starts_at"), body.get("ends_at")
            start_dt, end_dt = parse_utc_timestamp(starts_at), parse_utc_timestamp(ends_at)
            now_dt = datetime.fromtimestamp(monitoring_now(), timezone.utc)
            if (entity_type not in ("camera", "server") or not isinstance(entity_id, str) or not entity_id.strip()
                    or not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 500
                    or not start_dt or not end_dt or end_dt <= start_dt or end_dt <= now_dt):
                return response(start_response, 400, {"error": "invalid_maintenance", "message": "Provide a camera/server scope, a reason (1–500 characters), and ISO-8601 start/end values with end in the future and after start."})
            now_text = now_dt.isoformat()
            with connect_db() as db:
                expire_maintenance(db)
                if entity_type == "camera":
                    exists = db.execute("SELECT 1 FROM cameras WHERE id=?", (entity_id,)).fetchone()
                else:
                    exists = db.execute("SELECT 1 FROM servers WHERE id=?", (entity_id,)).fetchone()
                if not exists:
                    return response(start_response, 404, {"error": f"{entity_type}_not_found"})
                duplicate = db.execute("SELECT * FROM maintenance_windows WHERE entity_type=? AND entity_id=? AND starts_at=? AND ends_at=?",
                                       (entity_type, entity_id, start_dt.isoformat(), end_dt.isoformat())).fetchone()
                if duplicate:
                    return response(start_response, 200, maintenance_public(duplicate, monitoring_now()))
                overlap = db.execute("SELECT 1 FROM maintenance_windows WHERE entity_type=? AND entity_id=? AND ended_at IS NULL AND starts_at<? AND ends_at>? LIMIT 1",
                                     (entity_type, entity_id, end_dt.isoformat(), start_dt.isoformat())).fetchone()
                if overlap:
                    return response(start_response, 409, {"error": "maintenance_overlap"})
                window_id = str(uuid.uuid4())
                db.execute("INSERT INTO maintenance_windows(id,entity_type,entity_id,reason,starts_at,ends_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                           (window_id, entity_type, entity_id, reason.strip(), start_dt.isoformat(), end_dt.isoformat(), now_text, now_text))
                if start_dt.timestamp() <= monitoring_now():
                    suppress_open_incidents(db,entity_type,entity_id,now_text,principal.get("username"))
                row = db.execute("SELECT * FROM maintenance_windows WHERE id=?", (window_id,)).fetchone()
                audit(principal, "maintenance.created", "maintenance", window_id, db)
            return response(start_response, 201, maintenance_public(row, monitoring_now()))
        if route.startswith("maintenance/") and method == "DELETE":
            window_id = route.split("/", 1)[1]
            now_text = datetime.fromtimestamp(monitoring_now(), timezone.utc).isoformat()
            with connect_db() as db:
                row = db.execute("SELECT * FROM maintenance_windows WHERE id=?", (window_id,)).fetchone()
                if not row:
                    return response(start_response, 404, {"error": "maintenance_not_found"})
                if row["ended_at"] is None:
                    db.execute("UPDATE maintenance_windows SET ended_at=?,updated_at=? WHERE id=?", (now_text, now_text, window_id))
                    reevaluate_latest_health(db, row["entity_type"], row["entity_id"], now_text, principal.get("username"))
                audit(principal, "maintenance.ended", "maintenance", window_id, db)
                updated = db.execute("SELECT * FROM maintenance_windows WHERE id=?", (window_id,)).fetchone()
            return response(start_response, 200, maintenance_public(updated, monitoring_now()))
        if route.startswith("cameras/") and route.endswith("/exclusion"):
            camera_id = route.split("/")[1]
            if method == "GET":
                with connect_db() as db:
                    expire_maintenance(db)
                    camera = db.execute("SELECT id FROM cameras WHERE id=?", (camera_id,)).fetchone()
                    if not camera: return response(start_response, 404, {"error":"camera_not_found"})
                    row = db.execute("SELECT * FROM camera_exclusions WHERE camera_id=?", (camera_id,)).fetchone()
                return response(start_response, 200, {"camera_id":camera_id,"excluded":bool(row),"reason":row["reason"] if row else None,"updated_at":row["updated_at"] if row else None})
            if method == "PUT":
                excluded, reason = body.get("excluded"), body.get("reason", "")
                if not isinstance(excluded, bool) or not isinstance(reason, str) or (excluded and (not reason.strip() or len(reason.strip()) > 500)) or len(reason) > 500:
                    return response(start_response, 400, {"error":"invalid_exclusion", "message":"excluded must be boolean; an active exclusion requires a 1–500 character reason."})
                now_text = datetime.fromtimestamp(monitoring_now(), timezone.utc).isoformat()
                with connect_db() as db:
                    camera = db.execute("SELECT id,server_id FROM cameras WHERE id=?", (camera_id,)).fetchone()
                    if not camera: return response(start_response, 404, {"error":"camera_not_found"})
                    if excluded:
                        db.execute("INSERT INTO camera_exclusions(camera_id,reason,created_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(camera_id) DO UPDATE SET reason=excluded.reason,updated_at=excluded.updated_at", (camera_id,reason.strip(),now_text,now_text))
                        suppress_open_incidents(db,"camera",camera_id,now_text,principal.get("username"))
                    else:
                        db.execute("DELETE FROM camera_exclusions WHERE camera_id=?", (camera_id,))
                        reevaluate_latest_health(db, "camera", camera_id, now_text, principal.get("username"))
                    audit(principal,"camera.exclusion.updated","camera",camera_id,db)
                    row=db.execute("SELECT * FROM camera_exclusions WHERE camera_id=?",(camera_id,)).fetchone()
                SCHEDULER_WAKE.set()
                return response(start_response,200,{"camera_id":camera_id,"excluded":bool(row),"reason":row["reason"] if row else None,"updated_at":row["updated_at"] if row else None})
        if route == "admin/credentials" and principal.get("auth_type") != "local": return response(start_response,403,{"error":"local_admin_required"})
        if route == "servers" and method == "GET":
            with connect_db() as db:
                rows = db.execute("SELECT * FROM servers ORDER BY name COLLATE NOCASE").fetchall()
            return response(start_response, 200, [server_public(row) for row in rows])
        if route == "servers" and method == "POST":
            with connect_db() as db:
                server_id = create_server(db, body)
                if not server_id:
                    return response(start_response, 400, {"error": "invalid_server", "message": "Check server name, host, port, credentials and adapter. Fixture mode is disabled unless CHM_ENABLE_FIXTURE=true."})
                row = db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
                audit(principal, "server.created", "server", server_id, db)
            return response(start_response, 201, server_public(row))
        if route == "cameras" and method == "GET":
            with connect_db() as db:
                rows = db.execute("SELECT * FROM cameras ORDER BY server_id, remote_id").fetchall()
            return response(start_response, 200, [camera_public(row) for row in rows])
        if route.startswith("cameras/") and route.endswith("/live-check") and method == "POST":
            camera_id = route.split("/")[1]
            with connect_db() as db:
                camera = db.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
                if not camera:
                    return response(start_response, 404, {"error": "camera_not_found"})
                server = db.execute("SELECT * FROM servers WHERE id=?", (camera["server_id"],)).fetchone()
                if not server or not server["enabled"] or camera["disappeared"]:
                    return response(start_response, 409, {"error": "camera_unavailable", "message": "The camera or its recorder is disabled or no longer present."})
                if server["adapter"] != "fixture":
                    return response(start_response, 501, {"error": "integration_unverified", "message": "Live sample retrieval cannot run until the installed ExacqVision interface contract is validated."})
                job, active_id, error = start_live_check(dict(camera), dict(server))
            if error == "duplicate":
                return response(start_response, 409, {"error": "check_already_running", "job_id": active_id})
            if error == "capacity":
                return response(start_response, 429, {"error": "check_capacity_reached", "message": "All live-check worker slots are occupied. Retry later."})
            audit(principal, "live_check.started", "live_check", job["id"])
            return response(start_response, 202, live_check_public(job), [("Location", f"/api/v1/live-checks/{job['id']}")])
        if route.startswith("cameras/") and route.endswith("/recording-check") and method == "POST":
            camera_id = route.split("/")[1]
            with connect_db() as db:
                camera = db.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
                if not camera: return response(start_response, 404, {"error": "camera_not_found"})
                server = db.execute("SELECT * FROM servers WHERE id=?", (camera["server_id"],)).fetchone()
                if not server or not server["enabled"] or camera["disappeared"]:
                    return response(start_response, 409, {"error": "camera_unavailable", "message": "The camera or its recorder is disabled or no longer present."})
                if server["adapter"] != "fixture":
                    return response(start_response, 501, {"error": "integration_unverified", "message": "Recording search and recorded playback are unverified for the installed Exacq interface; no recorder request was attempted."})
                job, active_id, error = start_recording_check(dict(camera), dict(server))
            if error == "duplicate": return response(start_response, 409, {"error": "check_already_running", "job_id": active_id})
            if error == "capacity": return response(start_response, 429, {"error": "check_capacity_reached", "message": "All recording-check worker slots are occupied. Retry later."})
            return response(start_response, 202, recording_check_public(job), [("Location", f"/api/v1/recording-checks/{job['id']}")])
        if route.startswith("recording-checks/") and method == "GET":
            with RECORDING_CHECK_LOCK:
                job = RECORDING_CHECKS.get(route.split("/", 1)[1])
                return response(start_response, 200, recording_check_public(job)) if job else response(start_response, 404, {"error": "recording_check_not_found"})
        if route.startswith("servers/") and route.endswith("/recording-check") and method == "POST":
            server_id = route.split("/")[1]
            with connect_db() as db:
                server = db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
                if not server: return response(start_response, 404, {"error": "server_not_found"})
                if not server["enabled"]: return response(start_response, 409, {"error": "server_disabled"})
                if server["adapter"] != "fixture": return response(start_response, 501, {"error": "integration_unverified", "message": "Recording search and playback are unverified; no recorder request was attempted."})
                cameras = db.execute("SELECT * FROM cameras WHERE server_id=? AND disappeared=0 ORDER BY remote_id", (server_id,)).fetchall()
            jobs = []
            for camera in cameras:
                job, active_id, error = start_recording_check(dict(camera), dict(server))
                if job: jobs.append(recording_check_public(job))
                elif error == "duplicate":
                    active_recording = RECORDING_CHECKS.get(active_id)
                    jobs.append(recording_check_public(active_recording) if active_recording else
                                 {"camera_id": camera["id"], "status": "conflict", "active_job_id": active_id})
                elif error == "capacity": return response(start_response, 429, {"error": "check_capacity_reached", "jobs": jobs})
            return response(start_response, 202, {"server_id": server_id, "jobs": jobs})
        if route.startswith("live-checks/"):
            job_id = route.split("/", 1)[1]
            with LIVE_CHECK_LOCK:
                job = LIVE_CHECKS.get(job_id)
                if not job:
                    return response(start_response, 404, {"error": "live_check_not_found"})
                if method == "DELETE":
                    if job["status"] in ("succeeded", "failed", "cancelled", "unsupported"):
                        return response(start_response, 409, {"error": "check_not_active"})
                    job["cancel_event"].set()
                    process = job.get("process")
                    if process and process.poll() is None:
                        process.terminate()
                    audit(principal, "live_check.cancelled", "live_check", job_id)
                    return response(start_response, 202, live_check_public(job))
                if method == "GET":
                    return response(start_response, 200, live_check_public(job))
        if route.startswith("cameras/") and method == "PUT":
            camera_id, overrides = route.split("/", 1)[1], body.get("overrides")
            overrides = validate_camera_overrides(overrides)
            if overrides is None:
                return response(start_response, 400, {"error": "invalid_overrides"})
            with connect_db() as db:
                row = db.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
                if not row:
                    return response(start_response, 404, {"error": "camera_not_found"})
                server = db.execute("SELECT defaults_json FROM servers WHERE id=?", (row["server_id"],)).fetchone()
                defaults = json.loads(server["defaults_json"]) if server else default_camera_settings()
                settings = {**defaults, **overrides}
                db.execute("UPDATE cameras SET overrides_json=?, settings_json=? WHERE id=?", (json.dumps(overrides), json.dumps(settings), camera_id))
                row = db.execute("SELECT * FROM cameras WHERE id=?", (camera_id,)).fetchone()
                audit(principal, "camera.overrides.updated", "camera", camera_id, db)
                SCHEDULER_WAKE.set()
            return response(start_response, 200, camera_public(row))
        if route.startswith("servers/"):
            parts = route.split("/")
            server_id, action = parts[1], (parts[2] if len(parts) > 2 else "")
            with connect_db() as db:
                row = db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
                if not row:
                    return response(start_response, 404, {"error": "server_not_found"})
                if not action and method == "GET":
                    return response(start_response, 200, server_public(row))
                if not action and method == "PUT":
                    existing = dict(row)
                    name, host, port = body.get("name", existing["name"]), body.get("host", existing["host"]), body.get("port", existing["port"])
                    username = body.get("username", existing["username"])
                    if username == "": username = existing["username"]
                    password = body.get("password", "")
                    enabled = body.get("enabled", bool(existing["enabled"]))
                    profile = body.get("fixture_profile", existing["fixture_profile"])
                    defaults = validate_camera_settings(body.get("defaults", json.loads(existing["defaults_json"])))
                    if (not isinstance(name, str) or not name.strip() or len(name.strip()) > 100
                            or not isinstance(host, str) or not host.strip() or len(host.strip()) > 253
                            or any(c.isspace() for c in host.strip()) or "://" in host
                            or (port is not None and (type(port) is not int or not 1 <= port <= 65535))
                            or not isinstance(username, str) or not isinstance(password, str) or not isinstance(enabled, bool)
                            or profile not in ("success", "discovery_error", "no_cameras", "capability_error", "invalid_media", "live_slow", "live_timeout", "live_flaky", "recording_none", "recording_success", "recording_invalid_media", "recording_permission_error", "recording_search_error", "recording_boundary", "server_unavailable") or defaults is None):
                        return response(start_response, 400, {"error": "invalid_server"})
                    cipher = credential_cipher().encrypt(password.encode()).decode() if password else existing["password_ciphertext"]
                    db.execute("UPDATE servers SET name=?,host=?,port=?,username=?,password_ciphertext=?,enabled=?,fixture_profile=?,defaults_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                               (name.strip(), host.strip(), port, username, cipher, int(enabled), profile, json.dumps(defaults), server_id))
                    for camera_row in db.execute("SELECT id,overrides_json FROM cameras WHERE server_id=?", (server_id,)).fetchall():
                        overrides = json.loads(camera_row["overrides_json"])
                        db.execute("UPDATE cameras SET settings_json=? WHERE id=?", (json.dumps({**defaults, **overrides}), camera_row["id"]))
                    audit(principal, "server.updated", "server", server_id, db)
                    SCHEDULER_WAKE.set()
                    return response(start_response, 200, server_public(db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()))
                if not action and method == "DELETE":
                    db.execute("DELETE FROM servers WHERE id=?", (server_id,))
                    audit(principal, "server.deleted", "server", server_id, db)
                    return response(start_response, 204)
                if action == "discover" and method == "POST":
                    result, status = discover_server(db, row)
                    audit(principal, "server.discovery.requested", "server", server_id, db)
                    SCHEDULER_WAKE.set()
                    return response(start_response, status, result)
                if action == "capabilities" and method in ("GET", "POST"):
                    capabilities = json.loads(row["capabilities_json"])
                    if method == "POST" and row["adapter"] == "fixture" and row["fixture_profile"] == "capability_error":
                        capabilities["live_delivery"] = {"status": "failed", "detail": "Fixture capability probe failed: simulated provider returned an authorization error. This is fixture behavior, not Exacq evidence."}
                        db.execute("UPDATE servers SET capabilities_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (json.dumps(capabilities), server_id))
                    elif method == "POST" and row["adapter"] == "fixture":
                        capabilities["live_delivery"] = {"status": "untested", "detail": "Fixture does not simulate live video decoding."}
                        capabilities["recording_search"] = {"status": "untested", "detail": "Fixture does not simulate recording search."}
                        capabilities["recorded_playback"] = {"status": "untested", "detail": "Fixture does not simulate recorded video decoding."}
                        db.execute("UPDATE servers SET capabilities_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (json.dumps(capabilities), server_id))
                    if method == "POST": audit(principal, "server.capabilities.probed", "server", server_id, db)
                    return response(start_response, 200, {"server_id": server_id, "capabilities": capabilities})
        if route == "dashboard" and method == "GET":
            with connect_db() as db:
                shared_branding = branding.load(db)
                servers = [server_public(row) for row in db.execute("SELECT * FROM servers ORDER BY name COLLATE NOCASE").fetchall()]
                cameras = [camera_public(row) for row in db.execute("SELECT * FROM cameras ORDER BY server_id, remote_id").fetchall()]
                incidents = [incident_public(row, db) for row in db.execute("SELECT * FROM monitoring_incidents WHERE status='open' ORDER BY severity DESC,updated_at DESC").fetchall()]
            return response(start_response, 200, {"principal": principal, "servers": servers, "cameras": cameras, "incidents": incidents, "monitor": monitor_health(), "summary": {"servers": len(servers), "cameras": len(cameras), "healthy": sum(1 for c in cameras if c["live_status"].get("health")=="healthy" and c["recording_status"].get("health")=="healthy"), "warnings": sum(1 for i in incidents if i["severity"]=="warning"), "failures": sum(1 for i in incidents if i["severity"]=="failure"), "monitoring": sum(1 for i in incidents if i["severity"]=="monitoring"), "unknown": sum(1 for c in cameras if "unknown" in (c["live_status"].get("health"),c["recording_status"].get("health")))}, "branding": shared_branding})
        if route == "branding" and method == "PUT":
            try:
                clean = branding.validate(body)
                uploads = body.get("asset_uploads", {})
                if not isinstance(uploads, dict) or not set(uploads).issubset(branding.ASSET_KEYS):
                    raise branding.BrandingError("invalid_image")
                staged = {key: (None if encoded is None else branding.validate_image(encoded, key)[0]) for key, encoded in uploads.items()}
            except branding.BrandingError as error:
                return response(start_response, 400, {"error": str(error)})
            pending = {}
            for key, image in staged.items():
                if image is not None:
                    target = branding.asset_path(DATA_DIR, key)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    temporary = target.with_suffix(".pending")
                    temporary.write_bytes(image)
                    pending[key] = (temporary, target)
            with connect_db() as db:
                current = branding.load(db)
                saved = {**clean, "assets": current["assets"]}
                for key, image in staged.items():
                    saved["assets"][key] = f"/api/v1/branding/assets/{key}" if image is not None else None
                db.execute("UPDATE settings SET value_json=? WHERE key='branding'", (json.dumps(saved),))
            for temporary, target in pending.values():
                temporary.replace(target)
            for key, image in staged.items():
                if image is None:
                    branding.asset_path(DATA_DIR, key).unlink(missing_ok=True)
            audit(principal, "branding.updated", "branding")
            return response(start_response, 200, saved)
        if route == "admin/credentials" and method == "PUT":
            with connect_db() as db:
                admin = db.execute("SELECT * FROM admins WHERE id=1").fetchone()
                if not verify_password(body.get("current_password", ""), admin["password_hash"], admin["salt"]):
                    return response(start_response, 403, {"error": "invalid_current_password"})
                raw_username = body.get("username", admin["username"])
                password = body.get("new_password", "")
                if not isinstance(raw_username, str) or not isinstance(password, str):
                    return response(start_response, 400, {"error": "invalid_credentials"})
                username = raw_username.strip()
                if not username or len(username) > 64 or (password and len(password) < 12):
                    return response(start_response, 400, {"error": "invalid_credentials"})
                digest, salt = hash_password(password) if password else (admin["password_hash"], admin["salt"])
                db.execute("UPDATE admins SET username=?, password_hash=?, salt=?, updated_at=CURRENT_TIMESTAMP WHERE id=1", (username, digest, salt))
            audit(principal, "credentials.updated", "administrator", 1)
            with SESSION_LOCK:
                SESSIONS.clear()
            return response(start_response, 200, {"id": 1, "username": username, "role": "administrator"}, [("Set-Cookie", issue_session(1))])
    return response(start_response, 404, {"error": "not_found"})


MONITORING_SCHEDULE = None
MONITORING_LAST_TICK = None


def periodic_monitoring_worker():
    """Run persisted periodic schedules without relying on browser activity."""
    global MONITORING_SCHEDULE, MONITORING_LAST_TICK
    tick = max(0.25, min(float(os.environ.get("CHM_SCHEDULER_TICK_SECONDS", "1")), 30))
    if os.environ.get("CHM_SCHEDULER_ENABLED", "true").lower() == "false":
        return
    MONITORING_SCHEDULE = MonitoringSchedule(DB_PATH)
    with connect_db() as db:
        rows = db.execute("SELECT c.id,c.settings_json FROM cameras c JOIN servers s ON s.id=c.server_id WHERE c.disappeared=0 AND s.enabled=1").fetchall()
    MONITORING_SCHEDULE.synchronize([{"id": row["id"], "settings": json.loads(row["settings_json"])} for row in rows], now=monitoring_now(), reset_missed=True)
    while True:
        now = monitoring_now()
        MONITORING_LAST_TICK = time.time()
        try:
            with connect_db() as db:
                expire_maintenance(db, now)
                cameras = db.execute("SELECT c.*,s.enabled AS server_enabled,s.adapter,s.fixture_profile FROM cameras c JOIN servers s ON s.id=c.server_id WHERE c.disappeared=0 AND s.enabled=1 AND NOT EXISTS (SELECT 1 FROM camera_exclusions e WHERE e.camera_id=c.id)").fetchall()
                by_id = {row["id"]: dict(row) for row in cameras}
                confirmations = db.execute("SELECT camera_id FROM live_check_state WHERE confirmation_due_at IS NOT NULL AND confirmation_due_at<=?", (now,)).fetchall()
            MONITORING_SCHEDULE.synchronize([{"id": row["id"], "settings": json.loads(row["settings_json"])} for row in cameras], now=now)
            # A single retry is scheduled 30 seconds after the initial failure.
            for confirmation in confirmations:
                camera = by_id.get(confirmation["camera_id"])
                if not camera:
                    continue
                with connect_db() as db:
                    server = db.execute("SELECT * FROM servers WHERE id=?", (camera["server_id"],)).fetchone()
                if not server or server["adapter"] != "fixture":
                    continue
                start_live_check(camera, dict(server), scheduled=True, confirmation_retry=True)
            due = MONITORING_SCHEDULE.claim_due(now)
            for entry in due:
                camera = by_id.get(entry["camera_id"])
                if not camera:
                    continue
                with connect_db() as db:
                    server = db.execute("SELECT * FROM servers WHERE id=?", (camera["server_id"],)).fetchone()
                if not server:
                    continue
                check_type = entry["check_type"]
                if server["adapter"] != "fixture":
                    # Keep installed Exacq integration explicitly unverified.
                    state = "integration_unverified"
                    with connect_db() as db:
                        db.execute("INSERT INTO monitoring_check_state(camera_id,check_type,current_state,last_attempt_at) VALUES(?,?,?,?) ON CONFLICT(camera_id,check_type) DO UPDATE SET current_state=excluded.current_state,current_job_id=NULL,last_attempt_at=excluded.last_attempt_at",
                                   (camera["id"], check_type, state, utc_now()))
                    MONITORING_SCHEDULE.complete(camera["id"], check_type)
                    continue
                if check_type == "live":
                    start_live_check(camera, dict(server), scheduled=True)
                else:
                    start_recording_check(camera, dict(server), scheduled=True)
            monitor_progress()
        except Exception:
            # A single failed cycle must not stop future monitoring cycles.
            monitor_fault("scheduler_cycle_failed")
        if SCHEDULER_WAKE.wait(tick):
            SCHEDULER_WAKE.clear()
            try:
                with connect_db() as db:
                    expire_maintenance(db, monitoring_now())
                    rows = db.execute("SELECT c.id,c.settings_json FROM cameras c JOIN servers s ON s.id=c.server_id WHERE c.disappeared=0 AND s.enabled=1 AND NOT EXISTS (SELECT 1 FROM camera_exclusions e WHERE e.camera_id=c.id)").fetchall()
                MONITORING_SCHEDULE.synchronize([{"id": row["id"], "settings": json.loads(row["settings_json"])} for row in rows], now=monitoring_now())
            except sqlite3.Error:
                continue


if __name__ == "__main__":
    initialize()
    if os.environ.get("CHM_RESET_ADMIN") == "1":
        username = input("New administrator username: ").strip()
        password = getpass.getpass("New administrator password (12+ characters): ")
        if not username or len(username) > 64 or len(password) < 12:
            raise SystemExit("Invalid credentials; use a username and password with at least 12 characters.")
        digest, salt = hash_password(password)
        with connect_db() as db:
            cursor = db.execute("UPDATE admins SET username=?, password_hash=?, salt=?, updated_at=CURRENT_TIMESTAMP WHERE id=1", (username, digest, salt))
            if cursor.rowcount != 1:
                raise SystemExit("No local administrator exists. Start the service normally and use first-run setup.")
        print("Local administrator credentials updated. Start the service normally.")
        raise SystemExit(0)
    host, port = os.environ.get("CHM_HOST", "0.0.0.0"), int(os.environ.get("CHM_PORT", "8080"))
    def periodic_discovery_worker():
        interval = max(1, int(os.environ.get("CHM_DISCOVERY_INTERVAL_SECONDS", "900")))
        while True:
            with connect_db() as db:
                servers = db.execute("SELECT * FROM servers WHERE enabled=1").fetchall()
                for server in servers:
                    try:
                        discover_server(db, server)
                    except Exception:
                        continue
            time.sleep(interval)
    threading.Thread(target=periodic_discovery_worker, name="periodic-discovery", daemon=True).start()
    threading.Thread(target=periodic_monitoring_worker, name="periodic-monitoring", daemon=True).start()
    threading.Thread(target=webhook_worker, name="webhook-delivery", daemon=True).start()
    with make_server(host, port, app, server_class=ThreadingWSGIServer) as server:
        print(f"Camera Health Monitor listening on {host}:{port}", flush=True)
        server.serve_forever()
