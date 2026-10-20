# Camera Health Monitor

Camera Health Monitor is a browser-managed service for checking ExacqVision camera live video and motion recordings. It is designed to run in Docker on a VM that can reach the recorder and camera network.

> **Integration status:** The ExacqVision Web Client interface has been implemented from sanitized captures of ExacqVision Server 21.12.8 and Web Service 21.12.1. Automated tests use synthetic responses. Validate authentication and playback against your recorder after deployment; live capture timestamps are not supplied by the observed JPEG endpoint, so freshness is explicitly reported as unverified.

## Requirements

- Docker Engine with Docker Compose v2.
- A VM that can reach the ExacqVision server over the interfaces you plan to validate.
- A persistent Docker volume or bind mount for `/data`.
- For production access, an HTTPS reverse proxy. Restrict direct network access to the application port.

The container listens on TCP 8080 and runs as an unprivileged user. It includes FFmpeg for live-sample decoding and uses Python's `cryptography` package for secret encryption. The Compose sample exposes that port on the VM, limits the container to 2 CPUs, 1 GiB of memory, and 128 processes, and keeps its root filesystem read-only. Temporary FFmpeg files use a 64 MiB `/tmp` memory filesystem; persistent state is written under `/data`.

## Start with Compose

From the repository directory:

```sh
docker compose up -d --build
docker compose ps
```

Open `http://<vm-address>:8080/` on a trusted network. On the first visit, create the local administrator. First-run setup is single use: once the account exists, the setup API returns `409` and cannot create or replace the account.

For a reverse proxy that terminates HTTPS, set `CHM_COOKIE_SECURE: "true"` in `compose.yaml`, then recreate the service:

```sh
docker compose up -d
```

The secure cookie option requires HTTPS. For direct HTTP testing on a private network, leave it `false`. Do not publish the unauthenticated HTTP port to the public internet.

## Persistence, backup, restore, and upgrades

SQLite database and application settings live in `/data/camera-health-monitor.sqlite3`. The named volume `camera-health-data` survives container replacement and image rebuilds. Do not remove the volume when updating the image.

Back up the complete `/data` directory while the app is stopped so the database, SQLite write-ahead log, OIDC encryption key, and recorder-credential key are captured together:

```sh
docker compose stop camera-health-monitor
docker cp camera-health-monitor:/data ./camera-health-monitor-data-backup
docker compose start camera-health-monitor
```

Restore by stopping the service, preserving the existing volume contents, and copying the complete backup directory back into `/data` in the existing container (or a one-off container with the same named volume mounted). Start the service and verify `/readyz`, sign-in, server credentials, branding, and webhook delivery state. Keep the previous volume or a separate copy before restoring. For upgrades, pull/build the new image and recreate the container without removing the named volume:

```sh
docker compose up -d --build
```

The administrator record is stored in that database. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes; session cookies are random, HttpOnly, SameSite=Strict, and expire after eight hours. OIDC and recorder secrets use encryption keys stored in `/data`; back up the complete directory as a unit or saved secrets cannot be recovered. Secret values are not returned by the API.

### Local administrator recovery

The initial release has one local administrator and no delete/disable operation, so the last usable local account cannot be removed or disabled through the application. If its password is lost, stop the service and run the interactive reset command against the same persistent volume:

```sh
docker compose stop camera-health-monitor
docker compose run --rm -it -e CHM_RESET_ADMIN=1 camera-health-monitor
docker compose start camera-health-monitor
```

The command prompts for a username and password without echoing the password, updates the existing administrator, and does not create another account. If the volume has no administrator yet, start the service normally and complete first-run setup instead.

## Browser interface

- `/` — first-run setup, local or OIDC sign-in, the dashboard, and administrator access settings.
- Dashboard **Account** — change the local administrator username and/or password. The current password is required; changing credentials revokes existing browser sessions and signs in the current browser again.
- Theme can be set to System, Light, or Dark from the sign-in or dashboard screen. System is the default, follows operating-system theme changes, and the selection is stored in that browser only.
- Administrators can open **Branding** to set the shared app name, separate light/dark logos, favicon, SSO button label/logo, and accent/background/surface/text colors for each theme. Color pickers and six-digit hex values preview immediately; **Discard changes** restores the saved preview and **Reset branding** previews neutral grayscale defaults until saved. These shared settings do not modify any browser's theme preference.
- Administrators can add, edit, and remove recorder servers, inspect independent capability states, and manage server defaults. Blank passwords on update retain saved credentials.
- Operators can review servers and inventory and refresh discovery; configuration mutations require the administrator role.
- Inventory gives each camera a stable server-scoped identity, applies server defaults to newly discovered cameras, preserves camera overrides/history on rediscovery, and flags missing cameras without deleting them.
- Discovery refreshes periodically every 15 minutes by default. Set `CHM_DISCOVERY_INTERVAL_SECONDS` to change the period.
- Monitoring runs in the service without a browser session. Server defaults set the live check interval (5 minutes), recording check interval (60 minutes), and recording lookback (24 hours); administrators can override each value per camera. Due camera checks are staggered, concurrency-bounded, and a camera can have only one live or recording job at a time.
- A scheduled live failure is provisional for 30 seconds. The service retries once; only a second failure becomes the current failure result. A successful retry clears the provisional result. Current health and last-success time are shown separately. A result older than its configured interval is returned as `unknown` with `state: stale`, while the last successful timestamp remains available.
- `GET /api/v1/monitoring` reports scheduler progress, each camera's configured intervals, next due times, last scheduled execution, active job ID, current result, and last success. The dashboard displays the same status and lets administrators edit server defaults and camera overrides.

## REST API and interactive docs

The browser calls the same versioned REST API intended for automation clients. OpenAPI JSON is available at [`/openapi.json`](http://localhost:8080/openapi.json); the interactive API explorer is at [`/docs`](http://localhost:8080/docs). The explorer uses the browser's same-origin session or a bearer token entered in its token field.

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/setup/status` | Public | Report whether first-run setup is required |
| `POST` | `/api/v1/setup/admin` | Public, once | Create and sign in the initial local administrator |
| `POST` | `/api/v1/auth/login` | Public | Sign in locally |
| `GET` | `/api/v1/auth/oidc/status` | Public | Check whether SSO is enabled |
| `GET` | `/api/v1/auth/oidc/login` | Public | Start OIDC authorization-code + PKCE flow |
| `GET` | `/api/v1/auth/oidc/callback` | Provider redirect | Validate response and sign in |
| `POST` | `/api/v1/auth/logout` | Public | Revoke the current session cookie |
| `GET` | `/api/v1/auth/me` | Operator or administrator | Read the authenticated principal |
| `PUT` | `/api/v1/admin/credentials` | Administrator | Change username and/or password |
| `GET` / `PUT` | `/api/v1/admin/auth/oidc` | Administrator | Read or configure provider and role/group mappings |
| `GET` / `POST` | `/api/v1/admin/api-tokens` | Administrator with `tokens:manage` when using a token | List token metadata or issue a scoped token; the secret is returned once |
| `DELETE` | `/api/v1/admin/api-tokens/{token_id}` | Administrator with `tokens:manage` when using a token | Revoke a token immediately |
| `GET` | `/api/v1/admin/audit` | Administrator; `auth:manage` for tokens | Read redacted actor/action/resource records |
| `GET` | `/api/v1/admin/diagnostics` | Administrator; `diagnostics:read` for tokens | Read recent bounded recorder action traces when enabled |
| `GET` | `/api/v1/dashboard` | Operator or administrator | Read initial dashboard summary |
| `GET` | `/api/v1/monitoring` | Operator or administrator; `health:read` for tokens | Read scheduler progress, per-camera current results, due times, active jobs, and last successes |
| `GET` / `POST` | `/api/v1/servers` | Operator read / administrator write | List or add recorder connections |
| `GET` / `PUT` / `DELETE` | `/api/v1/servers/{server_id}` | Operator read / administrator write | Read, edit, or remove server connection |
| `POST` | `/api/v1/servers/{server_id}/discover` | Operator or administrator | Refresh camera inventory |
| `GET` / `POST` | `/api/v1/servers/{server_id}/capabilities` | Operator read / administrator probe | Read or probe independent capabilities |
| `GET` | `/api/v1/cameras` | Operator or administrator | List persistent inventory |
| `PUT` | `/api/v1/cameras/{camera_id}` | Administrator | Update per-camera overrides |
| `POST` | `/api/v1/cameras/{camera_id}/live-check` | Operator or administrator; `checks:run` for tokens | Start asynchronous live sample check (`202` with job ID; `502` for recorder or media failures) |
| `GET` / `DELETE` | `/api/v1/live-checks/{job_id}` | Operator or administrator; `health:read` to poll, `checks:run` to cancel | Poll a check result or cancel an active check |
| `POST` | `/api/v1/cameras/{camera_id}/recording-check` | Operator or administrator; `checks:run` for tokens | Start recording search and decode (`202` with job ID; `502` for recorder or media failures) |
| `POST` | `/api/v1/servers/{server_id}/recording-check` | Operator or administrator; `checks:run` for tokens | Queue a bounded recording check batch for all present cameras |
| `GET` | `/api/v1/recording-batches/{batch_id}` | Operator or administrator; `health:read` for tokens | Poll progress and per-camera playback, no-footage, or error results |
| `GET` | `/api/v1/recording-checks/{job_id}` | Operator or administrator; `health:read` for tokens | Poll recording-check job and sanitized result |
| `GET` | `/api/v1/branding` | Public | Read shared appearance settings for sign-in and application pages |
| `PUT` | `/api/v1/branding` | Administrator | Replace shared app name, theme colors, SSO button text, and optional image updates |
| `GET` | `/api/v1/branding/assets/{asset}` | Public | Serve an uploaded light/dark logo, favicon, or SSO logo |
| `PUT` | `/api/v1/branding/assets/{asset}` | Administrator | Upload a PNG/JPEG image as base64 JSON (`{"data":"..."}`) |
| `DELETE` | `/api/v1/branding/assets/{asset}` | Administrator | Remove an uploaded image |

Example first-run request:

```sh
curl -i -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"username":"siteadmin","password":"choose-a-long-unique-password"}' \
  http://localhost:8080/api/v1/setup/admin
```

Example authenticated dashboard request:

```sh
curl -b cookies.txt http://localhost:8080/api/v1/dashboard
```

Successful setup/login returns a session cookie and a principal with `id`, `username`, `role`, and `auth_type`. Roles are `operator` or `administrator`; the local account remains an administrator recovery path. Unauthenticated dashboard/account calls return `401`; invalid credentials return `401`; repeated setup returns `409`. Responses never contain password hashes, password salts, submitted passwords, or saved credentials.

### Scoped automation tokens

Administrators can issue tokens from **API tokens** or `POST /api/v1/admin/api-tokens`. Choose the role ceiling (`operator` or `administrator`), a nonempty subset of that role's scopes, and optionally a future ISO-8601 `expires_at`. The raw `chm_at_…` value appears only in the successful creation response; copy it immediately. SQLite stores only its SHA-256 verifier. Token listing returns name, role, scopes, creation/expiry/revocation metadata, never the credential. Delete the numeric token ID to revoke it. Expired, revoked, malformed, or unknown credentials return `401`; a recognized token missing an endpoint scope returns `403` with `error: insufficient_scope` and no login redirect.

Send the token in the standard bearer header:

```sh
curl -H 'Authorization: Bearer chm_at_REPLACE_WITH_TOKEN' \
  http://localhost:8080/api/v1/dashboard
```

Operator scopes are `health:read`, `history:read`, `incidents:acknowledge`, `checks:run`, and `maintenance:read`. Administrator tokens may additionally receive `maintenance:write`, `servers:read`, `servers:write`, `cameras:read`, `cameras:write`, `webhooks:read`, `webhooks:write`, `branding:write`, `auth:manage`, `tokens:manage`, and `diagnostics:read`. An administrator role sets the maximum possible authority, while each token still receives only its selected scopes. Browser sessions use the same role authorization rules without token scope restrictions. Current server and camera inventory routes require their corresponding read/write scopes; manual inventory discovery requires `checks:run`. New route handlers must explicitly declare both the minimum role and required token scope; unmapped future operations must not be treated as implicitly authorized.

Token issuance/revocation, local credential changes, OIDC configuration changes, and branding changes produce audit entries containing actor identity/type, action, resource, and timestamp. Audit records intentionally omit request bodies, bearer values, passwords, OIDC secrets, and webhook secrets. API tokens should be unique to an automation and stored in that automation's secret store. Avoid placing bearer values in URLs, command history, or diagnostic output. The interactive API explorer accepts a token in its Bearer token field and sends it only as an Authorization header.

### Opt-in action diagnostics

Detailed operational traces are disabled by default. To enable them temporarily, set `CHM_DIAGNOSTICS_ENABLED: "true"` in the Compose service environment and recreate the container with `docker compose up -d --force-recreate camera-health-monitor`. Read traces from `GET /api/v1/admin/diagnostics` using a local administrator session or an administrator API token with `diagnostics:read`. Set the value back to `"false"` and recreate the container when troubleshooting is complete. `CHM_DIAGNOSTIC_MAX_EVENTS` bounds retained records (default 5,000; allowed range 100–50,000), and `CHM_DIAGNOSTIC_RETENTION_DAYS` removes older records (default 7; allowed range 1–90 days).

Each trace contains an opaque correlation/job/batch ID, action, stage, outcome, duration, safe HTTP status, and an allowlisted error category. Stages include authentication, search, clip selection, recorded-frame retrieval, timestamp progression, and decoding. The logger never stores credentials, sessions, cookies, full URLs or queries, request/response bodies, frames, media, or private camera inventory. Operators receive the qualified health result; detailed stage/status fields are only returned to administrators with diagnostic scope. The existing `/api/v1/admin/audit` endpoint remains the record of configuration changes and user actions.

Live sample checks return asynchronously. Clients should submit a check, retain its returned job ID, then poll the job endpoint until a terminal state:

```sh
job=$(curl -sS -H "Authorization: Bearer $CHM_TOKEN" -H 'Content-Type: application/json' \
  -d '{}' http://localhost:8080/api/v1/cameras/CAMERA_ID/live-check)
job_id=$(printf '%s' "$job" | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -H "Authorization: Bearer $CHM_TOKEN" \
  "http://localhost:8080/api/v1/live-checks/$job_id"
```

Poll until the job status is terminal (`succeeded`, `failed`, `cancelled`, or `unsupported`). Keep `$CHM_TOKEN` in the automation platform's secret store and avoid shell tracing. Other REST responses are synchronous where listed in the table.

### Camera exclusions and maintenance

Use a persistent exclusion for an intentionally offline camera. Excluded cameras are omitted from scheduled checks and their existing health incidents are marked suppressed. Manual checks remain available and continue to store their result/evidence, but they do not create health webhook events while the exclusion is active. Operators can see the reason and state; administrators can set or clear it.

```sh
curl -X PUT -H "Authorization: Bearer $CHM_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"excluded":true,"reason":"Camera removed for renovation"}' \
  http://localhost:8080/api/v1/cameras/CAMERA_ID/exclusion
```

For planned work, create a camera- or server-scoped maintenance window with an ISO-8601 start, end, and reason. Checks continue and health evidence is persisted throughout a temporary maintenance window. Health incident webhooks are suppressed; job completion events and webhook delivery behavior are unchanged. At the end time the scheduler (or a `GET /api/v1/maintenance`) finalizes the window and evaluates the newest persisted check result. A still-current warning/failure produces one current incident event; suppressed intermediate check transitions are not replayed. A successful latest result leaves the issue resolved without a recovery event for a failure that was never notified.

```sh
curl -X POST -H "Authorization: Bearer $CHM_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"entity_type":"server","entity_id":"SERVER_ID","reason":"Recorder maintenance","starts_at":"2026-10-20T22:00:00Z","ends_at":"2026-10-20T23:30:00Z"}' \
  http://localhost:8080/api/v1/maintenance
curl -H "Authorization: Bearer $CHM_OPERATOR_TOKEN" http://localhost:8080/api/v1/maintenance
curl -X DELETE -H "Authorization: Bearer $CHM_ADMIN_TOKEN" \
  http://localhost:8080/api/v1/maintenance/WINDOW_ID
```

Windows ending in the past are rejected; start times may be in the past to begin maintenance immediately. End must follow start. Identical scope/start/end requests are idempotent and return the existing window; overlapping windows for the same scope return `409 maintenance_overlap`. Deleting a window ends it immediately and can be repeated; windows also expire automatically at `ends_at`. Administrators need `maintenance:write`; operators may list windows with `maintenance:read`. Exclusion writes use the same scopes. Exclusions and maintenance survive restarts. `/openapi.json` documents the request and response shapes.

Branding PUT takes the complete `app_name`, `sso_button_text`, and `colors` object shown by `GET /api/v1/branding`. Each theme needs `accent`, `background`, `surface`, and `text` as `#RRGGBB` values. Optional `asset_uploads` maps `light_logo`, `dark_logo`, `favicon`, and/or `sso_logo` to base64 PNG/JPEG image data; set a value to `null` to remove it. Logos are limited to 2 MiB and 2048×2048 pixels; favicon is limited to 512 KiB and 512×512 pixels. Invalid images, including SVG, are rejected without updating the branding configuration. Image responses use fixed asset names, `X-Content-Type-Options: nosniff`, and a sandbox content policy. Images are stored in the persistent data volume.

The SSO label and logo are saved and displayed as branding data. The SSO sign-in button becomes active when an administrator configures OIDC.

## Network and ExacqVision prerequisites

The VM needs DNS and network routes/firewall rules to each recorder and any separately configured RTSP server. No recorder API port is assumed by the form; specify a port only after confirming it for the installed interface. Exacq public material identifies CLI/SDK/Web Services Integration tools and describes Web Service as an interface for video/server data. The SDK/OEM path is gated by the Connected Partner Program. Public documentation does not establish the installed server's authentication method, exposed API operations, enabled services, permissions, platform, or licensing.

Configure the Web Service host, scheme, and port independently of the optional native recorder port. The captured target uses HTTP on port 80; HTTPS is supported and recommended where enabled. Exacq credentials are encrypted at rest and exchanged only when the monitor makes a request. The application does not persist Exacq session IDs; each job authenticates, uses its short-lived session, and discards it after the operation. Redirects are rejected so credentials cannot be forwarded to a different origin.

The adapter is isolated in `exacq.py` and follows the version-specific Web Client routes observed in the captures:

- Authentication: `POST /login.web` using the Web Client credential form.
- Discovery: `GET /config.web` and `/server.web/devices`, with `/status.web` for recorder state.
- Live: repeated `GET /video.web` JPEG samples, decoded individually by FFmpeg.
- Recording: `GET /search.web`, bounded polling of `/search.web/status`, and recorded frame retrieval using `/playspeed.web`, `/step.web`, `/video.web`, and `/timestamp.web`.

Discovery preserves stable application camera IDs across refreshes and stores the Exacq remote ID, parent association, enabled/connection state, and available device metadata. Cameras that Exacq marks disabled are visible and excluded from scheduled checks. A device's disconnected state is shown as a dashboard warning; it becomes a camera incident only when a confirmed live retrieval or decode check fails. Auxiliary devices without a camera association are ignored.

A live success means three live-endpoint JPEG frames were retrieved and decoded. The captured service does not provide a source capture timestamp, so the result reports `freshness_verified: false` and does not claim wall-clock freshness. Recording checks search the configured rolling lookback, select the newest interval, narrow the search to that clip, retrieve a recorded sample, and decode it. No media, thumbnails, session IDs, or Exacq response bodies are retained. Use the **Test connection** action, refresh inventory, then run one live and one recording check to validate the installed account's permissions and playback behavior.

These routes are undocumented Web Client behavior and may vary by Exacq release. In particular, test the ordinary username/password login path, session behavior, JPEG live retrieval, search completion status values, and recorded-frame selection against the installed service. The adapter limits request/decoder time, rejects malformed or oversized responses, and reports authentication, transport, timeout, unsupported media, and decode failures separately. Failed discovery preserves the last known inventory rather than marking every camera missing.

Live checks run asynchronously and return a pollable job (`queued`, `running`, `succeeded`, `failed`, or `cancelled`). The service limits active live and recording work separately with `CHM_LIVE_CHECK_CONCURRENCY` (default 4, maximum 8), prevents overlapping check types for one camera, and bounds FFmpeg decoding with `CHM_LIVE_CHECK_TIMEOUT_SECONDS` (default 15, maximum 60). FFmpeg reads a temporary sample file that is removed after success, failure, timeout, or cancellation. A successful result confirms that FFmpeg decoded at least one video frame. `sample_timestamp` is null when the source supplies no capture timestamp; a container presentation timestamp is not treated as wall-clock capture evidence. Job outcomes are held in memory for up to 24 hours and are lost if the service restarts; persisted current health, last success, and next schedule time remain available.

The monitoring scheduler checks schedules every second by default (`CHM_SCHEDULER_TICK_SECONDS`, bounded to 0.25–30 seconds) and can be disabled with `CHM_SCHEDULER_ENABLED=false`. Due work is staggered across cameras, starts only when a bounded worker slot is available, and advances its next run before dispatch. This intentionally skips a run that was missed while the service was down or a camera was busy; it does not build a catch-up queue. At startup, overdue schedules move to one future interval, so restart does not replay backlog. Active jobs are process-local: a container restart interrupts in-flight work, but does not duplicate it. Run one application instance per data volume; concurrency exclusion is process-local, not a distributed lock across multiple replicas.

### Monitoring the monitor

`GET /healthz` is process liveness only: HTTP 200 means the web process can answer. `GET /readyz` also checks SQLite readiness. Neither endpoint claims that camera checks are progressing. Authenticated `GET /api/v1/monitoring` and the dashboard report monitor state (`healthy`, `fault`, `starting`, or `disabled`), last scheduler progress time/age, and a sanitized error code. A live process with stale scheduler progress is reported as a monitor fault; a successful later cycle emits one `monitoring.recovered` event. Fault/recovery events use the versioned webhook outbox, persist across restart, and only emit on state transitions. Diagnostic records never include exception text, credentials, URLs, or provider response bodies.

Camera authentication, permission, connector, and unsupported-interface results remain `unknown` camera health. They do not open camera incidents or trigger per-camera failure notifications; fix the recorder account or integration separately. A monitor fault describes scheduler progress, not camera condition.

An administrator may configure an optional external heartbeat in **Webhooks** or with `GET/PUT /api/v1/monitoring/heartbeat`. Create an enabled webhook receiver subscribed to `monitoring.heartbeat`, select it, then choose an interval from 60 to 86,400 seconds. Heartbeats use the normal durable, signed, at-least-once delivery pipeline and report process presence/progress metadata only. The remote receiver should alarm when the expected heartbeat is missing by its own timeout; this is the way to detect a fully stopped container that cannot report its own failure. Heartbeat delivery failures are visible in the receiver's sanitized delivery history and retry with the usual backoff.

For acceptance tests, `CHM_TEST_CLOCK_FILE` may point to a file containing an epoch timestamp. The scheduler reads that clock for due-time and confirmation decisions; leave this unset in normal deployments.

Recording checks use the persisted server `recording_lookback_hours` default (24 hours) unless a camera override is configured (1–720 hours). `recording_expected` defaults to true and can be set per camera to false when motion recordings are not expected; the no-recording result remains visible without opening an incident or sending a missing-recording alert. The time window includes its exact lower boundary. A check searches that rolling window, selects the newest matching recording by timestamp, starts its recorded playback cursor, decodes multiple JPEG frames with FFmpeg, and requires the recorder-reported playback timestamp to advance. A still frame alone never verifies recorded playback. `recording_status.health` is independent of live status: `healthy` means decoded recorded playback advanced; `warning` with reason `no_recent_recording` means the window had no motion footage; `failure` with reason `decode_failed` means a matching newest recording existed but was unreadable; connector, unsupported, timeout, and permission problems are `unknown` and do not claim a camera fault. Results retain check time, the most recent successful recording-check time, newest recording time, and sanitized evidence without retaining media. Recording jobs are in-memory for polling and are lost on restart, while the latest per-camera outcome persists. The server-level action queues present cameras with bounded concurrency, retries cameras already under another check, and returns a batch ID. Retry pacing and its finite deadline are controlled by `CHM_RECORDING_BATCH_RETRY_SECONDS` (default 1 second) and `CHM_RECORDING_BATCH_BUSY_TIMEOUT_SECONDS` (default 120 seconds, capped at 30 minutes). A timed-out busy/capacity entry gets an explicit terminal result and still counts toward completed progress. Poll `/api/v1/recording-batches/{batch_id}` for totals and per-camera results. An empty recording window verifies search but leaves playback untested; it raises a camera warning only if recordings are expected. Batch progress and in-flight jobs are process-local: a service restart stops active work and loses the batch/job poll records, while persisted per-camera outcomes remain available.

For installed-recorder validation, first select one camera known to have recent footage and run `POST /api/v1/cameras/{camera_id}/recording-check`. Poll its returned job ID to a terminal result and review the administrator diagnostic trace for the failed stage and safe HTTP/transport status. Capture only the app version, recorder/Web Service versions if known, stage, status/category, duration, and whether a clip was present and playback advanced. Once that one-camera path has been understood, run `POST /api/v1/servers/{server_id}/recording-check` and review per-camera outcomes. Cameras with no motion in the lookback are empty search windows, not search failures; playback remains untested for those cameras. Synthetic tests do not establish compatibility with the installed recorder, and no live-server capability is marked verified solely from fixtures.

### Incidents and recovery

Live and recording findings create independent incidents, so a successful live sample never clears a recording warning and a successful recording decode never hides a live failure. `GET /api/v1/incidents` lists active incidents by default; pass `?status=resolved` or `?status=all` for resolved incidents. `GET /api/v1/incidents/{incident_id}` returns the incident, sanitized evidence, and its transition history. `POST /api/v1/incidents/{incident_id}/acknowledge` records the operator and timestamp; it does not change health, resolve the incident, or prevent recovery notifications. `GET /api/v1/history?days=90` returns resolved incidents and all active incidents for a 1–90 day range. Operators need `health:read` to inspect incidents/history and `incidents:acknowledge` to acknowledge an incident.

An initial live decode failure waits for the configured second attempt after 30 seconds; only a confirmed decode failure becomes a camera incident. Explicit `no_recent_recording` findings are warnings; unreadable recording samples are failures. Authentication, permission, connector, timeout, unsupported-capability, and other unknown results do not create camera incidents or resolve existing ones. A successful applicable recheck resolves its incident automatically. If an adapter explicitly reports `server_unavailable`, `server_outage`, `server_timeout`, or `monitoring_stalled`, the monitor opens one server incident and suppresses duplicate camera notifications while retaining camera-specific evidence. After server connectivity returns, the next applicable camera recheck resolves or re-notifies based on that camera's own result. The current fixture can simulate server unavailability; it does not establish Exacq compatibility.

Incidents and transitions are stored in SQLite and survive container replacement. Resolved incident history is retained for 90 days by default; active incidents and pending outbox events are not pruned. The `event_outbox` table is the durable handoff seam for webhook delivery work; each incident open/update/recovery has a stable event ID and redacted JSON payload. This incident slice records pending events; delivery and retry are handled by webhook delivery support. No video or thumbnails are stored in incidents. The browser dashboard uses these same versioned API routes for active incidents, details, acknowledgments, and 90-day history.

Fixture-only profiles include `recording_success`, `recording_none`, `recording_invalid_media`, `recording_permission_error`, `recording_search_error`, and `recording_boundary`. They exercise application behavior with synthetic metadata and a bundled MP4 or intentionally malformed bytes. They are not evidence of Exacq compatibility.

### Webhooks and downstream automation

Administrators can add multiple receivers from **Webhooks** or the versioned REST API (`/api/v1/webhooks`). Choose event types per destination and optionally set an HMAC signing secret. Operators can read receiver metadata and sanitized delivery history, but cannot create, edit, test, or remove destinations. A receiver secret is encrypted using the persistent data-volume key, accepted only on create/update, and never returned. The browser uses these same routes as automation clients. The API explorer and downloadable OpenAPI document include the receiver and event contracts.

Version 1 event names are `incident.opened`, `incident.updated`, `incident.resolved`, `job.completed`, `monitoring.fault`, `monitoring.recovered`, and `incident.reminder`; the test action sends a synthetic `test` event. Each payload is JSON with `id` (UUID), `version` (`1`), `type`, `created_at` (UTC ISO 8601), and `data`. Incident events include incident identity, server/camera identity when known, check type, severity, state, reason, and transition timestamps. Job completion includes job ID/type, server/camera identity, terminal status, completion time, and sanitized reason. Monitor fault and recovery use the same envelope with monitoring state identity and reason. No receiver credentials, API tokens, video, or thumbnails are included.

Delivery is at least once. The persistent `event_outbox` row is the event source of truth; one persistent delivery row per receiver/event pair tracks attempts. Failed HTTP requests remain pending and retry after exponential delays beginning at 2 seconds, capped at 1 hour. The event ID and exact event payload stay stable across retries and process restarts. Receivers should deduplicate using `id` (and may also use `X-CHM-Event-Id`). A successful HTTP 2xx marks delivery complete. Timeouts, 3xx/4xx/5xx responses, and network failures are retried; the history retains only a sanitized error code/status, not response bodies or secrets. Test deliveries run synchronously and report their result immediately.

For signed requests, the application sends `X-CHM-Event-Id`, `X-CHM-Event-Type`, `X-CHM-Event-Version`, `X-CHM-Timestamp` (Unix seconds), and `X-CHM-Signature`. The signature is `sha256=` followed by lowercase hexadecimal HMAC-SHA256 over the exact request bytes `timestamp + "." + raw_body`, keyed by the configured UTF-8 secret. Receivers should reject timestamps more than five minutes from their current UTC clock, compare signatures in constant time, parse the body only after signature verification, and deduplicate by event ID. Example verification in Python:

```python
import hashlib, hmac, time

timestamp = request.headers["X-CHM-Timestamp"]
if abs(time.time() - int(timestamp)) > 300:
    raise ValueError("stale webhook")
expected = "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + request.body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers["X-CHM-Signature"]):
    raise ValueError("invalid signature")
event = json.loads(request.body)
```

Use HTTPS whenever the receiver network supports it. Since automation receivers commonly run on the same private network, RFC1918 and loopback destinations are allowed after administrator configuration. The application accepts only HTTP(S), rejects URL user-info, link-local and known cloud metadata addresses, re-resolves the configured host before sending, and does not follow redirects. Restrict outbound network access at the VM/firewall to the intended automation services for additional SSRF containment. Do not enable unresolved reminders unless desired; they default off and, when enabled, are emitted once per unresolved incident every 24 hours after the first full day.

Example configuration and verification:

```sh
curl -sS -H "Authorization: Bearer $CHM_ADMIN_TOKEN" http://localhost:8080/api/v1/webhook-events
curl -sS -X POST -H "Authorization: Bearer $CHM_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"n8n","url":"https://automation.example/webhook/camera-health","events":["incident.opened","incident.resolved","job.completed"],"signing_secret":"replace-with-a-random-secret-at-least-16-chars"}' \
  http://localhost:8080/api/v1/webhooks
curl -sS -X POST -H "Authorization: Bearer $CHM_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{}' http://localhost:8080/api/v1/webhooks/RECEIVER_ID/test
curl -sS -H "Authorization: Bearer $CHM_OPERATOR_TOKEN" http://localhost:8080/api/v1/webhooks/RECEIVER_ID/deliveries
```

The test endpoint creates a synthetic signed event and does not alter camera state. Repeated failed checks update their existing incident instead of sending another opening event; recovery creates one resolution event per incident. Grant automation tokens `webhooks:read` or `webhooks:write` as needed, in addition to the corresponding role. The API never includes event bodies in delivery-history responses.

For acceptance testing only, `CHM_ENABLE_FIXTURE=true` enables a controlled fixture adapter that simulates inventory and capability errors and decodes a bundled real MP4 sample using FFmpeg. The `live_slow`, `live_timeout`, and `live_flaky` profiles exercise cancellation, timeout, and a successful confirmation retry; `invalid_media` verifies that malformed bytes fail decoding. Keep fixture mode disabled in production; successful fixture checks do not test camera transport or prove recorder compatibility.

## Health endpoints and troubleshooting

- `GET /healthz` checks that the HTTP service responds.
- `GET /readyz` checks that the service can access its persistent SQLite store; Docker uses this for container health.
- `GET /api/v1/monitoring` shows whether scheduled monitoring is progressing, last progress time, current monitor fault state, and sanitized diagnostics. `/healthz` only proves that the process responds; a healthy HTTP process can still have stalled or unavailable monitoring.
- Monitoring faults describe the monitor, scheduler, authentication, permissions, or recorder connector. They are not camera incidents. Check the last progress time and sanitized reason, then validate server credentials/permissions and each independently reported Exacq capability. An unsupported integration remains unknown; do not treat it as healthy.
- Configure an optional heartbeat receiver under **Monitoring health** or through the admin API to have the service send periodic heartbeat events. The heartbeat uses the durable webhook queue, so delivery attempts/retries are visible in webhook history. A heartbeat cannot run while the entire container is stopped: configure the receiver or an external uptime system to alert when no heartbeat arrives within a timeout longer than the configured interval plus retry allowance.
- If live video works but recording search or playback fails, inspect the independent capability result and sanitized server error. A quiet scene with no motion in the lookback is a warning; a found recording that cannot be decoded is a failure. Validate recording search and playback separately against the installed Exacq version and account permissions.
- If `/readyz` fails, check the volume mount and ownership. The container runs as UID `10001` and needs write access to `/data`.
- If first-run setup reports it is already complete, sign in or use the documented offline recovery command.
- If the browser keeps returning to sign-in, allow same-origin cookies; set `CHM_COOKIE_SECURE=true` only when accessing through HTTPS.
- Keep the volume when replacing containers. Removing it deletes the local administrator and all persisted settings.

## Run acceptance tests

The API acceptance suite launches the app as a separate process with temporary persistent storage and a controlled fixture provider:

```sh
python -m unittest discover -s tests -v
```

The real-browser acceptance flow is in `tests/test_browser_acceptance.py`. To run it, install Playwright and its Chromium browser, then run the same unittest command. It covers first-run setup, recorder configuration and capability display, dashboard rendering, sign-out, and sign-in through the browser.


## OpenID Connect provider setup and role mappings

OIDC is disabled until configured by an administrator in **Single sign-on** or through `PUT /api/v1/admin/auth/oidc`. Configure the provider issuer URL, client ID and secret, claim name containing role/group values, and exact values that grant administrator or operator. Unmatched users are denied; administrator mapping takes precedence.

Register `https://<public-host>/api/v1/auth/oidc/callback` with the provider and set `CHM_PUBLIC_URL` to the external HTTPS origin when TLS terminates at a reverse proxy. The app uses authorization code + PKCE and validates state, nonce, token signature, issuer, audience, and lifetime. Client secrets are encrypted at rest. Preserve `/data/.secret-key` with the database during backups. The local administrator login remains available if the provider is offline.

### Camera and settings pages

The **Cameras** page has an alphabetical searchable camera drawer, one muted live feed at a time, and the selected camera’s health, check actions, and inventory details below the player. Switching cameras stops the previous feed. Smooth mode targets up to 15 JPEG frames per second; Low bandwidth targets up to 5. Actual speed depends on camera, recorder, network, and browser response time. The **Settings** page contains the personal System/Light/Dark theme choice. Administrators also see recorder configuration, SSO, shared branding, webhook receivers, API tokens, and account settings. Operators can change only their own browser theme there.

To verify a real ExacqVision recorder after deployment, use **Settings → Run recording checks** and wait for the batch result. A camera with recent motion footage should report playback verified. Cameras with no footage report that fact separately; inspect error rows individually. Recorder capability badges update only from actual successful checks, and cannot be verified from synthetic tests alone.
