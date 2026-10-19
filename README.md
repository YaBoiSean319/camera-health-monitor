# Camera Health Monitor

Camera Health Monitor is a browser-managed service for checking ExacqVision camera live video and motion recordings. It is designed to run in Docker on a VM that can reach the recorder and camera network.

> **Integration status:** Server configuration and persistent camera inventory are available. Installed-server Exacq compatibility is not verified. Discovery, live delivery/decoding, recording search, and recorded playback must be validated independently against the actual ExacqVision deployment. The current fixture does not verify stale/replayed sample detection; that behavior also requires validation against the installed interface where its evidence permits. No untested capability is reported as healthy.

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
| `GET` | `/api/v1/dashboard` | Operator or administrator | Read initial dashboard summary |
| `GET` | `/api/v1/monitoring` | Operator or administrator; `health:read` for tokens | Read scheduler progress, per-camera current results, due times, active jobs, and last successes |
| `GET` / `POST` | `/api/v1/servers` | Operator read / administrator write | List or add recorder connections |
| `GET` / `PUT` / `DELETE` | `/api/v1/servers/{server_id}` | Operator read / administrator write | Read, edit, or remove server connection |
| `POST` | `/api/v1/servers/{server_id}/discover` | Operator or administrator | Refresh camera inventory |
| `GET` / `POST` | `/api/v1/servers/{server_id}/capabilities` | Operator read / administrator probe | Read or probe independent capabilities |
| `GET` | `/api/v1/cameras` | Operator or administrator | List persistent inventory |
| `PUT` | `/api/v1/cameras/{camera_id}` | Administrator | Update per-camera overrides |
| `POST` | `/api/v1/cameras/{camera_id}/live-check` | Operator or administrator; `checks:run` for tokens | Start asynchronous live sample check (`202` with job ID; `501` for unverified Exacq) |
| `GET` / `DELETE` | `/api/v1/live-checks/{job_id}` | Operator or administrator; `health:read` to poll, `checks:run` to cancel | Poll a check result or cancel an active check |
| `POST` | `/api/v1/cameras/{camera_id}/recording-check` | Operator or administrator; `checks:run` for tokens | Start recording search and decode (`202` with job ID; `501` for unverified Exacq) |
| `POST` | `/api/v1/servers/{server_id}/recording-check` | Operator or administrator; `checks:run` for tokens | Start a recording check for each present camera |
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

Operator scopes are `health:read`, `history:read`, `incidents:acknowledge`, `checks:run`, and `maintenance:read`. Administrator tokens may additionally receive `maintenance:write`, `servers:read`, `servers:write`, `cameras:read`, `cameras:write`, `webhooks:read`, `webhooks:write`, `branding:write`, `auth:manage`, and `tokens:manage`. An administrator role sets the maximum possible authority, while each token still receives only its selected scopes. Browser sessions use the same role authorization rules without token scope restrictions. Current server and camera inventory routes require their corresponding read/write scopes; manual inventory discovery requires `checks:run`. New route handlers must explicitly declare both the minimum role and required token scope; unmapped future operations must not be treated as implicitly authorized.

Token issuance/revocation, local credential changes, OIDC configuration changes, and branding changes produce audit entries containing actor identity/type, action, resource, and timestamp. Audit records intentionally omit request bodies, bearer values, passwords, OIDC secrets, and webhook secrets. API tokens should be unique to an automation and stored in that automation's secret store. Avoid placing bearer values in URLs, command history, or diagnostic output. The interactive API explorer accepts a token in its Bearer token field and sends it only as an Authorization header.

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

For planned work, create a camera- or server-scoped maintenance window with an ISO-8601 start, end, and reason. Checks continue and health evidence is persisted throughout a temporary maintenance window. Health incident webhooks are suppressed; job completion events and webhook delivery behavior are unchanged. At the end time the scheduler (or a `GET /api/v1/maintenance`) finalizes the window and evaluates the newest persisted check result. A still-current warning/failure produces one current incident event; suppressed intermediate check transitions are not replayed. A successful latest result le