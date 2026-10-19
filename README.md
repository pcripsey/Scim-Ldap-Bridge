# SCIM LDAP Bridge

A Docker-ready SCIM/LDAP synchronization service with an embedded SQLite database.
Synchronization supports `ldap_to_scim`, `scim_to_ldap`, and `bidirectional` modes.
Dry-run mode is enabled and the automatic schedule is disabled by default.

## Run With Docker

Generate a random administrator token in your terminal, then start the service:

```bash
export BRIDGE_ADMIN_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
curl http://localhost:8000/healthz
```

Keep the token in your secret manager: the same token must be supplied after a
restart. An optional, distinct `BRIDGE_SCIM_TOKEN` enables inbound provisioning.
Both tokens must be at least 24 characters. Do not commit tokens to source control.
The port binds to localhost by default; use a TLS reverse proxy for remote access.

Open **http://localhost:8000/** and sign in with your administrator token. The
Docker build compiles and bundles the React console; no separate web server or
Node.js runtime is required in the final container.

PowerShell alternative (generate a token once, then keep it securely for restarts):

```powershell
$env:BRIDGE_ADMIN_TOKEN = python -c "import secrets; print(secrets.token_hex(32))"
docker compose up --build -d
```

### Published Images (GitHub Container Registry)

The `Publish container image` GitHub Actions workflow tests the backend, builds
the bundled console and Linux AMD64 container, and publishes to
`ghcr.io/pcripsey/scim-ldap-bridge`. Pushes to `main` publish `latest` and `main`;
version tags such as `v1.2.3` publish `1.2.3`. Every build also publishes a
`sha-<short-commit>` tag. The workflow can also be run manually from Actions.
Publishing uses the workflow's built-in `GITHUB_TOKEN`; no registry secret is
required.

To run the published image instead of building locally, set your administrator
token as described above, then run in PowerShell:

```powershell
$env:BRIDGE_IMAGE = "ghcr.io/pcripsey/scim-ldap-bridge:latest"
docker compose pull
docker compose up --no-build -d
```

Keep `BRIDGE_IMAGE` set when managing this deployment. To update, repeat the pull
and up commands; the existing data volume is retained. Omit `BRIDGE_IMAGE` to
keep the original local-build behavior.

New GitHub packages may be private by default. For anonymous pulls, make the
container package public in its GitHub package settings. Otherwise authenticate
Docker to `ghcr.io` with a GitHub token that has `read:packages` access before
pulling. Never commit that token.

## Web Configuration Console

The responsive React/TypeScript console includes:

- **Overview:** connector configuration state, inventory counts, linked identities,
  synchronization status, recent runs, and events.
- **Connections:** SCIM URL/token and LDAP URL, bind DN/password, base DN, and StartTLS.
  Test saved connectors before syncing. Saved credentials are never returned;
  explicitly choose to replace or clear them, otherwise they remain unchanged.
- **Synchronization:** direction, conflict policy, dry-run/live mode, automatic
  scheduling, interval (30-86,400 seconds), and manual runs.
- **Inventory:** paginated, source/type-filtered cached resources, presence state,
  and a read-only decrypted attribute inspector.
- **Activity:** recent runs, paginated operation history, and recent events.
- **System:** inbound SCIM availability, deployment settings, and backup guidance.

The admin token is held only in memory, never in local/session storage or URLs.
Reloading or signing out clears the session. Use HTTPS for remote access.
Status refreshes every five seconds; inventory and operation lists have explicit
refresh buttons. Poll failures are visible and disable manual sync until recovery.
Draft configuration survives navigation between console sections and warns before
closing the page. Save or discard edits before testing connections or starting a
manual run. Saving is blocked during a running directory operation; server
validation and authorization remain authoritative.

Enabling live writes, changing connector identity (which resets baselines and
inventory), or clearing credentials requires confirmation. Live manual runs also
require confirmation. The schedule always uses **persisted** settings, so an
already-enabled schedule continues using the previous policy until edits are saved.
Start with dry runs, review the operation plan, then intentionally enable live mode.

The console manages every setting currently exposed by the bridge, not the host
or external directories. Deployment tokens, TLS trust, data paths, ports, and
container settings stay server-managed. Rotate environment tokens by updating
the deployment and restarting. Inventory is read-only; groups, deletion,
password writes, custom mappings, and interactive conflict resolution are not
implemented. Resolve conflicts in the authoritative directories and rerun sync.

### Run Locally (PowerShell)

Requires Python with the project dependencies and Node.js 22+ for building.
Run from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Push-Location web
npm ci
npm run build
Pop-Location
$env:BRIDGE_ADMIN_TOKEN = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe -m uvicorn bridge.app:app --host 127.0.0.1 --port 8000 --workers 1
```

Open http://127.0.0.1:8000/. Supply the value of `$env:BRIDGE_ADMIN_TOKEN` at sign-in
(keep it in a secret manager to reuse after restarts). Do not run the app file
directly; use the module-based Uvicorn command above. For hot-reload development,
keep the backend running and run `npm run dev` in `web` in another terminal.
Open the Vite URL (normally http://127.0.0.1:5173); it proxies management requests
to the backend on port 8000. Production serves UI and API from the same origin,
without CORS or external/CDN assets. Rebuild the console after frontend changes.

## Database

SQLite runs inside the service, with no separate database container required.
The Docker named volume `bridge-data` contains:

| File | Purpose |
| --- | --- |
| `/data/bridge.db` | Configuration, resource inventory, sync baselines, operations, runs, and events |
| `/data/bridge.db-wal`, `/data/bridge.db-shm` | SQLite write-ahead logging files, when present |
| `/data/encryption.key` | Key required to decrypt stored configuration and resource data |

Configuration (including connector credentials), resource payloads, planned-write
payloads, and identity baselines are encrypted before storage. Inventory preserves
nested JSON attributes and extension objects supplied by the connectors, rather
than requiring a database column for each attribute. Password attributes are
excluded from inventory, operations, and baselines. Operational metadata such as
usernames, sources, timestamps, and statuses is not encrypted.

Each synchronization run reads both connectors completely before atomically
storing its inventory and operation plan. Live writes are recorded as `planned`,
then `applying`, and finally `applied` or `failed`. Dry runs are stored as `preview`
and conflicts as `conflict`. A restart marks unfinished work `interrupted`; it
does **not** replay a potentially completed remote write. Run synchronization again
to read current remote state and build a fresh plan.

The inventory retains each resource's last observed data. Missing resources are
marked absent, not deleted from the cache. Changing a connector's identity clears
inventory and baselines. Operations follow the most recent 200 runs; event history
is capped at 2,000 entries. The inventory is the latest observed state, not a full
historical archive or the authoritative directory.

### Persistence And Backups

`docker compose restart`, image updates, and container replacement retain the named
volume. `docker compose down` also retains it. **Do not use `docker compose down -v`
unless you intend to delete all configuration, synchronization data, and keys.**

For a consistent backup, stop the service and copy the entire data directory:

```bash
docker compose stop bridge
docker compose cp bridge:/data ./bridge-backup
docker compose start bridge
```

Store the backup securely, including `encryption.key`. Losing the key makes encrypted
records unrecoverable. Since the key lives alongside the database, volume access
must be restricted; this is application-level encryption, not an external KMS or
full-database encryption. Existing plaintext baselines are migrated on startup;
historical backups may still contain their original plaintext.

Run one service instance and one Uvicorn worker per data volume. SQLite and the
in-process synchronization lock are not a multi-replica coordination mechanism.
For local development, `BRIDGE_DATA_DIR` defaults to `./data`.

## Management API

All `/api/` endpoints require `Authorization: Bearer <BRIDGE_ADMIN_TOKEN>`.
Provisioning credentials cannot access management data.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/status` | Sync status, database inventory counts, operation totals, runs, and events |
| `GET /api/settings` | Current configuration with connector secrets redacted |
| `PUT /api/settings` | Update configuration; omitted secrets remain unchanged |
| `POST /api/sync` | Start a manual run using persisted configuration |
| `POST /api/test/scim` or `/api/test/ldap` | Verify saved connector settings |
| `GET /api/data/resources` | Paginated resource metadata, without payloads |
| `GET /api/data/resource?source=scim&key=ada` | Read an authorized resource's decrypted attributes |
| `GET /api/data/operations` | Paginated operation history, without write payloads |

Inventory accepts `source=scim` or `source=ldap`, `resource_type` (default `Users`),
`limit` (1-1,000), and `offset`. Operation history accepts `limit` and `offset`.
The storage model can hold users, groups, and arbitrary JSON resource types;
the current synchronization connectors populate users only.

Example direction configuration:

```bash
curl -X PUT http://localhost:8000/api/settings \
	-H "Authorization: Bearer $BRIDGE_ADMIN_TOKEN" \
	-H 'Content-Type: application/json' \
	-d '{"direction":"ldap_to_scim"}'
```

## Current Compatibility

The inbound SCIM 2.0 User service exposes `/ServiceProviderConfig`, `/Schemas`,
`/ResourceTypes`, and User list/read/create/replace/patch endpoints under `/scim/v2`.
It supports SCIM filter expressions provided by the schema filter library, with
pagination capped at 1,000 results per page. User responses include `meta.resourceType`
and `meta.location`. Inbound writes are blocked during dry runs. The advertised feature
set intentionally excludes bulk, sorting, ETags, and password changes.

The console's **Attribute mapping** section can discover SCIM schemas/resource types
and LDAP attribute names and samples, excluding sensitive-looking attributes. Map
SCIM paths to LDAP attributes with per-rule directions, inspect a sample comparison,
and save the mapping with the rest of the encrypted settings. Defaults map `userName`
to `uid`, names to `givenName`/`sn`, `displayName` to `displayName`, and primary email
to `mail`. SCIM paths are simple dotted paths, with extension attributes addressable
by their full extension URN and attribute name. Mapping values are copied as-is; this
is not a transformation language or a general-purpose schema/mapping engine.

This is not yet a fully SCIM-compliant or Entra-validated connector. Only User is
advertised as a resource type. Group provisioning, deactivation, deletion, password
operations, configurable attribute transforms/defaults, full multivalue mapping, and
arbitrary custom schema discovery/provisioning are not implemented. PATCH supports
only `name`, `name.givenName`, `name.familyName`, `displayName`, and `emails` paths,
not every writable User attribute or every SCIM path/value combination. LDAP writes still use the
`inetOrgPerson` object classes and require a family name. Validate actual Entra
provisioning behavior in a test tenant before production use.

LDAP uses certificate-verified LDAPS (`ldaps://`, port 636, implicit TLS) or StartTLS
on `ldap://` (port 389). Unencrypted `ldap://` without StartTLS is rejected unless
`ldap_allow_insecure` is explicitly enabled; it sends the bind password and directory
data in clear text, so use it only on a trusted, isolated network. Remote SCIM supports HTTP or
HTTPS; use HTTPS outside an isolated development environment. Usernames are the
current matching key. Treat renames and missing linked users as manual conflicts.

Authenticated administrator endpoints `POST /api/discovery/scim` and
`POST /api/discovery/ldap` read saved connector settings and return schemas (SCIM),
resource types, attribute names, and up to three sample values per attribute. Use
the discovery buttons only with trusted directories; returned sample values may
contain personal data.

## Development Checks

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

The focused database tests are in `tests/test_store.py` and `tests/test_service.py`.

Console browser tests use isolated, mocked management APIs (no live directory
writes), and exercise auth, credential preservation/clearing, configuration saves,
confirmations, tests, sync triggers, errors, polling, inventory, and mobile layout:

```powershell
Push-Location web
npm ci
npm run build
npx playwright install chromium
npm test
Pop-Location
```