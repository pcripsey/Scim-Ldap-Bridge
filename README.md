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

These credentials serve different purposes:

- `BRIDGE_ADMIN_TOKEN`: administrator console and management API access.
- `BRIDGE_SCIM_TOKEN`: optional, distinct token for clients provisioning into this
  bridge's `/scim/v2` endpoints.
- Saved connector setting `scim_token`: outbound authentication to the remote
  SCIM provider; it is not either of the deployment tokens.

The saved outbound `scim_url` must be the **remote provider's SCIM base URL**.
Do not point it at this bridge's own `/scim/v2`, even through a public proxy alias.
Inbound provisioning is an LDAP-backed service, not a proxy to the outbound provider.

Set optional deployment variable `BRIDGE_SCIM_SELF_URLS` to a comma-separated list
of this bridge's full inbound SCIM base URLs, including public proxy aliases and
internal service addresses (for example,
`https://bridge.example.com/scim/v2,http://bridge:8000/scim/v2`).
Include any proxy path prefix. These endpoints are rejected on settings save and
before outbound connector use, including scheduled jobs using existing settings.
Scheme, hostname case/trailing dot, default port, and trailing slash are normalized;
other paths or ports on a shared host remain available for a separate provider.
Localhost/port combinations are not assumed to belong to the bridge: list the ones
used by your deployment explicitly. No DNS lookup or authenticated probe is used
to guess ownership.

Settings save also rejects the inbound endpoint on the current request's base URL.
An outbound per-process `X-SCIM-Bridge-Caller` marker catches self-calls through
unlisted proxy aliases when they return to the same process, rejecting them with
400 before authentication or LDAP access. The marker never grants access and is
not a credential or a request correlation ID. Proxies must preserve this header
for runtime detection; list aliases explicitly if headers are stripped or routing
can reach another process. Existing bad settings remain readable so they can be
corrected. Keep the single-instance/worker deployment restriction below.

### Pull users from Microsoft Entra (opt-in)

These are **different topologies**:

- **Entra pushes:** an enterprise application's outbound provisioning client calls
  this bridge's inbound `/scim/v2` using `BRIDGE_SCIM_TOKEN`.
- **Bridge pulls:** select **Microsoft Entra — OAuth pull** in Connections. This
  bridge reads Entra's SCIM Provisioning API and reconciles user attributes to LDAP.
  Never set the outbound provider URL to this bridge.

The existing **generic SCIM / static bearer token** mode remains the default for
saved installations. Its `scim_token` and index pagination are unchanged.
`BRIDGE_ADMIN_TOKEN` authenticates console/admin requests; `BRIDGE_SCIM_TOKEN`
authenticates incoming provisioning; Entra OAuth credentials authenticate outgoing
Entra reads. None of these credentials is interchangeable. **An Entra client secret
is not a bearer token** and must not be entered in the generic SCIM token field.

#### Microsoft prerequisites and setup

Contract checked on 2026-10-19 against Microsoft's official documentation source,
revision `d9dc367c42d3607d97971aeded9785768175764f` (the two API pages are dated
2026-09-04). Microsoft Learn was unavailable from the development environment;
the linked official `MicrosoftDocs/entra-docs` sources were used instead:

- [Enable the API](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/enable-scim-api)
  ([source](https://github.com/MicrosoftDocs/entra-docs/blob/d9dc367c42d3607d97971aeded9785768175764f/docs/identity/app-provisioning/enable-scim-api.md)).
- [API reference](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/entra-id-scim-api-reference)
  ([source](https://github.com/MicrosoftDocs/entra-docs/blob/d9dc367c42d3607d97971aeded9785768175764f/docs/identity/app-provisioning/entra-id-scim-api-reference.md)).
- [Schema mapping](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/entra-id-scim-api-schema-documentation)
  ([source](https://github.com/MicrosoftDocs/entra-docs/blob/d9dc367c42d3607d97971aeded9785768175764f/docs/identity/app-provisioning/entra-id-scim-api-schema-documentation.md)).
- [Release notes](https://github.com/MicrosoftDocs/entra-docs/blob/d9dc367c42d3607d97971aeded9785768175764f/docs/fundamentals/whats-new.md):
  global GA in March 2026, US Government GA in June 2026; not a preview.

1. Obtain **Entra ID P1**, or a license containing P1, and an active Azure
   subscription. The SCIM Provisioning API is a **paid add-on**: Microsoft states
   that **every API call is billed**, monthly through the linked subscription.
   Dry runs, tests, and discovery still make billable reads. Check Microsoft's
   current pricing; no fixed price or free-read allowance is assumed here.
2. A Billing Administrator enables **Entra admin center → ID Governance →
   Dashboard → SCIM Provisioning API → Get Started**, selects an Azure subscription
   and resource group, and selects **Turn on**.
3. An Application Administrator/Cloud Application Administrator creates an app
   registration in the source tenant. Under **API permissions**, add Microsoft
   Graph **application** permission `User.Read.All`, and obtain administrator
   consent. This connector does not support delegated authentication.
4. For console schema discovery/mapping validation, also grant and consent
   `Group.Read.All`: Microsoft's discovery endpoints require both user and group
   read permissions. This does not enable group synchronization. No write
   permission is needed. Custom-security-attribute schema access additionally
   requires `CustomSecAttributeDefinition.Read.All`; this connector does not
   request that schema separately.
5. Under **Certificates & secrets**, create a client secret. Save its **value**
   securely and record its expiry. Enter the directory (tenant) ID, application
   (client) ID, and secret in Connections. Rotate it before expiry.

This implementation supports **public cloud and client secrets only**. The
resource base is fixed to `https://graph.microsoft.com/rp/scim`, with token requests
to `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token`, using
`grant_type=client_credentials` and `scope=https://graph.microsoft.com/.default`.
The requested audience/resource is Microsoft Graph, **not** `/rp/scim` or Graph
`/users`; Graph user responses are not substituted for SCIM. Certificate,
managed-identity, US Government, and other sovereign-cloud authentication are
not implemented, even where Microsoft offers those capabilities.

#### Safe initial configuration

Use the console secret controls, or send these settings to the authenticated
settings API with your own placeholders substituted (never commit credentials):

```json
{
  "scim_provider": "entra",
  "scim_url": "https://graph.microsoft.com/rp/scim",
  "entra_tenant_id": "<directory-tenant-GUID>",
  "entra_client_id": "<application-client-GUID>",
  "entra_client_secret": "<client-secret-value>",
  "scim_filter": "userName ew \"@example.org\"",
  "direction": "scim_to_ldap",
  "enabled": false,
  "dry_run": true,
  "confirm_scope_reset": true
}
```

Configure the existing LDAP connection and mappings separately. Secrets are
encrypted with the existing settings store and never returned by settings reads;
`entra_client_secret_configured` reports presence only. Omitting a credential
preserves it, supplying a nonempty value replaces it, and `""` clears it.
OAuth access tokens are cached **only in the connector instance's memory**,
renewed before expiry, and discarded when it closes. Credentials are sent only
to the fixed Microsoft authority using a separate, non-traffic-logging client.
Redirects and environment proxies are disabled for both Entra clients.
Authentication/read failures stop the operation without automatic retries;
there are no Entra writes, including on 401 responses.

#### Scope, discovery, and reconciliation limits

The bridge accepts this deliberately small subset of Microsoft's user filters:

| Source filter | Meaning |
| --- | --- |
| Empty | All users visible to the application |
| `userName eq "person@example.org"` | Exact username |
| `userName ew "@example.org"` | Username suffix |
| `id eq "<user-id>"` | Exact resource ID |
| `externalId eq "<external-id>"` | Exact external ID |
| `groups.value eq "<group-id>"` | Direct user membership, not transitive membership |
| `active eq true` / `active eq false` | Active-state scope, **not** LDAP deactivation |

String operands must be nonempty double-quoted JSON strings. Boolean literals
are case-insensitive. Compound filters, `not`, other operators, and extension
filter attributes are not accepted by this connector, even though Microsoft
supports some of them. Parameters are encoded, not appended as URL fragments.
The same saved filter applies to connection tests, discovery samples, mapping
validation, manual synchronization, and scheduled synchronization.

Reads use documented lowercase `/users` and `resources`, request `count=100`,
and carry opaque `nextCursor` values in the next request's `cursor` parameter.
Cursors are never followed as URLs. The connector treats absent, null, or empty
`nextCursor` as completion; Microsoft does not explicitly enumerate terminal
representations. It neither requires `totalResults` nor compares it with the
accumulated count: the documented cursor examples omit that field. Cursor expiry,
snapshot/count consistency, and empty-page behavior are not guaranteed by the
reviewed documentation. Empty pages with a continuing cursor, repeated cursors,
duplicate/malformed users, failed pages, and inventories above 10,000 users fail
closed before staging reconciliation. A failed enumeration does not replace
inventory or synchronization baselines.

Discovery calls real lowercase `/schemas` and `/resourcetypes`, whose documented
list responses use uppercase `Resources`, then enumerates the complete scoped
user inventory for samples. It does not fabricate schemas or require generic
index pagination. Microsoft supports SCIM create/PATCH/delete operations, but
this connector intentionally rejects remote writes and requires `scim_to_ldap`.
Ordinary Entra `extension_{appId}_{property}` directory extensions are not exposed
by the documented SCIM schema.

Changing provider, tenant, client ID, or source filter requires explicit console
confirmation (API: `confirm_scope_reset=true`), clears inventory and baselines,
and cancels outstanding planned operations. Changing connector URLs or LDAP
identity retains the existing reset behavior. **Review the new scope and baseline
before live LDAP writes.** Start with scheduling disabled and `dry_run=true`,
test connections, inspect discovery/mappings, and review a manual dry-run plan
before allowing writes or scheduling.

The selected LDAP service profile applies; the bridge requires a nonempty
`sn`/family name for every profile. This is user-profile reconciliation, **not** complete identity
lifecycle management: filtering out or missing users does not delete/deactivate
LDAP accounts. Group provisioning, deletion, deactivation, and password
synchronization remain unsupported. No live Entra authentication or directory
writes were performed to validate this connector.

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
- **Connections:** separate inbound **SCIM push** deployment instructions,
  outbound **generic SCIM** or **Microsoft Entra ID OAuth pull** credentials,
  and LDAP service selection, URL, bind credentials, base DN, and StartTLS.
  Test saved connectors before syncing. Saved credentials are never returned;
  explicitly choose to replace or clear them, otherwise they remain unchanged.
- **Attribute mapping:** a dedicated page for SCIM-to-LDAP mappings, attribute
  discovery, validation and preview, and the opt-in **Ignore unsupported or
  unmapped fields** policy for inbound provisioning.
- **Synchronization:** direction, conflict policy, dry-run/live mode, automatic
  scheduling, interval (30-86,400 seconds), and manual runs.
- **Inventory:** paginated, source/type-filtered cached resources, presence state,
  and a read-only decrypted attribute inspector. Users received through inbound
  SCIM push that are not yet in LDAP are listed with source **SCIM push** and
  status **Waiting to be synchronised to LDAP**, and can be discarded.
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

Enabling live writes, enabling the ignore-unsupported-fields policy, changing
connector identity (which resets baselines and inventory), or clearing credentials
requires confirmation. Live manual runs also
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
| `/data/bridge.db` | Configuration, resource inventory, queued inbound users, sync baselines, operations, runs, and events |
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

### Queued inbound SCIM users

An inbound SCIM `POST /scim/v2/Users` is validated and then stored, encrypted, in
the database **before** the bridge attempts to create it in LDAP. When LDAP accepts
the user it is removed from the queue and the LDAP inventory is refreshed. If dry
run is enabled, another directory operation is running, or LDAP is unreachable or
rejects the write, the request still returns `201 Created` and the user remains
queued with status `waiting_for_ldap` (plus the last error type and attempt count).
While live mode is on, the service retries queued users every 30 seconds. Queued
users are returned by inbound SCIM reads and can be updated with `PUT`/`PATCH`
until they are created. A new user whose `userName` already exists in LDAP is
rejected with `409` when the last LDAP inventory already contains it; one that is
only discovered when the queue is retried is marked `conflict` and is not retried or overwritten; review it and discard it from
Inventory (`DELETE /api/data/pending?key=<userName>`). Queued users are kept when
connector settings change and are written to the LDAP directory configured when
they are retried.

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

## Traffic Logs And Troubleshooting

The standard-library `bridge.traffic` logger emits structured JSON to stdout.
View it with `docker compose logs -f bridge`, or
`docker logs -f <container-name>`. In Unraid, click the container icon and select
**Logs**. Traffic logs are separate from the console's persisted Activity history;
polling does not add per-request SQLite records.

| Environment variable | Default | Behavior |
| --- | --- | --- |
| `BRIDGE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `OFF` |
| `BRIDGE_LOG_POLLS` | `false` | Successful `/healthz` and `/api/status` requests log at `DEBUG`; `true` promotes them to `INFO` |

Failures are not demoted as successful polls. Change these deployment variables
and recreate the container (`docker compose up -d`) to apply them. Set
`BRIDGE_LOG_LEVEL=DEBUG` to enable **redacted attribute/payload logging**.
`INFO`, `WARNING`, and `ERROR` remain metadata-only; `OFF` emits nothing.

Metadata entries include `timestamp`, `level`, `direction`, `protocol`, `operation`,
`result`, `duration_ms`, and `request_id`, plus safe operation-specific metadata:

- Inbound HTTP requests receive a generated ID returned as `X-Request-ID`;
  client-supplied request IDs are ignored. Routes use templates with resource IDs
  redacted; unknown paths are redacted and query strings are never logged.
  Forwarded client IP headers are neither trusted nor used. Optional `CF-Ray`
  metadata is strictly validated but remains untrusted, never authentication.
- Every outbound SCIM send is recorded, including each pagination request,
  discovery, and writes. Logs include HTTP status or a safe transport exception
  class, destination scheme/host/port, and a redacted path template, not query
  strings or URL credentials. Only allowlisted response media types and validated
  upstream `CF-Ray` or UUID/hex `X-Request-ID` values are retained.
- LDAP logs include TLS mode, operation, numeric LDAP result/category, and
  aggregate result count where applicable. Connection, StartTLS, and bind are
  one `connect_starttls_bind` event (or `connect_bind`), covering ldap3's
  `auto_bind` lifecycle. Search logging also covers failures during lazy result
  consumption. DNs and filters are only included in the separate DEBUG events.
- Background work has its own generated request ID. A manually triggered job
  also has `parent_id` linking it to the initiating request.

At DEBUG, separate events contain a sanitized `data` object and the same
`request_id` as the metadata events (background jobs retain their existing
`parent_id` link on the job event):

- `request_payload` / `response_payload`: inbound `/scim/v2/Users` resource
  traffic and outbound SCIM Users/Groups traffic, including Entra resource reads.
  Inbound JSON is observed **before validation**, including rejected `active`,
  `groups`, or password fields and PATCH operations. Values retain JSON types,
  nested extension attributes, arrays, booleans, and nulls.
- SCIM responses include resources, error status, and known static bridge
  validation details. Untrusted free-form error `detail`, `message`, and
  `error_description` values are redacted rather than risking echoed credentials.
- `search_request` / `search_entry`: LDAP base DN, filter, requested attributes,
  and individual returned entry attributes.
- `add_attributes` / `modify_attributes`: LDAP DN, exact attribute sets,
  object classes for adds, and ldap3 modification codes for changes
  (`2` means `MODIFY_REPLACE`).

Management/settings API bodies and OAuth/token exchanges are never captured.
Headers, bind credentials, and connection objects are never included.
Shared recursive redaction replaces sensitive values with `<redacted>`,
preserving attribute names. This includes case-insensitive password,
`userPassword;binary`, `unicodePwd`, credential, token, secret, private/encryption
key names, and SCIM extension equivalents. Sensitive PATCH paths redact their
`value`; embedded PATCH path filters and URL/query-like values are suppressed.
Binary data is omitted, dates use ISO format, and unknown objects are not
converted with `repr`. Sanitization or logging failures discard the event.

Capture is limited to 32 KiB per JSON body and serialized event, depth 8,
50 items per container, 500 visited values, and 512 characters per string.
LDAP searches log at most 50 entries plus a truncation event per search.
Limits produce explicit `<truncated>` or `{"truncated":true}` indicators;
oversized JSON is omitted entirely, not logged as an unsafe partial document.
Malformed/non-JSON bodies produce only safe capture-state metadata.
Unconsumed outbound HTTP streams are not read just for logging.

**DEBUG logs contain personal directory data. Restrict log access and retention,
use DEBUG only while troubleshooting, and disable it afterwards.** Redaction is
not a reason to keep DEBUG enabled routinely. Raw Uvicorn access logs and
httpx/httpcore/ldap3 logging remain disabled; Uvicorn exception tracebacks are
reduced to a safe exception class.

Illustrative sanitized entries (synthetic metadata):

```json
{"timestamp":"2026-01-01T12:00:00.000+00:00","level":"INFO","direction":"inbound","protocol":"http","operation":"request","result":"success","duration_ms":2.1,"request_id":"11111111111141118111111111111111","method":"GET","path":"/api/status","status":200}
{"timestamp":"2026-01-01T12:00:01.000+00:00","level":"WARNING","direction":"outbound","protocol":"scim","operation":"request","result":"forbidden","duration_ms":41.2,"request_id":"22222222222242228222222222222222","method":"GET","path":"/Users","status":403,"scheme":"https","host":"scim.example.com","port":443}
{"timestamp":"2026-01-01T12:00:02.000+00:00","level":"INFO","direction":"outbound","protocol":"ldap","operation":"connect_starttls_bind","result":"success","duration_ms":18.4,"request_id":"33333333333343338333333333333333","scheme":"ldap","host":"ldap.example.com","port":389,"tls_mode":"starttls","ldap_result":0}
```

The successful poll example requires `BRIDGE_LOG_POLLS=true` at `INFO`.

Illustrative DEBUG events (fake directory data, abbreviated metadata):

```json
{"level":"DEBUG","direction":"inbound","protocol":"scim","operation":"request_payload","request_id":"11111111111141118111111111111111","data":{"userName":"ada@example.invalid","name":{"familyName":"Example"},"active":false,"password":"<redacted>"}}
{"level":"DEBUG","direction":"inbound","protocol":"scim","operation":"response_payload","request_id":"11111111111141118111111111111111","status":400,"data":{"status":"400","detail":"Account status, passwords, and group provisioning are not supported by this mapping."}}
{"level":"DEBUG","direction":"outbound","protocol":"ldap","operation":"modify_attributes","request_id":"22222222222242228222222222222222","data":{"dn":"uid=ada,ou=People,dc=example","changes":{"sn":[[2,["Example"]]],"userPassword":"<redacted>"}}}
```

### Diagnosing Provisioning And Connector Failures

1. Distinguish Entra provisioning **into this bridge** from this bridge's
   **outbound connector**. Verify the appropriate URL and token for that direction;
   do not substitute the administrator token for an inbound or saved outbound token.
2. Correlate the returned bridge `X-Request-ID` with traffic logs and manual job
   `parent_id`. The generic `/api/test/{connector}` response contract is unchanged;
   its correlated outbound logs explain the remote status or safe failure class.
   An inbound `401` is an authentication rejection; an inbound `503` indicates
   unavailable service/configuration. An outbound SCIM `403` is a rejection on the
   remote request, not proof that inbound bridge authentication failed.
3. Compare Entra provisioning diagnostics, reverse-proxy/Cloudflare events, and
   bridge timestamps/statuses. An HTML response alone does not identify its source
   or prove Cloudflare blocked it. Investigate endpoint configuration, application
   authentication, and proxy policy rather than assuming any one cause. Do not
   broadly bypass WAF or authentication protections.
4. Requests blocked before reaching the app cannot appear in its logs. Absence of
   an entry is not proof of a block: also check log level (`OFF`/poll suppression),
   container/version, retention, and log availability.
5. For credential/decryption failures such as `InvalidToken`, keep the original
   `encryption.key` and database together and verify the mounted data directory.
   The exception class is safe diagnostic information; do not share keys, database
   contents, tokens, or raw payloads. Rotate any credentials exposed during
   troubleshooting and share only sanitized metadata.

### Diagnosing A Sync 409 Or Self-Target Rejection

- Compare the saved outbound SCIM destination with the bridge's inbound URLs and
  the deployment's DNS/reverse-proxy routes. The outbound log path `/Users` is
  relative to the configured base URL, so it can represent an actual request to
  this bridge's `/scim/v2/Users`.
- Match outbound `upstream_request_id` to inbound `request_id`. The former is read
  from the response's validated `X-Request-ID`, not forwarded in the request.
  The outbound `request_id` instead belongs to its worker; the final `reconcile`
  event shares that ID and links a manual trigger through `parent_id`.
- Inbound SCIM errors expose a fixed `X-SCIM-Bridge-Error` category, also logged
  as allowlisted `reason` metadata: `self_target` (400), `directory_busy` (409,
  including reads), `dry_run` (409 on writes), or `uniqueness` (409 on create).
  Outbound logs retain these categories when present; remote headers remain
  untrusted diagnostic metadata. Arbitrary header values and bodies are not logged.
- A reconciliation result of `conflicts` with `reason=planner_conflict` is an
  identity/baseline decision, not an HTTP 409. A remote 409 without a bridge
  category remains an upstream conflict requiring provider-specific investigation.
- Correct a self-target by saving the actual remote provider base URL and its
  provider token, then test the connection and rerun a dry-run sync. Changing the
  connector URL clears inventory and baselines; review the new plan before live
  writes. If only inbound provisioning is intended, leave the outbound sync schedule
  disabled rather than configuring the bridge as its own remote provider.
- Do not remove the directory lock or retry blindly. A genuine concurrent
  provisioning request remains rejected while a sync holds the lock; self-call
  retries inside that sync cannot succeed while the same lock is held.

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
| `DELETE /api/data/pending?key=ada` | Discard a queued inbound user that has not been created in LDAP |

Inventory accepts `source=scim`, `source=ldap`, or `source=inbound` (queued inbound
users waiting for LDAP), `resource_type` (default `Users`),
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
and `meta.location`. During dry runs, inbound creates are queued in the database
instead of being written to LDAP, and updates to existing LDAP users are blocked. The advertised feature
set intentionally excludes bulk, sorting, ETags, and password changes.

The console's **Attribute mapping** page can discover SCIM schemas/resource types,
attribute type/multiplicity metadata when the SCIM schema provides it, and LDAP
attribute names and samples (LDAP type/multiplicity is reported as unavailable).
Sensitive-looking attributes are excluded. Map SCIM paths to LDAP attributes with
per-rule directions, validate mappings against both connected sources, inspect a
sample comparison, and save the mapping with the rest of the encrypted settings.
Defaults map `userName`
to `uid` (`sAMAccountName` for AD DS), names to `givenName`/`sn`, `displayName` to `displayName`, and primary email
to `mail`. SCIM paths are simple dotted paths, with extension attributes addressable
by their full extension URN and attribute name. Mapping values are copied as-is; this
is not a transformation language or a general-purpose schema/mapping engine.

### LDAP service profiles and required attributes

Choose **Connections → LDAP service** before customizing mappings:

| Service | Default username attribute | User search / creation class | Required attributes |
| --- | --- | --- | --- |
| Generic LDAP (default) | `uid` | `inetOrgPerson` | Username identity, `cn`, `sn` |
| OpenLDAP | `uid` | `inetOrgPerson` | Username identity, `cn`, `sn` |
| 389 Directory Server / Red Hat Directory Server | `uid` | `inetOrgPerson` | Username identity, `cn`, `sn` |
| Microsoft Active Directory Domain Services | `sAMAccountName` | `user`, restricted to `objectCategory=person` for searches | Username identity, `cn`; `sn` additionally required by this bridge |

All profiles also default to `givenName`, `sn`, `displayName`, and `mail` for
the corresponding SCIM name, display name, and email fields. `userName` must
be mapped in both directions and unique in the search base. Supply
`name.familyName` in the source; surnames are never fabricated. For inetOrgPerson,
`cn` defaults to display name or username unless explicitly mapped, and the
username attribute forms the RDN. AD uses `cn=<escaped userName>` for new DNs;
display-name updates do not rename existing AD accounts.

AD creates **disabled** accounts (`userAccountControl=514`) by default. Opt in to
**Enable new AD accounts** in Connections (`ad_enable_new_accounts=true` in the
API) to initialize a cryptographically random password over certificate-verified
LDAPS or StartTLS, then enable the newly created account (`userAccountControl=512`).
The password is generated in memory, never returned or persisted, and is not
synchronized from the source. Users need a separate password-reset process.
Delegate user creation, password reset, and account-control permissions to the
bind identity. Referral following is disabled for this option.

Creation is ordered: add disabled, set password, enable only after success.
Password-policy rejection leaves the new account disabled. Activation errors or
network timeouts require administrator review; the directory may have committed
an operation before a connection failure. Partial accounts are not deleted.
Retries treat already-created accounts as existing and do not reset their
passwords or activate them. Existing accounts are always unchanged by this option.
Dry runs do not initialize passwords or enable accounts. Changing LDAP service
in the console clears the opt-in. Test against your domain password policy before
production use; custom password filters may reject generated passwords.

Without this option, set passwords and activate accounts using native AD tooling. AD naming,
object class, and account status attributes cannot be mapped. Use an appropriate
OU/base DN, delegated create/update permissions, and directory-valid usernames
(including AD's `sAMAccountName` constraints). AD DS is not Microsoft Entra ID.
Profiles do not provision POSIX/FreeIPA accounts or discover custom schema MUST
attributes. Local schema extensions may require additional mappings.

Changing service in the console asks before replacing **all** mappings with the
profile defaults. Saving a service change clears cached inventory and baselines,
pauses scheduling, and enables dry run on the server too. Test and inspect a dry
run before allowing writes. Existing saved installations retain the generic
profile and their mappings. API clients can set `ldap_service` to `generic`,
`openldap`, `389ds`, or `active_directory`; when changing service, omitted
`attribute_mappings` selects defaults, while an explicit list preserves custom
mappings. The console highlights identity, schema-required, bridge-required,
and automatically generated attributes. Discovery samples do not prove schema
compliance.

### Password synchronization feasibility

There is intentionally **no password-sync toggle**; the new-account initialization
option above is not password synchronization. SCIM's `password` attribute
is write-only, so reconciliation cannot retrieve existing passwords. Entra OAuth
pull does not expose existing user passwords; Entra enterprise-app SCIM
provisioning is not a channel for exporting users' existing passwords. The
LDAP bind password is a service-account credential, not a user's password.

For **AD DS → Entra** password hash synchronization, use Microsoft Entra Connect
Sync or Cloud Sync where supported; that does not provide **Entra → LDAP**
password export. Manage LDAP password resets using native directory tooling or
a separately designed password-change integration. Such an integration would
need an actual password-change source, explicit one-way opt-in, verified TLS,
directory-specific password operations and permissions, and guarantees that
passwords never enter inventory, operations, responses, or logs. It cannot be
implemented safely by simply allowing password attribute mappings.

Password mappings remain blocked. Inbound password fields are rejected by
default or discarded by the ignore-unsupported-fields policy; discarding them
does not set or synchronize passwords. Reference:
[SCIM password definition (RFC 7643 §4.1.1)](https://www.rfc-editor.org/rfc/rfc7643#section-4.1.1),
[Microsoft password hash synchronization](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs).
No live password synchronization or AD DS integration was tested.

### Ignoring unsupported or unmapped inbound fields

By default, inbound SCIM provisioning is **strict**: a User create, replace, or patch
containing `active`, `password`, or `groups` is rejected with HTTP 400
(`Account status, passwords, and group provisioning are not supported by this mapping.`).
Some identity providers, including Microsoft Entra, always send `active`, so every
create fails in strict mode.

The **Ignore unsupported or unmapped fields** checkbox in the console's **Attribute
mapping** section (setting `ignore_unsupported_fields`, default `false`) changes this
for inbound `/scim/v2/Users` create, replace, and patch requests only. It is saved
with the other encrypted settings; installations saved before this option existed
remain strict. When enabled:

- Create and replace keep only attributes the inbound mapping can apply to LDAP:
  paths mapped `both` or `scim_to_ldap` (nested and extension paths included), plus
  mapped `name.familyName` and `displayName` because LDAP `sn`/`cn` derive from them.
  For `emails.value`, only each email's `value` and `primary` are kept. `active`,
  `password`, `groups`, `externalId`, client-supplied `id`/`meta`, `ldap_to_scim`-only
  paths, and any other unmapped attributes or sub-attributes are dropped before
  mapping and validation. `schemas` keeps the core User schema and retained extensions.
  Dropped values are neither written to LDAP nor echoed in responses.
- PATCH skips operations whose path addresses no inbound-mapped attribute (for example
  `active`, `password`, `groups[...]`, `externalId`, or an unmapped extension
  attribute) and removes unmapped keys from path-less `value` objects and unmapped
  sub-attributes from `name`/`emails` values. An operation left with nothing to apply
  is skipped, so ignored fields never clear existing data. Remaining operations are
  applied as usual. If **every** operation is ignored, the PATCH is a no-op: no LDAP
  write occurs and the unchanged resource is returned with `200 OK`.
- Validation is otherwise unchanged. The PATCH envelope (1-50 `Operations`), operation
  verbs, malformed paths, mapped paths this PATCH implementation cannot apply
  (including filtered paths such as `emails[type eq "work"].value`), `userName`
  changes, invalid types on retained fields, authentication, dry-run blocking, and
  the directory lock still produce the same errors.

**Required attributes are still required.** `userName` must be a nonempty string, and
LDAP `inetOrgPerson` entries require `name.familyName`. The bridge never invents a
surname: a request such as `{"userName": "...", "active": true, "displayName": "..."}`
still fails with `name.familyName is required by the inetOrgPerson schema.` after
`active` is ignored. Map a surname in the provider (for example, Entra `surname` to
`name.familyName`) before relying on this option.

**Lifecycle risk:** this option does not add account enable/disable, password, or
group support, and the advertised capabilities are unchanged. An ignored
`active: false` **does not disable or deprovision** the LDAP account; the provider
will report success while the account remains usable. Handle deactivation in the
authoritative directory or another process. Outbound synchronization is not affected.

This is not yet a fully SCIM-compliant or Entra-validated connector. Only User is
advertised as a resource type. Group provisioning, deactivation, deletion, password
operations, configurable attribute transforms/defaults, full multivalue mapping, and
arbitrary custom schema discovery/provisioning are not implemented. PATCH supports
only `name`, `name.givenName`, `name.familyName`, `displayName`, and `emails` paths,
not every writable User attribute or every SCIM path/value combination (see the
ignore option above for skipping unsupported paths). LDAP writes use the selected
profile's `inetOrgPerson` or AD `user` object classes and require a family name. Validate actual Entra
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