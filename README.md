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

The existing LDAP `inetOrgPerson` requirements still apply, including nonempty
`sn`/family name. This is user-profile reconciliation, **not** complete identity
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
and recreate the container (`docker compose up -d`) to apply them. `DEBUG` does
**not** enable payload logging.

Entries include `timestamp`, `level`, `direction`, `protocol`, `operation`,
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
  consumption. DNs and filters are not logged.
- Background work has its own generated request ID. A manually triggered job
  also has `parent_id` linking it to the initiating request.

No request/response bodies, directory attributes, credentials, cookies, or
authorization headers are logged, even at `DEBUG`. Raw Uvicorn access logs and
httpx/httpcore/ldap3 logging are disabled to prevent accidental disclosure;
Uvicorn exception tracebacks are reduced to a safe exception class.

Illustrative sanitized entries (synthetic metadata):

```json
{"timestamp":"2026-01-01T12:00:00.000+00:00","level":"INFO","direction":"inbound","protocol":"http","operation":"request","result":"success","duration_ms":2.1,"request_id":"11111111111141118111111111111111","method":"GET","path":"/api/status","status":200}
{"timestamp":"2026-01-01T12:00:01.000+00:00","level":"WARNING","direction":"outbound","protocol":"scim","operation":"request","result":"forbidden","duration_ms":41.2,"request_id":"22222222222242228222222222222222","method":"GET","path":"/Users","status":403,"scheme":"https","host":"scim.example.com","port":443}
{"timestamp":"2026-01-01T12:00:02.000+00:00","level":"INFO","direction":"outbound","protocol":"ldap","operation":"connect_starttls_bind","result":"success","duration_ms":18.4,"request_id":"33333333333343338333333333333333","scheme":"ldap","host":"ldap.example.com","port":389,"tls_mode":"starttls","ldap_result":0}
```

The successful poll example requires `BRIDGE_LOG_POLLS=true` at `INFO`.

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

The console's **Attribute mapping** section can discover SCIM schemas/resource types,
attribute type/multiplicity metadata when the SCIM schema provides it, and LDAP
attribute names and samples (LDAP type/multiplicity is reported as unavailable).
Sensitive-looking attributes are excluded. Map SCIM paths to LDAP attributes with
per-rule directions, validate mappings against both connected sources, inspect a
sample comparison, and save the mapping with the rest of the encrypted settings.
Defaults map `userName`
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