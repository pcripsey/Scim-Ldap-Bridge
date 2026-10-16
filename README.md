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

The current container exposes the management API. Web console assets have not yet
been implemented; the root URL reports that the console is unavailable.

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

The running synchronization path currently maps `userName`, given name, family name,
display name, and primary email to LDAP `inetOrgPerson` attributes. Inbound SCIM
Users list/read/create/replace/patch operations are available at `/scim/v2`; inbound
writes are blocked during dry runs. Deletion, groups, password writes, lifecycle
provisioning, and complete schema-driven synchronization are not yet implemented.
Schema-extension helpers are work in progress. The database can preserve additional
attributes, but that alone does not make the connectors synchronize them.

LDAP requires certificate-verified LDAPS or StartTLS. Remote SCIM supports HTTP or
HTTPS; use HTTPS outside an isolated development environment. Usernames are the
current matching key. Treat renames and missing linked users as manual conflicts.

## Development Checks

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

The focused database tests are in `tests/test_store.py` and `tests/test_service.py`.