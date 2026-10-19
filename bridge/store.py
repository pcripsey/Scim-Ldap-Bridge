import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

from bridge.config import Settings


SECRET_ATTRIBUTES = {
    "password", "userpassword", "unicodepwd", "authpassword", "dbcspwd",
    "supplementalcredentials", "ntpwdhistory", "lmpwdhistory", "krbprincipalkey",
    "scim_token", "ldap_password", "entra_client_secret", "access_token", "refresh_token", "client_secret",
}


def without_secrets(value):
    if isinstance(value, dict):
        return {key: without_secrets(item) for key, item in value.items()
                if key.casefold().split(";")[0] not in SECRET_ATTRIBUTES}
    if isinstance(value, list):
        return [without_secrets(item) for item in value]
    return value


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        key_path = self.directory / "encryption.key"
        if not key_path.exists():
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(Fernet.generate_key())
        self.cipher = Fernet(key_path.read_bytes())
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / "bridge.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS snapshots (username TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, started TEXT, finished TEXT,
                status TEXT, dry_run INTEGER, processed INTEGER DEFAULT 0,
                changed INTEGER DEFAULT 0, conflicts INTEGER DEFAULT 0, errors INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time TEXT, run_id INTEGER,
                level TEXT, username TEXT, message TEXT);
            CREATE TABLE IF NOT EXISTS resources (
                source TEXT NOT NULL, resource_type TEXT NOT NULL, resource_key TEXT NOT NULL,
                data BLOB NOT NULL, observed_at TEXT NOT NULL, present INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (source, resource_type, resource_key));
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, resource_type TEXT NOT NULL,
                resource_key TEXT NOT NULL, target TEXT, operation TEXT NOT NULL,
                payload BLOB, status TEXT NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, error TEXT);
            CREATE INDEX IF NOT EXISTS operations_run ON operations (run_id, id);
            CREATE INDEX IF NOT EXISTS operations_status ON operations (status);
            PRAGMA user_version=1;
        """)
        self.db.execute("UPDATE runs SET status='interrupted', finished=? WHERE status='running'", (timestamp(),))
        self.db.execute("UPDATE operations SET status='interrupted', updated_at=?, error=? "
                        "WHERE status IN ('planned', 'applying')",
                        (timestamp(), "Service restarted; reconcile again before retrying."))
        for row in self.db.execute("SELECT username, value FROM snapshots").fetchall():
            if isinstance(row["value"], str):
                self.db.execute("UPDATE snapshots SET value=? WHERE username=?",
                                (self._encrypt(json.loads(row["value"])), row["username"]))
        self.db.commit()

    def _encrypt(self, value):
        return self.cipher.encrypt(json.dumps(without_secrets(value), ensure_ascii=True).encode())

    def _decrypt(self, value):
        return json.loads(self.cipher.decrypt(value))

    def settings(self):
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE id=1").fetchone()
        return Settings.model_validate_json(self.cipher.decrypt(row[0])) if row else Settings()

    def save_settings(self, settings, reset=False):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES (1, ?)",
                            (self.cipher.encrypt(settings.model_dump_json().encode()),))
            if reset:
                self.db.execute("DELETE FROM snapshots")
                self.db.execute("DELETE FROM resources")
                self.db.execute("UPDATE operations SET status='cancelled', updated_at=?, error=? "
                                "WHERE status IN ('planned', 'applying')",
                                (timestamp(), "Connector identity changed; reconcile again."))

    def snapshots(self):
        with self.lock:
            return {row[0]: self._decrypt(row[1]) for row in self.db.execute("SELECT * FROM snapshots")}

    def snapshot(self, username, scim, ldap):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO snapshots VALUES (?, ?)",
                            (username, self._encrypt({"scim": scim, "ldap": ldap})))

    def _replace_resources(self, source, resource_type, resources):
        observed = timestamp()
        self.db.execute("UPDATE resources SET present=0 WHERE source=? AND resource_type=?",
                        (source, resource_type))
        self.db.executemany("INSERT INTO resources VALUES (?,?,?,?,?,1) "
                            "ON CONFLICT(source,resource_type,resource_key) DO UPDATE SET "
                            "data=excluded.data, observed_at=excluded.observed_at, present=1",
                            [(source, resource_type, key, self._encrypt(data), observed)
                             for key, data in resources.items()])

    def replace_resources(self, source, resource_type, resources):
        if source not in ("scim", "ldap"):
            raise ValueError("Unknown resource source")
        with self.lock, self.db:
            self._replace_resources(source, resource_type, resources)

    def stage_run(self, run_id, scim, ldap, decisions, dry_run, resource_type="Users"):
        identifiers = []
        with self.lock, self.db:
            self._replace_resources("scim", resource_type, scim)
            self._replace_resources("ldap", resource_type, ldap)
            for decision in decisions:
                status = "conflict" if decision.operation == "conflict" else "preview" if dry_run else "planned"
                now = timestamp()
                cursor = self.db.execute(
                    "INSERT INTO operations (run_id,resource_type,resource_key,target,operation,payload,status,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (run_id, resource_type, decision.username, decision.target, decision.operation,
                     self._encrypt(decision.user) if decision.user is not None else None, status, now, now))
                identifiers.append(cursor.lastrowid)
        return identifiers

    def operation_state(self, operation_id, status, error=None):
        if status not in ("applying", "applied", "failed"):
            raise ValueError("Invalid operation state")
        with self.lock, self.db:
            expected = "planned" if status == "applying" else "applying"
            cursor = self.db.execute("UPDATE operations SET status=?, updated_at=?, error=? WHERE id=? AND status=?",
                                     (status, timestamp(), error, operation_id, expected))
            if cursor.rowcount != 1:
                raise ValueError("Invalid operation transition")

    def resource_records(self, source=None, resource_type="Users", limit=100, offset=0):
        with self.lock:
            return [dict(row) for row in self.db.execute(
                "SELECT source,resource_type,resource_key,observed_at,present FROM resources "
                "WHERE (? IS NULL OR source=?) AND resource_type=? "
                "ORDER BY source,resource_key LIMIT ? OFFSET ?", (source, source, resource_type, limit, offset))]

    def resource(self, source, resource_type, key):
        with self.lock:
            row = self.db.execute("SELECT data FROM resources WHERE source=? AND resource_type=? AND resource_key=?",
                                   (source, resource_type, key)).fetchone()
            return self._decrypt(row[0]) if row else None

    def operations(self, limit=100, offset=0):
        with self.lock:
            return [dict(row) for row in self.db.execute(
                "SELECT id,run_id,resource_type,resource_key,target,operation,status,created_at,updated_at,error "
                "FROM operations ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))]

    def data_summary(self):
        with self.lock:
            inventory = [dict(row) for row in self.db.execute(
                "SELECT source,resource_type,COUNT(*) AS count FROM resources WHERE present=1 GROUP BY source,resource_type")]
            operations = {row[0]: row[1] for row in self.db.execute("SELECT status,COUNT(*) FROM operations GROUP BY status")}
        return {"engine": "sqlite", "inventory": inventory, "operations": operations}

    def begin_run(self, dry_run):
        with self.lock, self.db:
            return self.db.execute("INSERT INTO runs (started,status,dry_run) VALUES (?,'running',?)",
                                   (timestamp(), int(dry_run))).lastrowid

    def finish_run(self, run_id, status, processed, changed, conflicts, errors):
        with self.lock, self.db:
            self.db.execute("UPDATE runs SET finished=?,status=?,processed=?,changed=?,conflicts=?,errors=? WHERE id=?",
                            (timestamp(), status, processed, changed, conflicts, errors, run_id))
            self.db.execute("DELETE FROM operations WHERE run_id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT 200)")
            self.db.execute("DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT 200)")

    def event(self, level, message, username="", run_id=None):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events (time,run_id,level,username,message) VALUES (?,?,?,?,?)",
                            (timestamp(), run_id, level, username, message))
            self.db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)")

    def rows(self, table, limit=100):
        if table not in ("runs", "events"):
            raise ValueError("Unknown table")
        with self.lock:
            return [dict(row) for row in self.db.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))]

    def close(self):
        self.db.close()