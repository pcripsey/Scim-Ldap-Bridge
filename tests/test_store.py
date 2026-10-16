import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bridge.config import Settings
from bridge.planner import Decision
from bridge.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(self.directory.name)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def reopen(self):
        self.store.close()
        self.store = Store(self.directory.name)

    def test_configuration_resources_and_operations_survive_restart(self):
        user = {"userName": "ada", "custom": {"projects": ["Analytical Engine"]}}
        self.store.save_settings(Settings(direction="ldap_to_scim", ldap_password="bind-secret"))
        run_id = self.store.begin_run(False)
        self.store.stage_run(run_id, {}, {"ada": user}, [Decision("ada", "scim", "create", user, "New user")], False)
        self.reopen()
        self.assertEqual(self.store.settings().direction, "ldap_to_scim")
        self.assertEqual(self.store.settings().ldap_password, "bind-secret")
        self.assertEqual(self.store.resource("ldap", "Users", "ada"), user)
        self.assertEqual(self.store.operations()[0]["status"], "interrupted")
        self.assertEqual(self.store.rows("runs")[0]["status"], "interrupted")

    def test_full_nested_attributes_are_encrypted(self):
        user = {"userName": "ada", "emails": [{"value": "private-address@example.org"}],
                "urn:example:custom": {"costCenter": "confidential-cost-center"}}
        self.store.replace_resources("scim", "Users", {"ada": user})
        self.store.snapshot("ada", user, user)
        self.store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        contents = (Path(self.directory.name) / "bridge.db").read_bytes()
        self.assertNotIn(b"private-address@example.org", contents)
        self.assertNotIn(b"confidential-cost-center", contents)
        self.assertEqual(self.store.snapshots()["ada"]["scim"], user)

    def test_passwords_are_never_cached(self):
        user = {"userName": "ada", "password": "never-save", "userPassword;binary": "never-save",
                "_raw": {"unicodePwd": "never-save", "name": {"givenName": "Ada"}}}
        self.store.replace_resources("ldap", "Users", {"ada": user})
        saved = self.store.resource("ldap", "Users", "ada")
        self.assertNotIn("password", saved)
        self.assertNotIn("userPassword;binary", saved)
        self.assertNotIn("unicodePwd", saved["_raw"])
        self.assertEqual(saved["_raw"]["name"]["givenName"], "Ada")

    def test_inventory_replacement_marks_missing_resources(self):
        self.store.replace_resources("ldap", "Groups", {"admins": {"displayName": "Admins"}})
        self.store.replace_resources("ldap", "Groups", {})
        records = self.store.resource_records("ldap", "Groups")
        self.assertEqual(records[0]["present"], 0)
        self.assertEqual(self.store.data_summary()["inventory"], [])

    def test_dry_runs_and_conflicts_are_not_pending_writes(self):
        run_id = self.store.begin_run(True)
        self.store.stage_run(run_id, {}, {}, [Decision("ada", "ldap", "create", {"userName": "ada"}, ""),
                                              Decision("grace", None, "conflict", None, "")], True)
        self.assertEqual({item["status"] for item in self.store.operations()}, {"preview", "conflict"})

    def test_write_transitions_and_metadata_do_not_expose_payload(self):
        run_id = self.store.begin_run(False)
        operation_id = self.store.stage_run(run_id, {}, {}, [Decision("ada", "ldap", "create", {"email": "private"}, "")], False)[0]
        with self.assertRaises(ValueError):
            self.store.operation_state(operation_id, "applied")
        self.store.operation_state(operation_id, "applying")
        self.store.operation_state(operation_id, "applied")
        self.assertEqual(self.store.operations()[0]["status"], "applied")
        self.assertNotIn("payload", self.store.operations()[0])

    def test_applying_write_is_not_blindly_replayed_after_restart(self):
        run_id = self.store.begin_run(False)
        operation_id = self.store.stage_run(run_id, {}, {}, [Decision("ada", "ldap", "create", {}, "")], False)[0]
        self.store.operation_state(operation_id, "applying")
        self.reopen()
        self.assertEqual(self.store.operations()[0]["status"], "interrupted")

    def test_connector_change_clears_old_inventory_and_baselines(self):
        self.store.replace_resources("ldap", "Users", {"ada": {"userName": "ada"}})
        self.store.snapshot("ada", {}, {})
        self.store.save_settings(Settings(), reset=True)
        self.assertEqual(self.store.snapshots(), {})
        self.assertEqual(self.store.resource_records(), [])

    def test_legacy_plaintext_baselines_are_migrated(self):
        self.store.close()
        with sqlite3.connect(Path(self.directory.name) / "bridge.db") as connection:
            connection.execute("INSERT INTO snapshots VALUES (?,?)", ("ada", json.dumps({"scim": {"email": "private"}, "ldap": {}})))
        self.store = Store(self.directory.name)
        self.assertEqual(self.store.snapshots()["ada"]["scim"]["email"], "private")
        self.assertIsInstance(self.store.db.execute("SELECT value FROM snapshots").fetchone()[0], bytes)


if __name__ == "__main__":
    unittest.main()