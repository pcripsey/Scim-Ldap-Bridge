import os
import tempfile
import unittest
from unittest.mock import patch

from bridge.config import Settings
from bridge.planner import canonical
from bridge.service import SyncService
from bridge.store import Store


ADA = canonical({"userName": "ada", "givenName": "Ada", "familyName": "Lovelace",
                 "displayName": "Ada Lovelace", "email": "ada@example.org"})


class ServiceDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(self.directory.name)
        self.service = SyncService(self.store)

    def tearDown(self):
        self.service.close()
        self.store.close()
        self.directory.cleanup()

    def run_sync(self, settings):
        run_id = self.store.begin_run(settings.dry_run)
        self.service.lock.acquire()
        self.service.run(settings, run_id)

    def test_dry_run_persists_inventory_and_proposal_without_writing(self):
        with patch("bridge.service.ScimClient") as scim, patch("bridge.service.LdapClient") as ldap:
            scim.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            directory = ldap.return_value.__enter__.return_value
            directory.users.return_value = {}
            self.run_sync(Settings())
            directory.write.assert_not_called()
        self.assertEqual(self.store.resource("scim", "Users", "ada"), ADA)
        self.assertEqual(self.store.operations()[0]["status"], "preview")

    def test_write_is_recorded_before_connector_is_called(self):
        with patch("bridge.service.ScimClient") as scim, patch("bridge.service.LdapClient") as ldap:
            scim.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            directory = ldap.return_value.__enter__.return_value
            directory.users.side_effect = [{}, {"ada": ADA}]

            def write(user, existing):
                self.assertEqual(self.store.operations()[0]["status"], "applying")
                self.assertEqual(self.store.resource("scim", "Users", "ada"), ADA)

            directory.write.side_effect = write
            self.run_sync(Settings(dry_run=False, direction="scim_to_ldap"))
        self.assertEqual(self.store.operations()[0]["status"], "applied")
        self.assertEqual(self.store.resource("ldap", "Users", "ada"), ADA)
        self.assertEqual(self.store.snapshots()["ada"]["ldap"], ADA)

    def test_failed_write_keeps_failure_state_without_baseline(self):
        with patch("bridge.service.ScimClient") as scim, patch("bridge.service.LdapClient") as ldap:
            scim.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            directory = ldap.return_value.__enter__.return_value
            directory.users.return_value = {}
            directory.write.side_effect = RuntimeError("secret must not be logged")
            self.run_sync(Settings(dry_run=False))
        self.assertEqual(self.store.operations()[0]["status"], "failed")
        self.assertEqual(self.store.operations()[0]["error"], "RuntimeError")
        self.assertEqual(self.store.snapshots(), {})
        self.assertEqual(self.store.rows("runs")[0]["status"], "failed")

    def test_ldap_to_scim_records_correct_destination(self):
        with patch("bridge.service.ScimClient") as scim, patch("bridge.service.LdapClient") as ldap:
            scim.return_value.__enter__.return_value.users.return_value = {}
            ldap.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            self.run_sync(Settings(direction="ldap_to_scim"))
        self.assertEqual(self.store.operations()[0]["target"], "scim")

    def test_known_self_target_fails_before_connecting_or_staging(self):
        with patch.dict(os.environ, {"BRIDGE_SCIM_SELF_URLS": "https://bridge.example/scim/v2"}), \
                patch("bridge.service.LdapClient") as ldap:
            self.run_sync(Settings(scim_url="https://bridge.example/scim/v2",
                                   scim_token="synthetic-provider-token"))
            ldap.assert_not_called()
        self.assertFalse(self.service.lock.locked())
        self.assertEqual(self.store.operations(), [])
        self.assertEqual(self.store.snapshots(), {})
        self.assertEqual(self.store.rows("runs")[0]["status"], "failed")
        self.assertIn("remote SCIM provider", self.store.rows("events")[0]["message"])


if __name__ == "__main__":
    unittest.main()