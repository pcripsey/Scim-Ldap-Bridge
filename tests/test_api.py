import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from bridge.app import create_app, opaque_id
from bridge.config import DEFAULT_ATTRIBUTE_MAPPINGS, Settings
from bridge.connectors import LdapClient
from bridge.planner import canonical
from bridge.schema import USER_SCHEMA
from bridge.self_target import ERROR_HEADER


ADMIN = "admin-test-token-at-least-24-chars"
SCIM = "scim-test-token-at-least-24-chars"
HEADERS = {"Authorization": f"Bearer {ADMIN}"}
SCIM_HEADERS = {"Authorization": f"Bearer {SCIM}"}
ADA = canonical({"userName": "ada", "givenName": "Ada", "familyName": "Lovelace",
                 "displayName": "Ada Lovelace", "email": "ada@example.org"})


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.client = TestClient(create_app(self.directory.name, ADMIN, SCIM))
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.directory.cleanup()

    def test_requires_authentication(self):
        self.assertEqual(self.client.get("/api/status").status_code, 401)
        self.assertEqual(self.client.get("/healthz").status_code, 200)

    def test_console_and_assets_are_served_with_security_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            static = Path(directory)
            (static / "assets").mkdir()
            (static / "index.html").write_text('<html><script src="/assets/console.js"></script></html>')
            (static / "assets" / "console.js").write_text('console.log("console loaded");')
            with patch("bridge.app.STATIC", static):
                with TestClient(create_app(self.directory.name, ADMIN, SCIM)) as client:
                    response = client.get("/")
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("/assets/console.js", response.text)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])
                    self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                    asset = client.get("/assets/console.js")
                    self.assertEqual(asset.status_code, 200)
                    self.assertIn("console loaded", asset.text)
                    self.assertEqual(client.get("/api/settings").status_code, 401)

    def test_unbuilt_console_has_explicit_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("bridge.app.STATIC", Path(directory)):
                response = self.client.get("/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("npm", response.json()["detail"])

    def test_settings_edits_preserve_or_explicitly_clear_secrets(self):
        self.client.put("/api/settings", headers=HEADERS,
                        json={"scim_token": "saved-token", "ldap_password": "saved-password"})
        response = self.client.put("/api/settings", headers=HEADERS,
                                   json={"direction": "ldap_to_scim", "interval_seconds": 600})
        self.assertEqual(response.status_code, 200)
        settings = self.client.app.state.store.settings()
        self.assertEqual(settings.scim_token, "saved-token")
        self.assertEqual(settings.ldap_password, "saved-password")
        self.client.put("/api/settings", headers=HEADERS, json={"scim_token": ""})
        settings = self.client.get("/api/settings", headers=HEADERS).json()
        self.assertFalse(settings["scim_token_configured"])
        self.assertTrue(settings["ldap_password_configured"])

    def test_defaults_are_safe(self):
        response = self.client.get("/api/settings", headers=HEADERS).json()
        self.assertTrue(response["dry_run"])
        self.assertFalse(response["enabled"])
        self.assertNotIn("ldap_password", response)
        self.assertFalse(response["ad_enable_new_accounts"])

    def test_ad_activation_setting_is_persisted_and_requires_tls(self):
        response = self.client.put("/api/settings", headers=HEADERS, json={
            "ldap_service": "active_directory", "ldap_url": "ldaps://directory.example.org",
            "ad_enable_new_accounts": True,
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(self.client.get("/api/settings", headers=HEADERS).json()["ad_enable_new_accounts"])
        response = self.client.put("/api/settings", headers=HEADERS, json={
            "ldap_url": "ldap://directory.example.org", "ldap_start_tls": False,
            "ldap_allow_insecure": True,
        })
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.client.app.state.store.settings().ldap_url.startswith("ldaps://"))
        response = self.client.put("/api/settings", headers=HEADERS, json={"ldap_service": "openldap"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.app.state.store.settings().ad_enable_new_accounts)

    def test_ldap_service_change_applies_defaults_and_resets_safely(self):
        store = self.client.app.state.store
        store.replace_resources("ldap", "Users", {"ada": ADA})
        store.snapshot("ada", ADA, ADA)
        response = self.client.put("/api/settings", headers=HEADERS, json={
            "ldap_service": "active_directory", "dry_run": False, "enabled": True,
        })
        self.assertEqual(response.status_code, 200, response.text)
        settings = self.client.get("/api/settings", headers=HEADERS).json()
        self.assertEqual(settings["ldap_service"], "active_directory")
        self.assertEqual(settings["attribute_mappings"][0]["ldap_attribute"], "sAMAccountName")
        self.assertTrue(settings["dry_run"])
        self.assertFalse(settings["enabled"])
        self.assertEqual(store.snapshots(), {})
        self.assertIsNone(store.resource("ldap", "Users", "ada"))
        response = self.client.put("/api/settings", headers=HEADERS, json={
            "ldap_service": "openldap", "attribute_mappings": [
                {"scim_path": "userName", "ldap_attribute": "mail"},
            ],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(store.settings().attribute_mappings[0].ldap_attribute, "mail")

    def test_rejects_own_inbound_url_without_saving_or_resetting_inventory(self):
        self.client.app.state.store.replace_resources("scim", "Users", {"ada": ADA})
        response = self.client.put("/api/settings", headers=HEADERS,
                                   json={"scim_url": "http://testserver/scim/v2/"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("remote SCIM provider", response.json()["detail"])
        self.assertEqual(self.client.app.state.store.settings().scim_url, "")
        self.assertIsNotNone(self.client.app.state.store.resource("scim", "Users", "ada"))
        self.assertFalse(self.client.app.state.service.lock.locked())

    def test_saved_self_target_has_actionable_diagnostics_and_can_be_repaired(self):
        self.client.app.state.store.save_settings(
            Settings(scim_url="https://public-alias.example/scim/v2", scim_token="synthetic-provider-token"))
        with patch.dict(os.environ, {"BRIDGE_SCIM_SELF_URLS": "https://public-alias.example/scim/v2"}):
            with patch("bridge.connectors.TrafficHttpClient") as outbound:
                for path in ("/api/test/scim", "/api/discovery/scim", "/api/mappings/validate"):
                    response = self.client.post(path, headers=HEADERS, json={
                        "attribute_mappings": [item.model_dump() for item in Settings().attribute_mappings],
                    })
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("remote SCIM provider", response.json()["detail"])
                outbound.assert_not_called()
            self.assertEqual(self.client.get("/api/settings", headers=HEADERS).status_code, 200)
            response = self.client.put("/api/settings", headers=HEADERS,
                                       json={"scim_url": "https://provider.example/scim/v2"})
            self.assertEqual(response.status_code, 200)

    def test_database_monitoring_requires_admin(self):
        for path in ("resources", "operations", "resource?source=scim&key=ada"):
            self.assertEqual(self.client.get(f"/api/data/{path}").status_code, 401)
            self.assertEqual(self.client.get(f"/api/data/{path}", headers=SCIM_HEADERS).status_code, 401)
        self.client.app.state.store.replace_resources("scim", "Users", {"ada": ADA})
        response = self.client.get("/api/data/resources", headers=HEADERS)
        self.assertEqual(response.json()["resources"][0]["resource_key"], "ada")
        self.assertNotIn("data", response.json()["resources"][0])
        response = self.client.get("/api/data/resource?source=scim&key=ada", headers=HEADERS)
        self.assertEqual(response.json()["data"], ADA)
        response = self.client.get("/api/status", headers=HEADERS)
        self.assertEqual(response.json()["database"]["inventory"][0]["count"], 1)

    def test_secrets_are_not_returned_or_stored_as_plaintext(self):
        secret = "private-connector-credential"
        response = self.client.put("/api/settings", headers=HEADERS, json={"ldap_password": secret})
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/api/settings", headers=HEADERS)
        self.assertNotIn(secret, response.text)
        self.assertTrue(response.json()["ldap_password_configured"])
        with open(self.directory.name + "/bridge.db", "rb") as stream:
            self.assertNotIn(secret.encode(), stream.read())

    def test_rejects_unencrypted_ldap(self):
        response = self.client.put("/api/settings", headers=HEADERS,
                                   json={"ldap_url": "ldap://directory.example.org", "ldap_start_tls": False})
        self.assertEqual(response.status_code, 400)

    def test_allows_unencrypted_ldap_with_explicit_opt_in(self):
        response = self.client.put("/api/settings", headers=HEADERS,
                                   json={"ldap_url": "ldap://directory.example.org:389", "ldap_start_tls": False,
                                         "ldap_allow_insecure": True})
        self.assertEqual(response.status_code, 200)
        saved = self.client.get("/api/settings", headers=HEADERS).json()
        self.assertTrue(saved["ldap_allow_insecure"])
        self.assertFalse(saved["ldap_start_tls"])

    def test_cannot_schedule_incomplete_connectors(self):
        self.assertEqual(self.client.put("/api/settings", headers=HEADERS, json={"enabled": True}).status_code, 400)
        self.assertEqual(self.client.post("/api/sync", headers=HEADERS).status_code, 400)

    def test_provisioning_token_cannot_access_admin(self):
        self.assertEqual(self.client.get("/api/status", headers=SCIM_HEADERS).status_code, 401)
        self.assertEqual(self.client.get("/scim/v2/ServiceProviderConfig", headers=HEADERS).status_code, 401)

    def test_scim_filter_and_pagination(self):
        with patch("bridge.app.LdapClient") as connector:
            connector.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            response = self.client.get('/scim/v2/Users?filter=userName%20eq%20%22ada%22', headers=SCIM_HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["totalResults"], 1)
        self.assertEqual(response.json()["Resources"][0]["userName"], "ada")

    def test_scim_discovery_describes_user_resource_and_schemas(self):
        provider = self.client.get("/scim/v2/ServiceProviderConfig", headers=SCIM_HEADERS).json()
        self.assertTrue(provider["filter"]["supported"])
        self.assertEqual(provider["filter"]["maxResults"], 1000)
        schemas = self.client.get("/scim/v2/Schemas", headers=SCIM_HEADERS).json()
        self.assertIn("urn:ietf:params:scim:schemas:core:2.0:User",
                      [item["id"] for item in schemas["Resources"]])
        resources = self.client.get("/scim/v2/ResourceTypes", headers=SCIM_HEADERS).json()
        self.assertEqual(resources["Resources"][0]["endpoint"], "/Users")
        self.assertNotIn("Group", [item["name"] for item in resources["Resources"]])
        self.assertEqual(self.client.get("/scim/v2/Users", headers=SCIM_HEADERS).headers["content-type"],
                         "application/scim+json")
        self.assertEqual(self.client.get("/scim/v2/ResourceTypes/Group", headers=SCIM_HEADERS).status_code, 404)

    def test_admin_can_discover_saved_connector_attributes(self):
        with patch("bridge.app.ScimClient") as connector:
            connector.return_value.__enter__.return_value.discovery.return_value = {
                "schemas": [], "resource_types": [], "attributes": [{"name": "userName", "samples": ["ada"]}],
                "users": 1,
            }
            response = self.client.post("/api/discovery/scim", headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["attributes"][0]["name"], "userName")
        self.assertEqual(self.client.post("/api/discovery/scim", headers=SCIM_HEADERS).status_code, 401)

    def test_mapping_validation_checks_both_connector_attribute_sets(self):
        with patch("bridge.app.ScimClient") as scim, patch("bridge.app.LdapClient") as ldap:
            scim.return_value.__enter__.return_value.discovery.return_value = {
                "attributes": [{"name": name} for name in
                               ("userName", "name.givenName", "name.familyName", "displayName", "emails.value")],
            }
            ldap.return_value.__enter__.return_value.discovery.return_value = {
                "attributes": [{"name": name} for name in ("uid", "givenName", "sn", "displayName", "mail")],
            }
            response = self.client.post("/api/mappings/validate", headers=HEADERS, json={
                "attribute_mappings": self.client.get("/api/settings", headers=HEADERS).json()["attribute_mappings"],
            })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["valid"])
        self.assertEqual(response.json()["scim_attributes"], 5)

    def test_user_resources_include_meta_and_full_filter_support(self):
        with patch("bridge.app.LdapClient") as connector:
            connector.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            response = self.client.get('/scim/v2/Users?filter=name.familyName%20eq%20%22Lovelace%22',
                                       headers=SCIM_HEADERS)
        self.assertEqual(response.status_code, 200)
        user = response.json()["Resources"][0]
        self.assertEqual(user["meta"]["resourceType"], "User")
        self.assertTrue(user["meta"]["location"].startswith("http://testserver/scim/v2/Users/"))
        self.assertTrue(user["meta"]["location"].endswith("/scim/v2/Users/YWRh"))

    def test_mapping_settings_reject_duplicate_or_sensitive_attributes(self):
        response = self.client.put("/api/settings", headers=HEADERS, json={
            "attribute_mappings": [
                {"scim_path": "userName", "ldap_attribute": "uid"},
                {"scim_path": "displayName", "ldap_attribute": "userPassword"},
            ],
        })
        self.assertEqual(response.status_code, 400)

    def test_inbound_dry_run_queues_users_without_writing(self):
        with patch("bridge.app.LdapClient") as connector:
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                        json={"userName": "ada", "name": {"familyName": "Lovelace"}})
            self.assertEqual(response.status_code, 201)
            identifier = response.json()["id"]
            self.assertEqual(self.client.get(f"/scim/v2/Users/{identifier}", headers=SCIM_HEADERS)
                             .json()["name"]["familyName"], "Lovelace")
            response = self.client.patch(f"/scim/v2/Users/{identifier}", headers=SCIM_HEADERS,
                                         json={"Operations": [{"op": "replace", "path": "name.givenName",
                                                               "value": "Augusta"}]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["name"]["givenName"], "Augusta")
            response = self.client.put(f"/scim/v2/Users/{identifier}", headers=SCIM_HEADERS,
                                       json={"userName": "ada", "name": {"givenName": "Ada", "familyName": "King"}})
            self.assertEqual(response.status_code, 200)
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                        json={"userName": "ADA", "name": {"familyName": "Lovelace"}})
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.headers[ERROR_HEADER], "uniqueness")
            connector.assert_not_called()
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {}
            response = self.client.put(f"/scim/v2/Users/{opaque_id('bob')}", headers=SCIM_HEADERS,
                                       json={"userName": "bob", "name": {"familyName": "Builder"}})
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.headers[ERROR_HEADER], "dry_run")
            directory.write.assert_not_called()
        records = self.client.get("/api/data/resources?source=inbound", headers=HEADERS).json()["resources"]
        self.assertEqual([(row["resource_key"], row["status"]) for row in records], [("ada", "waiting_for_ldap")])
        detail = self.client.get("/api/data/resource?source=inbound&key=ada", headers=HEADERS).json()["data"]
        self.assertEqual((detail["givenName"], detail["familyName"]), ("Ada", "King"))
        summary = self.client.get("/api/status", headers=HEADERS).json()["database"]
        self.assertEqual(summary["pending_users"], {"pending": 1})

    def test_inbound_create_is_queued_when_ldap_write_fails_and_retried(self):
        self.client.put("/api/settings", headers=HEADERS, json={
            "dry_run": False, "ldap_url": "ldaps://directory.example.org", "ldap_bind_dn": "cn=bridge",
            "ldap_password": "saved-password", "ldap_base_dn": "dc=example,dc=org"})
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {}
            directory.write.side_effect = ConnectionError("synthetic")
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                        json={"userName": "ada", "name": {"familyName": "Lovelace"}})
        self.assertEqual(response.status_code, 201)
        record = self.client.get("/api/data/resources", headers=HEADERS).json()["resources"][0]
        self.assertEqual((record["source"], record["status"], record["error"], record["attempts"]),
                         ("inbound", "waiting_for_ldap", "ConnectionError", 1))
        with patch("bridge.service.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.side_effect = [{}, {"ada": ADA}]
            self.assertEqual(self.client.app.state.service.drain_pending(), 1)
            self.assertEqual(directory.write.call_args.args[0]["familyName"], "Lovelace")
        self.assertEqual(self.client.app.state.store.pending_users(None), {})
        records = self.client.get("/api/data/resources", headers=HEADERS).json()["resources"]
        self.assertEqual([(row["source"], row["resource_key"], row["status"]) for row in records],
                         [("ldap", "ada", "present")])
        self.assertFalse(self.client.app.state.service.lock.locked())

    def test_live_inbound_create_does_not_leave_queued_user(self):
        self.client.put("/api/settings", headers=HEADERS, json={"dry_run": False})
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.side_effect = [{}, {"ada": ADA}]
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                        json={"userName": "ada", "name": {"familyName": "Lovelace"}})
        self.assertEqual(response.status_code, 201)
        directory.write.assert_called_once()
        self.assertEqual(self.client.app.state.store.pending_users(None), {})
        self.assertIsNotNone(self.client.app.state.store.resource("ldap", "Users", "ada"))

    def test_queued_user_existing_in_ldap_becomes_conflict_and_can_be_discarded(self):
        store = self.client.app.state.store
        self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                         json={"userName": "ada", "name": {"familyName": "Lovelace"}})
        store.save_settings(store.settings().model_copy(update={
            "dry_run": False, "ldap_url": "ldaps://directory.example.org", "ldap_bind_dn": "cn=bridge",
            "ldap_password": "saved-password", "ldap_base_dn": "dc=example,dc=org"}))
        with patch("bridge.service.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"Ada": ADA}
            self.assertEqual(self.client.app.state.service.drain_pending(), 0)
            directory.write.assert_not_called()
        record = self.client.get("/api/data/resources?source=inbound", headers=HEADERS).json()["resources"][0]
        self.assertEqual(record["status"], "conflict")
        self.assertEqual(self.client.delete("/api/data/pending?key=ada").status_code, 401)
        self.assertEqual(self.client.delete("/api/data/pending?key=ada", headers=HEADERS).status_code, 200)
        self.assertEqual(self.client.delete("/api/data/pending?key=ada", headers=HEADERS).status_code, 404)
        self.assertEqual(store.pending_users(None), {})

    def test_duplicate_username_has_distinct_diagnostic(self):
        self.client.put("/api/settings", headers=HEADERS, json={"dry_run": False})
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"ADA": ADA}
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                        json={"userName": "ada", "name": {"familyName": "Lovelace"}})
            directory.write.assert_not_called()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.headers[ERROR_HEADER], "uniqueness")

    def test_busy_read_and_write_preserve_lock_and_never_touch_ldap(self):
        service = self.client.app.state.service
        self.assertEqual(self.client.put("/api/settings", headers=HEADERS, json={"dry_run": False}).status_code, 200)
        service.lock.acquire()
        try:
            with patch("bridge.app.LdapClient") as connector:
                response = self.client.get("/scim/v2/Users", headers=SCIM_HEADERS)
                created = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                           json={"userName": "ada", "name": {"familyName": "Lovelace"}})
                connector.assert_not_called()
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.headers[ERROR_HEADER], "directory_busy")
            self.assertEqual(response.json()["status"], "409")
            self.assertEqual(created.status_code, 201)
            self.assertIn("ada", self.client.app.state.store.pending_users())
            self.assertTrue(service.lock.locked())
        finally:
            service.lock.release()
        with patch("bridge.app.LdapClient") as connector:
            connector.return_value.__enter__.return_value.users.return_value = {}
            listed = self.client.get("/scim/v2/Users", headers=SCIM_HEADERS)
            self.assertEqual(listed.status_code, 200)
            self.assertEqual([user["userName"] for user in listed.json()["Resources"]], ["ada"])

    def test_scim_create_and_patch(self):
        self.client.put("/api/settings", headers=HEADERS, json={"dry_run": False})
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {}
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                       json={"userName": "ada", "name": {"familyName": "Lovelace"}})
            self.assertEqual(response.status_code, 201)
            identifier = response.json()["id"]
            directory.users.return_value = {"ada": ADA}
            response = self.client.patch(f"/scim/v2/Users/{identifier}", headers=SCIM_HEADERS,
                                        json={"Operations": [{"op": "replace", "path": "name.givenName", "value": "Augusta"}]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(directory.write.call_args.args[0]["givenName"], "Augusta")

    def enable_ignore(self, enabled=True, **extra):
        response = self.client.put("/api/settings", headers=HEADERS,
                                   json={"dry_run": False, "ignore_unsupported_fields": enabled, **extra})
        self.assertEqual(response.status_code, 200)

    def test_ignore_unsupported_fields_defaults_off_and_round_trips(self):
        self.assertFalse(self.client.get("/api/settings", headers=HEADERS).json()["ignore_unsupported_fields"])
        self.assertFalse(Settings.model_validate({"dry_run": True}).ignore_unsupported_fields)
        self.client.put("/api/settings", headers=HEADERS, json={"ldap_password": "saved-password"})
        self.enable_ignore()
        self.assertTrue(self.client.get("/api/settings", headers=HEADERS).json()["ignore_unsupported_fields"])
        self.client.__exit__(None, None, None)
        self.client = TestClient(create_app(self.directory.name, ADMIN, SCIM))
        self.client.__enter__()
        settings = self.client.get("/api/settings", headers=HEADERS).json()
        self.assertTrue(settings["ignore_unsupported_fields"])
        self.assertTrue(settings["ldap_password_configured"])
        self.assertNotIn("ldap_password", settings)
        self.enable_ignore(False)
        self.assertFalse(self.client.app.state.store.settings().ignore_unsupported_fields)
        for invalid in ("yes", "true", 1, None):
            response = self.client.put("/api/settings", headers=HEADERS, json={"ignore_unsupported_fields": invalid})
            self.assertEqual(response.status_code, 400)
        self.assertFalse(self.client.app.state.store.settings().ignore_unsupported_fields)
        self.assertEqual(self.client.put("/api/settings", headers=SCIM_HEADERS,
                                         json={"ignore_unsupported_fields": True}).status_code, 401)

    def test_legacy_saved_settings_without_ignore_flag_stay_strict(self):
        store = self.client.app.state.store
        legacy = Settings().model_dump()
        legacy.pop("ignore_unsupported_fields")
        with store.lock:
            store.db.execute("INSERT OR REPLACE INTO settings VALUES (1, ?)",
                             (store.cipher.encrypt(json.dumps(legacy).encode()),))
        self.assertFalse(store.settings().ignore_unsupported_fields)
        self.assertFalse(self.client.get("/api/settings", headers=HEADERS).json()["ignore_unsupported_fields"])

    def test_strict_mode_still_rejects_unsupported_fields(self):
        self.client.put("/api/settings", headers=HEADERS, json={"dry_run": False})
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"ada": ADA}
            for field, value in (("active", True), ("password", "Secret-1"), ("groups", [{"value": "g"}])):
                for method, url in (("post", "/scim/v2/Users"), ("put", f"/scim/v2/Users/{opaque_id('ada')}")):
                    response = getattr(self.client, method)(url, headers=SCIM_HEADERS, json={
                        "userName": "ada", "name": {"familyName": "Lovelace"}, field: value})
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("not supported", response.json()["detail"])
            response = self.client.patch(f"/scim/v2/Users/{opaque_id('ada')}", headers=SCIM_HEADERS,
                                         json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
            self.assertEqual(response.status_code, 400)
            directory.write.assert_not_called()

    def test_ignore_mode_drops_unsupported_fields_on_create(self):
        self.enable_ignore()
        enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {}
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS, json={
                "schemas": [USER_SCHEMA, enterprise], "externalId": "csuser3167", "id": "client-id",
                "userName": "csuser3167@example.org", "active": False, "password": "Secret-1",
                "groups": [{"value": "admins"}], "title": "Engineer", "meta": {"resourceType": "User", "created": "x"},
                "displayName": "CS Test User", "name": {"familyName": "User", "givenName": "CS", "middleName": "Q"},
                "emails": [{"value": "cs@example.org", "type": "work", "primary": True}],
                enterprise: {"department": "R&D"},
            })
            self.assertEqual(response.status_code, 201, response.text)
            written = directory.write.call_args.args[0]
        body = response.json()
        for document in (body, written["_raw"]):
            for field in ("active", "password", "groups", "externalId", "title", enterprise):
                self.assertNotIn(field, document)
            self.assertNotIn("middleName", document["name"])
            self.assertNotIn("type", document["emails"][0])
        self.assertEqual(body["schemas"], [USER_SCHEMA])
        self.assertEqual(body["id"], opaque_id("csuser3167@example.org"))
        self.assertEqual(body["meta"], {"resourceType": "User", "location": body["meta"]["location"]})
        self.assertEqual((written["userName"], written["givenName"], written["familyName"], written["email"]),
                         ("csuser3167@example.org", "CS", "User", "cs@example.org"))
        self.assertNotIn("_mapped", written)
        client = LdapClient(Settings(ldap_url="ldaps://directory.example.org", ldap_bind_dn="cn=bridge",
                                     ldap_password="password", ldap_base_dn="dc=example,dc=org"))
        client.connection = Mock()
        with patch.object(client, "_add") as add:
            client.write(written)
        attributes = {name.casefold() for name in add.call_args.args[2]}
        self.assertEqual(attributes, {"uid", "givenname", "sn", "displayname", "mail", "cn"})

    def test_ignore_mode_keeps_required_and_type_validation(self):
        self.enable_ignore()
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {}
            reported = {"schemas": [USER_SCHEMA], "externalId": "csuser3167", "active": True,
                        "userName": "csuser3167@example.org", "displayName": "CS Test User 3167",
                        "meta": {"resourceType": "User"}}
            response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS, json=reported)
            self.assertEqual(response.status_code, 400)
            self.assertIn("name.familyName is required", response.json()["detail"])
            for payload in ({"active": True, "name": {"familyName": "L"}},
                            {"userName": " ", "name": {"familyName": "L"}},
                            {"userName": 7, "name": {"familyName": "L"}},
                            {"userName": "ada", "name": {"familyName": "L"}, "emails": "ada@example.org"}):
                response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS, json=payload)
                self.assertEqual(response.status_code, 400, payload)
            directory.write.assert_not_called()

    def test_ignore_mode_follows_inbound_mapping_direction_and_extensions(self):
        enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        mappings = [*DEFAULT_ATTRIBUTE_MAPPINGS,
                    {"scim_path": f"{enterprise}:employeeNumber", "ldap_attribute": "employeeNumber"},
                    {"scim_path": "title", "ldap_attribute": "title", "direction": "ldap_to_scim"}]
        self.enable_ignore(attribute_mappings=mappings)
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"ada": ADA}
            response = self.client.put(f"/scim/v2/Users/{opaque_id('ada')}", headers=SCIM_HEADERS, json={
                "schemas": [USER_SCHEMA, enterprise], "userName": "ada", "active": False,
                "name": {"familyName": "Lovelace"}, "title": "Countess",
                enterprise: {"employeeNumber": "42", "department": "Math"}})
            self.assertEqual(response.status_code, 200, response.text)
            written = directory.write.call_args.args[0]
            self.assertEqual(written["_mapped"][f"{enterprise}:employeeNumber"], "42")
            self.assertEqual(written["_raw"][enterprise], {"employeeNumber": "42"})
            self.assertNotIn("title", written["_raw"])
            self.assertNotIn("active", written["_raw"])
            self.assertEqual(response.json()["schemas"], [USER_SCHEMA, enterprise])
            response = self.client.put(f"/scim/v2/Users/{opaque_id('ada')}", headers=SCIM_HEADERS, json={
                "userName": "grace", "name": {"familyName": "Hopper"}, "active": True})
            self.assertEqual(response.status_code, 400)
            self.assertIn("immutable", response.json()["detail"])

    def test_ignore_mode_patch_mixed_operations(self):
        self.enable_ignore()
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"ada": ADA}
            response = self.client.patch(f"/scim/v2/Users/{opaque_id('ada')}", headers=SCIM_HEADERS, json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                    {"op": "Replace", "path": "active", "value": "False"},
                    {"op": "replace", "path": "name.givenName", "value": "Augusta"},
                    {"op": "add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                     "value": "Math"},
                    {"op": "remove", "path": 'groups[value eq "admins"]'},
                    {"op": "replace", "path": "name.middleName", "value": "King"},
                    {"op": "replace", "path": "name", "value": {"middleName": "King"}},
                    {"op": "replace", "value": {"active": False, "password": "Secret-1", "displayName": "Augusta Ada"}},
                ]})
            self.assertEqual(response.status_code, 200, response.text)
            written = directory.write.call_args.args[0]
        self.assertEqual((written["givenName"], written["familyName"], written["displayName"], written["email"]),
                         ("Augusta", "Lovelace", "Augusta Ada", "ada@example.org"))
        body = response.json()
        for field in ("active", "password", "groups", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"):
            self.assertNotIn(field, body)
            self.assertNotIn(field, written["_raw"])
        self.assertEqual(body["name"], {"givenName": "Augusta", "familyName": "Lovelace"})

    def test_ignore_mode_all_ignored_patch_is_a_safe_no_op(self):
        self.enable_ignore()
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"ada": ADA}
            response = self.client.patch(f"/scim/v2/Users/{opaque_id('ada')}", headers=SCIM_HEADERS, json={
                "Operations": [{"op": "replace", "path": "active", "value": False},
                               {"op": "replace", "value": {"active": False, "externalId": "x"}}]})
            self.assertEqual(response.status_code, 200, response.text)
            directory.write.assert_not_called()
        body = response.json()
        self.assertNotIn("active", body)
        self.assertEqual((body["userName"], body["name"]["familyName"]), ("ada", "Lovelace"))

    def test_ignore_mode_patch_preserves_security_and_validation_checks(self):
        self.enable_ignore()
        identifier = opaque_id("ada")
        rejected = [
            {"Operations": []},
            {"Operations": "replace"},
            {"Operations": [{"op": "replace", "path": "active", "value": False}] * 51},
            {"Operations": [{"op": "replace", "path": "active", "value": False}, {"op": "move", "path": "active"}]},
            {"Operations": [{"op": "replace", "path": "active", "value": False}, "replace"]},
            {"Operations": [{"op": "replace", "path": "userName", "value": "grace"}]},
            {"Operations": [{"op": "replace", "value": {"userName": "grace", "active": False}}]},
            {"Operations": [{"op": "replace", "path": "", "value": "x"}]},
            {"Operations": [{"op": "replace", "path": "active eq true", "value": "x"}]},
            {"Operations": [{"op": "replace", "path": 'emails[type eq "work"].value', "value": "a@example.org"}]},
            {"Operations": [{"op": "replace", "path": "name.familyName", "value": ""}]},
            {"Operations": [{"op": "replace", "path": "name", "value": ["Lovelace"]}]},
            {"Operations": [{"op": "replace", "path": "emails", "value": "ada@example.org"}]},
        ]
        with patch("bridge.app.LdapClient") as connector:
            directory = connector.return_value.__enter__.return_value
            directory.users.return_value = {"ada": ADA}
            for payload in rejected:
                response = self.client.patch(f"/scim/v2/Users/{identifier}", headers=SCIM_HEADERS, json=payload)
                self.assertEqual(response.status_code, 400, payload)
            response = self.client.patch("/scim/v2/Users/missing", headers=SCIM_HEADERS,
                                         json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
            self.assertEqual(response.status_code, 404)
            directory.write.assert_not_called()
        ignored = {"Operations": [{"op": "replace", "path": "active", "value": False}]}
        self.assertEqual(self.client.patch(f"/scim/v2/Users/{identifier}", json=ignored).status_code, 401)
        self.client.put("/api/settings", headers=HEADERS, json={"dry_run": True})
        with patch("bridge.app.LdapClient") as connector:
            response = self.client.patch(f"/scim/v2/Users/{identifier}", headers=SCIM_HEADERS, json=ignored)
            connector.assert_not_called()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.headers[ERROR_HEADER], "dry_run")

    def test_ignore_mode_does_not_advertise_new_capabilities(self):
        self.enable_ignore()
        config = self.client.get("/scim/v2/ServiceProviderConfig", headers=SCIM_HEADERS).json()
        self.assertFalse(config["changePassword"]["supported"])
        self.assertFalse(config["bulk"]["supported"])

    def test_scim_deletion_disabled(self):
        response = self.client.delete("/scim/v2/Users/ada", headers=SCIM_HEADERS)
        self.assertEqual(response.status_code, 405)
        self.assertIn("schemas", response.json())


if __name__ == "__main__":
    unittest.main()