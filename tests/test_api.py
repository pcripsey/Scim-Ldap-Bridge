import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from bridge.app import create_app
from bridge.planner import canonical


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
        self.assertEqual(self.client.get("/scim/v2/ResourceTypes/Group", headers=SCIM_HEADERS).status_code, 404)

    def test_user_resources_include_meta_and_full_filter_support(self):
        with patch("bridge.app.LdapClient") as connector:
            connector.return_value.__enter__.return_value.users.return_value = {"ada": ADA}
            response = self.client.get('/scim/v2/Users?filter=name.familyName%20eq%20%22Lovelace%22',
                                       headers=SCIM_HEADERS)
        self.assertEqual(response.status_code, 200)
        user = response.json()["Resources"][0]
        self.assertEqual(user["meta"]["resourceType"], "User")
        self.assertTrue(user["meta"]["location"].endswith("/scim/v2/Users/YWRh"))

    def test_mapping_settings_reject_duplicate_or_sensitive_attributes(self):
        response = self.client.put("/api/settings", headers=HEADERS, json={
            "attribute_mappings": [
                {"scim_path": "userName", "ldap_attribute": "uid"},
                {"scim_path": "displayName", "ldap_attribute": "userPassword"},
            ],
        })
        self.assertEqual(response.status_code, 400)

    def test_inbound_dry_run_blocks_writes(self):
        response = self.client.post("/scim/v2/Users", headers=SCIM_HEADERS,
                                   json={"userName": "ada", "name": {"familyName": "Lovelace"}})
        self.assertEqual(response.status_code, 409)

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

    def test_scim_deletion_disabled(self):
        response = self.client.delete("/scim/v2/Users/ada", headers=SCIM_HEADERS)
        self.assertEqual(response.status_code, 405)
        self.assertIn("schemas", response.json())


if __name__ == "__main__":
    unittest.main()