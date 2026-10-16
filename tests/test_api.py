import tempfile
import unittest
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