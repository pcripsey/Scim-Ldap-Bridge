import json
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

import httpx
from fastapi.testclient import TestClient

from bridge.app import create_app
from bridge.config import ENTRA_SCIM_URL, Settings
from bridge.connectors import ScimClient, TrafficHttpClient
from bridge.self_target import ERROR_HEADER, SelfTargetError
from bridge.service import SyncService
from bridge.store import Store


TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
SECRET = "synthetic-client-credential"
TOKEN = "synthetic-oauth-access-token"
ADMIN = "synthetic-admin-token-at-least-24"


def settings(**values):
    return Settings(scim_provider="entra", scim_url=ENTRA_SCIM_URL, entra_tenant_id=TENANT,
                    entra_client_id=CLIENT, entra_client_secret=SECRET,
                    direction="scim_to_ldap", **values)


def resource(identifier="1", username="ada@example.org"):
    return {"id": identifier, "userName": username, "name": {"familyName": "Example"}}


class EntraConnectorTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        emitter = patch("bridge.connectors.emit",
                        side_effect=lambda *args, **kwargs: self.events.append((args, kwargs)))
        emitter.start()
        self.addCleanup(emitter.stop)

    def connector(self, handler, **values):
        client = ScimClient(settings(**values))
        client.entra.client.close()
        client.entra.client = TrafficHttpClient(
            base_url=ENTRA_SCIM_URL + "/", transport=httpx.MockTransport(handler),
            follow_redirects=False)
        self.addCleanup(client.__exit__)
        return client

    def oauth(self, handler=None):
        requests = []
        original = httpx.Client

        def respond(request):
            requests.append(request)
            return handler(request) if handler else httpx.Response(
                200, json={"access_token": TOKEN, "expires_in": 3600, "token_type": "Bearer"})

        def factory(**kwargs):
            self.assertEqual(kwargs, {"timeout": 30, "follow_redirects": False, "trust_env": False})
            return original(**kwargs, transport=httpx.MockTransport(respond))

        mock = patch("bridge.entra.httpx.Client", side_effect=factory)
        mock.start()
        self.addCleanup(mock.stop)
        return requests

    def assert_safe(self):
        logged = json.dumps(self.events)
        for value in (SECRET, TOKEN, TENANT, CLIENT, "ada@example.org"):
            self.assertNotIn(value, logged)
        self.assertNotIn("login.microsoftonline", logged)

    def test_client_credentials_cached_and_renewed_before_expiry(self):
        requests = []
        client = self.connector(lambda req: requests.append(req) or httpx.Response(200, json={"resources": []}))
        tokens = self.oauth()
        with patch("bridge.entra.time.monotonic", return_value=100):
            client.users()
            client.users()
        self.assertEqual(len(tokens), 1)
        self.assertEqual(str(tokens[0].url),
                         f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")
        self.assertEqual(parse_qs(tokens[0].content.decode()), {
            "grant_type": ["client_credentials"], "client_id": [CLIENT],
            "client_secret": [SECRET], "scope": ["https://graph.microsoft.com/.default"]})
        with patch("bridge.entra.time.monotonic", return_value=3640):
            client.users()
        self.assertEqual(len(tokens), 2)
        self.assertTrue(all(req.headers["authorization"] == "Bearer " + TOKEN for req in requests))
        self.assertNotIn(SECRET, repr(client.entra.settings))
        self.assert_safe()
        client.__exit__()
        self.assertEqual(client.entra.token, "")

    def test_safe_auth_failure_never_calls_resource_or_retries(self):
        outbound = Mock(return_value=httpx.Response(200, json={"resources": []}))
        client = self.connector(outbound)
        tokens = self.oauth(lambda req: httpx.Response(400, text=SECRET + TOKEN + TENANT))
        with self.assertRaisesRegex(RuntimeError, "OAuth authentication failed") as raised:
            client.users()
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertEqual(len(tokens), 1)
        outbound.assert_not_called()
        self.assertEqual(client.entra.token, "")
        self.assert_safe()

    def test_auth_response_validation(self):
        client = self.connector(lambda req: httpx.Response(200, json={"resources": []}))
        for body in ([], {}, {"access_token": TOKEN, "expires_in": True, "token_type": "bearer"},
                     {"access_token": TOKEN, "expires_in": -1, "token_type": "bearer"},
                     {"access_token": "bad\nheader", "expires_in": 3600, "token_type": "bearer"},
                     {"access_token": TOKEN, "expires_in": 3600, "token_type": "other"}):
            with self.subTest(body=body):
                with patch("bridge.entra.httpx.Client") as oauth:
                    response = oauth.return_value.__enter__.return_value.post.return_value
                    response.json.return_value = body
                    with self.assertRaises(RuntimeError):
                        client.users()
                self.assertEqual(client.entra.token, "")

    def test_oauth_redirect_not_followed(self):
        client = self.connector(lambda req: self.fail("Resource called after failed OAuth"))
        requests = self.oauth(lambda req: httpx.Response(
            307, headers={"location": "https://attacker.example/token"}, text=SECRET))
        with self.assertRaises(RuntimeError):
            client.users()
        self.assertEqual(len(requests), 1)

    def test_complete_cursor_pages_preserve_and_encode_filter(self):
        requests = []
        cursor = "https://attacker.example/?cursor=a&b=+/%"
        expression = 'userName eq "ada+tag&team@example.org"'

        def handler(req):
            requests.append(req)
            if "cursor" not in req.url.params:
                return httpx.Response(200, json={"resources": [resource()], "nextCursor": cursor})
            return httpx.Response(200, json={"resources": [resource("2", "grace@example.org")],
                                            "totalResults": 1})

        client = self.connector(handler, scim_filter=expression)
        self.oauth()
        self.assertEqual(len(client.users()), 2)
        self.assertEqual(len(requests), 2)
        for req in requests:
            self.assertEqual(req.url.host, "graph.microsoft.com")
            self.assertEqual(req.url.path, "/rp/scim/users")
            self.assertEqual(req.url.params["filter"], expression)
            self.assertEqual(req.url.params["count"], "100")
            self.assertNotIn("startIndex", req.url.params)
        self.assertEqual(requests[1].url.params["cursor"], cursor)
        self.assert_safe()

    def test_discovery_real_lowercase_routes_and_same_scoped_inventory(self):
        requests = []

        def handler(req):
            requests.append(req)
            if req.url.path.endswith("/users"):
                return httpx.Response(200, json={"resources": [resource()]})
            return httpx.Response(200, json={"Resources": []})

        client = self.connector(handler, scim_filter="active eq true")
        self.oauth()
        result = client.discovery()
        self.assertEqual(result["users"], 1)
        self.assertIn("name.familyName", [item["name"] for item in result["attributes"]])
        self.assertEqual([req.url.path for req in requests],
                         ["/rp/scim/schemas", "/rp/scim/resourcetypes", "/rp/scim/users"])
        self.assertEqual(requests[-1].url.params["filter"], "active eq true")
        self.assert_safe()

    def test_bad_cursor_pages_fail_without_partial_samples(self):
        for page in ({}, [], {"Resources": []}, {"resources": {}},
                     {"resources": [], "nextCursor": "again"},
                     {"resources": [], "nextCursor": 123},
                     {"resources": [], "nextCursor": "x" * 16385}):
            with self.subTest(page=str(page)[:80]):
                client = self.connector(lambda req: httpx.Response(200, json=page))
                with patch.object(client.entra, "_access_token", return_value=TOKEN):
                    with self.assertRaises(ValueError):
                        client.users()
                self.assertEqual(client.entra.discovered_attributes, {})

    def test_repeated_cursors_duplicate_id_and_username_fail(self):
        for second in ({"resources": [resource("2", "grace")], "nextCursor": "repeat"},
                       {"resources": [resource("1", "grace")]},
                       {"resources": [resource("2", "ADA@example.org")]}):
            pages = iter([{"resources": [resource()], "nextCursor": "repeat"}, second])
            client = self.connector(lambda req: httpx.Response(200, json=next(pages)))
            with patch.object(client.entra, "_access_token", return_value=TOKEN):
                with self.assertRaises(ValueError):
                    client.users()
            self.assertEqual(client.entra.discovered_attributes, {})

    def test_malformed_resources_rejected(self):
        for item in (None, [], {}, {"id": "1"}, {"userName": "ada"},
                     resource(username=42), resource(username="  "),
                     resource(username="ada\ninjected"), {**resource(), "displayName": {}},
                     {**resource(), "name": []}, {**resource(), "emails": {}},
                     {**resource(), "name": {"familyName": []}},
                     {**resource(), "emails": ["invalid"]},
                     {**resource(), "emails": [{"value": {}}]}):
            client = self.connector(lambda req: httpx.Response(200, json={"resources": [item]}))
            with self.subTest(item=item), patch.object(client.entra, "_access_token", return_value=TOKEN):
                with self.assertRaises(ValueError):
                    client.users()

    def test_limits_bound_inventory_and_page_size(self):
        client = self.connector(lambda req: httpx.Response(
            200, json={"resources": [resource(str(i), str(i)) for i in range(101)]}))
        with patch.object(client.entra, "_access_token", return_value=TOKEN):
            with self.assertRaises(ValueError):
                client.users()
        client = self.connector(lambda req: httpx.Response(200, json={"resources": [resource()]}))
        with patch.object(client.entra, "_access_token", return_value=TOKEN), \
                patch("bridge.connectors.MAX_USERS", 0):
            with self.assertRaises(ValueError):
                client.users()

    def test_resource_redirect_unauthorized_and_self_target_never_retried(self):
        for status in (302, 401, 403, 429, 500):
            handler = Mock(return_value=httpx.Response(
                status, text=SECRET, headers={"location": "https://attacker.example/users"}))
            client = self.connector(handler)
            with patch.object(client.entra, "_access_token", return_value=TOKEN):
                with self.assertRaises(RuntimeError):
                    client.users()
            self.assertEqual(handler.call_count, 1)
        client = self.connector(lambda req: httpx.Response(400, headers={ERROR_HEADER: "self_target"}))
        with patch.object(client.entra, "_access_token", return_value=TOKEN):
            with self.assertRaises(SelfTargetError):
                client.users()
        self.assert_safe()

    def test_write_blocked_before_any_request(self):
        handler = Mock()
        client = self.connector(handler)
        with self.assertRaisesRegex(ValueError, "pull-only"):
            client.write({})
        handler.assert_not_called()

    def test_transport_and_invalid_json_fail_safely_without_retry(self):
        for result in (httpx.ReadTimeout(SECRET), httpx.Response(200, text=SECRET)):
            handler = Mock(side_effect=result) if isinstance(result, Exception) else Mock(return_value=result)
            client = self.connector(handler)
            with patch.object(client.entra, "_access_token", return_value=TOKEN):
                with self.assertRaises(RuntimeError) as raised:
                    client.users()
            self.assertNotIn(SECRET, str(raised.exception))
            self.assertEqual(handler.call_count, 1)
        self.assert_safe()

    def test_authority_and_destination_checked_even_for_unvalidated_settings(self):
        for change in ({"scim_url": "https://attacker.example/rp/scim"},
                       {"scim_url": "https://graph.microsoft.com/rp/scim?next=evil"},
                       {"scim_url": "http://graph.microsoft.com/rp/scim"},
                       {"scim_url": "https://graph.microsoft.us/rp/scim"},
                       {"scim_url": "https://graph.microsoft.com/rp/scim//"},
                       {"entra_tenant_id": "../common"}, {"entra_client_id": "bad"},
                       {"direction": "bidirectional"}, {"direction": "ldap_to_scim"}):
            with self.subTest(change=change), patch("bridge.connectors.TrafficHttpClient") as outbound:
                with self.assertRaises(ValueError):
                    ScimClient(settings().model_copy(update=change))
                outbound.assert_not_called()


class EntraSettingsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.client = TestClient(create_app(self.directory.name, ADMIN))
        self.client.__enter__()
        self.headers = {"Authorization": "Bearer " + ADMIN}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.directory.cleanup()

    def save(self, payload):
        return self.client.put("/api/settings", headers=self.headers, json=payload)

    def test_migration_and_secret_preserve_replace_clear_encrypted_redacted(self):
        old = self.client.get("/api/settings", headers=self.headers).json()
        self.assertEqual(old["scim_provider"], "generic")
        self.assertFalse(old["entra_client_secret_configured"])
        payload = settings().model_dump()
        payload["confirm_scope_reset"] = True
        self.assertEqual(self.save(payload).status_code, 200)
        self.assertEqual(self.save({"interval_seconds": 600}).status_code, 200)
        self.assertEqual(self.client.app.state.store.settings().entra_client_secret, SECRET)
        read = self.client.get("/api/settings", headers=self.headers)
        self.assertNotIn(SECRET, read.text)
        self.assertNotIn("entra_client_secret", read.json())
        self.assertTrue(read.json()["entra_client_secret_configured"])
        self.assertEqual(self.save({"entra_client_secret": "replacement-synthetic"}).status_code, 200)
        self.assertEqual(self.save({"entra_client_secret": ""}).status_code, 200)
        self.assertFalse(self.client.get("/api/settings", headers=self.headers).json()["entra_client_secret_configured"])
        self.assertEqual(self.save({"enabled": True}).status_code, 400)
        for file in self.client.app.state.store.directory.glob("bridge.db*"):
            self.assertNotIn(SECRET.encode(), file.read_bytes())

    def test_scope_change_confirmation_and_reset(self):
        self.client.app.state.store.save_settings(settings())
        for key, value in (("entra_tenant_id", CLIENT), ("entra_client_id", TENANT),
                           ("scim_filter", "active eq true"), ("scim_provider", "generic")):
            store = self.client.app.state.store
            before = settings()
            store.save_settings(before)
            store.replace_resources("scim", "Users", {"ada": resource()})
            store.snapshot("ada", {}, {})
            self.assertEqual(self.save({key: value}).status_code, 400)
            self.assertIsNotNone(store.resource("scim", "Users", "ada"))
            self.assertTrue(store.snapshots())
            self.assertEqual(self.save({key: value, "confirm_scope_reset": True}).status_code, 200)
            self.assertIsNone(store.resource("scim", "Users", "ada"))
            self.assertEqual(store.snapshots(), {})
        self.assertFalse(self.client.app.state.service.lock.locked())

    def test_supported_filter_subset_and_rejections(self):
        for expression in ('userName eq "ada+tag&team@example.org"', 'userName ew "@example.org"',
                           'id eq "1"', 'externalId eq "1"', 'groups.value eq "1"',
                           "active eq true", "active eq FALSE", ""):
            self.assertEqual(settings(scim_filter=expression).scim_filter, expression)
        for expression in ('displayName eq "Ada"', 'userName sw "ada"', 'active eq "true"',
                           'id ew "1"', 'userName eq "a" and active eq true',
                           'not(userName ew "@example.org")', 'userName eq "a" trailing',
                           'userName eq "a\\n"', 'userName eq ""'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                settings(scim_filter=expression)
        with self.assertRaises(ValueError):
            Settings(scim_filter="active eq true")

    def test_test_discovery_mapping_and_sync_use_saved_entra_scope(self):
        configured = settings(scim_filter="active eq true", ldap_url="ldaps://ldap.example.org",
                              ldap_bind_dn="cn=bridge", ldap_password="synthetic-ldap-password",
                              ldap_base_dn="ou=people")
        self.client.app.state.store.save_settings(configured)
        with patch("bridge.app.ScimClient") as scim, patch("bridge.app.LdapClient") as ldap:
            scim.return_value.__enter__.return_value.users.return_value = {}
            discovery = {"schemas": [], "resource_types": [], "attributes": [], "users": 0}
            scim.return_value.__enter__.return_value.discovery.return_value = discovery
            ldap.return_value.__enter__.return_value.discovery.return_value = discovery
            for path in ("/api/test/scim", "/api/discovery/scim", "/api/mappings/validate"):
                response = self.client.post(path, headers=self.headers, json={
                    "attribute_mappings": [item.model_dump() for item in configured.attribute_mappings]})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(scim.call_args.args[0].scim_filter, "active eq true")
        with patch.object(self.client.app.state.service, "trigger", return_value=1):
            self.assertEqual(self.client.post("/api/sync", headers=self.headers).status_code, 202)


class EntraInventoryTests(unittest.TestCase):
    def test_complete_scoped_read_flows_to_dry_run_ldap_plan_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            self.addCleanup(store.close)
            service = SyncService(store)
            client = ScimClient(settings(scim_filter="active eq true"))
            client.entra.client.close()
            requests = []
            client.entra.client = TrafficHttpClient(
                base_url=ENTRA_SCIM_URL + "/", transport=httpx.MockTransport(
                    lambda req: requests.append(req) or httpx.Response(200, json={"resources": [resource()]})))
            with patch.object(client.entra, "_access_token", return_value=TOKEN), \
                    patch("bridge.service.ScimClient", return_value=client), \
                    patch("bridge.service.LdapClient") as ldap:
                ldap.return_value.__enter__.return_value.users.return_value = {}
                run = store.begin_run(True)
                service.lock.acquire()
                service.run(settings(scim_filter="active eq true"), run)
                ldap.return_value.__enter__.return_value.write.assert_not_called()
            self.assertEqual(requests[0].url.params["filter"], "active eq true")
            self.assertEqual(store.rows("runs")[0]["status"], "completed")
            self.assertEqual(store.operations()[0]["target"], "ldap")
            self.assertEqual(store.operations()[0]["status"], "preview")
            self.assertEqual(store.resource("scim", "Users", "ada@example.org")["familyName"], "Example")
            self.assertFalse(service.lock.locked())

    def test_partial_fetch_failure_preserves_inventory_baseline_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            self.addCleanup(store.close)
            store.replace_resources("scim", "Users", {"original": resource()})
            store.snapshot("original", {"old": True}, {"old": True})
            baseline = store.snapshots()
            service = SyncService(store)
            client = ScimClient(settings())
            self.addCleanup(client.__exit__)
            pages = iter([{"resources": [resource()], "nextCursor": "next"}])

            def handler(req):
                if "cursor" in req.url.params:
                    return httpx.Response(503, text=SECRET)
                return httpx.Response(200, json=next(pages))

            client.entra.client.close()
            client.entra.client = TrafficHttpClient(base_url=ENTRA_SCIM_URL + "/",
                                                    transport=httpx.MockTransport(handler))
            with patch.object(client.entra, "_access_token", return_value=TOKEN), \
                    patch("bridge.service.ScimClient", return_value=client), \
                    patch("bridge.service.LdapClient") as ldap:
                run = store.begin_run(True)
                service.lock.acquire()
                service.run(settings(), run)
                ldap.return_value.__enter__.return_value.users.assert_not_called()
                ldap.return_value.__enter__.return_value.write.assert_not_called()
            self.assertEqual(store.snapshots(), baseline)
            self.assertIsNotNone(store.resource("scim", "Users", "original"))
            self.assertIsNone(store.resource("scim", "Users", "ada@example.org"))
            self.assertEqual(store.operations(), [])
            self.assertEqual(store.rows("runs")[0]["status"], "failed")
            self.assertNotIn(SECRET, json.dumps(store.rows("events")))
            self.assertFalse(service.lock.locked())


if __name__ == "__main__":
    unittest.main()
