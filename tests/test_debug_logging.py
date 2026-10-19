import asyncio
import io
import json
import logging
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient
from ldap3 import MODIFY_REPLACE

from bridge.app import create_app
from bridge.config import ENTRA_SCIM_URL, Settings
from bridge.connectors import LdapClient, ScimClient, TrafficHttpClient, from_scim
from bridge.log_safety import (
    MAX_BYTES, MAX_ITEMS, MAX_STRING, REDACTED, TRUNCATED, sanitize,
)
from bridge.traffic import (
    JsonCapture, TrafficMiddleware, correlation_id, debug_event, logger,
)


ADMIN = "synthetic-admin-for-debug-tests-only"
SCIM = "synthetic-scim-for-debug-tests-only"
SECRET = "synthetic-sensitive-value-98124"


class DebugLoggingTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.old_handlers = logger.handlers[:]
        self.old_level = logger.level
        logger.handlers = [logging.StreamHandler(self.output)]
        logger.setLevel(logging.DEBUG)
        self.addCleanup(self.restore_logging)

    def restore_logging(self):
        logger.handlers = self.old_handlers
        logger.setLevel(self.old_level)

    def records(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def test_ad_generated_password_is_redacted_even_at_debug(self):
        client = LdapClient(Settings(
            ldap_service="active_directory", ad_enable_new_accounts=True,
            ldap_url="ldaps://directory.example.org", ldap_bind_dn="cn=bridge",
            ldap_password="test-bind", ldap_base_dn="dc=example,dc=org", dry_run=False,
        ))
        client.connection = Mock()
        client.connection.server.ssl = True
        client.connection.result = {"result": 0}
        client.connection.add.return_value = True
        client.connection.modify.return_value = True
        with patch("bridge.connectors.secrets.token_urlsafe", return_value=SECRET):
            client.write(from_scim({"userName": "ada", "name": {"familyName": "Lovelace"}}))
        password_event = next(record for record in self.records()
                              if record["operation"] == "modify_attributes"
                              and "unicodePwd" in record["data"]["changes"])
        self.assertEqual(password_event["data"]["changes"]["unicodePwd"], REDACTED)
        self.assertNotIn(SECRET, self.output.getvalue())
        self.assertNotIn(repr(('"aA1!' + SECRET + '"').encode("utf-16-le")), self.output.getvalue())

    def app_client(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        app = create_app(directory.name, ADMIN, SCIM)
        logger.setLevel(logging.DEBUG)
        client = TestClient(app)
        client.__enter__()
        self.addCleanup(client.__exit__, None, None, None)
        return app, client

    def test_rejected_create_logs_attributes_and_safe_validation_detail(self):
        app, client = self.app_client()
        payload = {
            "userName": "ada@example.invalid", "name": {"familyName": "Lovelace"},
            "active": False, "groups": [], "password": SECRET,
            "urn:example:User": {"enabled": True, "empty": None,
                                 "nested": [{"access_token": SECRET, "costCenter": 42}]},
        }
        with patch("bridge.app.LdapClient") as ldap:
            response = client.post("/scim/v2/Users", json=payload,
                                   headers={"Authorization": "Bearer " + SCIM, "Cookie": SECRET})
        self.assertEqual(response.status_code, 400)
        ldap.assert_not_called()
        records = self.records()
        request = next(e for e in records if e["operation"] == "request_payload")
        self.assertFalse(request["data"]["active"])
        self.assertEqual(request["data"]["groups"], [])
        self.assertEqual(request["data"]["password"], REDACTED)
        self.assertIsNone(request["data"]["urn:example:User"]["empty"])
        self.assertEqual(request["data"]["urn:example:User"]["nested"][0]["costCenter"], 42)
        reply = next(e for e in records if e["operation"] == "response_payload")
        self.assertIn("not supported", reply["data"]["detail"])
        self.assertEqual({r["request_id"] for r in records}, {response.headers["x-request-id"]})
        for secret in (SECRET, ADMIN, SCIM):
            self.assertNotIn(secret, self.output.getvalue())
        self.assertEqual(correlation_id.get(), "")

    def test_patch_body_and_successful_create_reach_validation_unchanged(self):
        app, client = self.app_client()
        app.state.store.save_settings(Settings(dry_run=False))
        headers = {"Authorization": "Bearer " + SCIM}
        document = {"userName": "ada", "name": {"familyName": "Lovelace"}}
        directory = Mock()
        directory.users.return_value = {}
        with patch("bridge.app.LdapClient") as ldap:
            ldap.return_value.__enter__.return_value = directory
            response = client.post("/scim/v2/Users", json=document, headers=headers)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(directory.write.call_args.args[0]["userName"], "ada")
        operations = {"Operations": [{"op": "replace", "path": "password", "value": SECRET},
                                     {"op": "replace", "path": "active", "value": False}]}
        directory.users.return_value = {"ada": from_scim(document)}
        with patch("bridge.app.LdapClient") as ldap:
            ldap.return_value.__enter__.return_value = directory
            response = client.patch("/scim/v2/Users/YWRh", json=operations, headers=headers)
        self.assertEqual(response.status_code, 400)
        data = [e["data"] for e in self.records() if e["operation"] == "request_payload"][-1]
        self.assertEqual(data["Operations"][0]["value"], REDACTED)
        self.assertFalse(data["Operations"][1]["value"])
        reply = [e for e in self.records() if e["operation"] == "response_payload"][-1]
        self.assertEqual(reply["data"]["detail"], "Only name, displayName, and emails can be patched.")
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_invalid_non_json_oversized_and_wrong_shape_bodies_are_safe(self):
        _, client = self.app_client()
        for body, content_type, capture in [
            ('{"password":"' + SECRET, "application/json", "invalid_json"),
            (SECRET, "text/plain", "non_json"),
            (json.dumps({"password": SECRET, "large": "x" * MAX_BYTES}),
             "application/json", "byte_limit"),
        ]:
            self.output.seek(0)
            self.output.truncate()
            response = client.post("/scim/v2/Users", content=body,
                                   headers={"Authorization": "Bearer " + SCIM,
                                            "Content-Type": content_type})
            self.assertEqual(response.status_code, 400)
            event = next(e for e in self.records() if e["operation"] == "request_payload")
            self.assertEqual(event["data"]["capture"], capture)
            self.assertNotIn(SECRET, self.output.getvalue())
        response = client.post("/scim/v2/Users", json=["wrong", "shape"],
                               headers={"Authorization": "Bearer " + SCIM})
        self.assertEqual(response.status_code, 400)

    def test_management_and_oauth_bodies_never_captured(self):
        _, client = self.app_client()
        client.put("/api/settings", json={"ldap_password": SECRET},
                   headers={"Authorization": "Bearer " + ADMIN})
        client.post("/oauth/token", json={"access_token": SECRET})
        self.assertFalse(any(e["operation"].endswith("_payload") for e in self.records()))
        with TrafficHttpClient(base_url="https://example.invalid/scim/v2/",
                               transport=httpx.MockTransport(
                                   lambda r: httpx.Response(200, json={"access_token": SECRET}))) as outbound:
            outbound.post("oauth/token", json={"client_secret": SECRET})
            outbound.post("https://other.invalid/scim/v2/Users", json={"userName": SECRET})
        self.assertFalse(any(e["operation"].endswith("_payload") for e in self.records()))
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_outbound_scim_payloads_errors_and_correlation(self):
        token = correlation_id.set("a" * 32)
        self.addCleanup(correlation_id.reset, token)
        requests = []

        def handler(request):
            requests.append(json.loads(request.content))
            return httpx.Response(400, json={"status": "400", "detail": SECRET,
                                            "userPassword": SECRET, "active": False})

        payload = {"Operations": [{"op": "replace", "path": "userPassword;binary", "value": SECRET},
                                  {"op": "replace", "path": "displayName", "value": "Ada"}]}
        with TrafficHttpClient(base_url="https://example.invalid/scim/v2/",
                               transport=httpx.MockTransport(handler)) as client:
            response = client.patch("Users/ada?access_token=" + SECRET, json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(requests, [payload])
        request, reply = [e for e in self.records() if e["level"] == "DEBUG"]
        self.assertEqual(request["data"]["Operations"][0]["value"], REDACTED)
        self.assertEqual(request["data"]["Operations"][1]["value"], "Ada")
        self.assertFalse(reply["data"]["active"])
        self.assertEqual(reply["data"]["detail"], REDACTED)
        self.assertEqual({e["request_id"] for e in self.records()}, {"a" * 32})
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_entra_debug_logs_resources_but_not_oauth_exchange(self):
        tenant = "11111111-1111-1111-1111-111111111111"
        client_id = "22222222-2222-2222-2222-222222222222"
        client = ScimClient(Settings(
            scim_provider="entra", scim_url=ENTRA_SCIM_URL, entra_tenant_id=tenant,
            entra_client_id=client_id, entra_client_secret=SECRET, direction="scim_to_ldap"))
        self.addCleanup(client.__exit__)
        client.entra.client.close()
        client.entra.client = TrafficHttpClient(
            base_url=ENTRA_SCIM_URL + "/", transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={
                    "resources": [{"id": "1", "userName": "ada", "name": {"familyName": "Example"}}],
                    "nextCursor": None,
                })))
        original_client = httpx.Client
        oauth_requests = []

        def token_response(request):
            oauth_requests.append(request)
            return httpx.Response(200, json={
                "access_token": SECRET, "expires_in": 3600, "token_type": "Bearer"})

        with patch("bridge.entra.httpx.Client", side_effect=lambda **kw: original_client(
                **kw, transport=httpx.MockTransport(token_response))):
            self.assertIn("ada", client.users())
        self.assertEqual(len(oauth_requests), 1)
        self.assertTrue(any(e.get("data", {}).get("resources") for e in self.records()))
        for value in (tenant, client_id, SECRET, "login.microsoftonline"):
            self.assertNotIn(value, self.output.getvalue())

    def test_ldap_search_add_modify_include_exact_attributes_without_credentials(self):
        token = correlation_id.set("b" * 32)
        self.addCleanup(correlation_id.reset, token)
        settings = Settings(ldap_url="ldaps://directory.invalid", ldap_base_dn="ou=People,dc=example",
                            ldap_bind_dn="cn=" + SECRET, ldap_password=SECRET)
        client = LdapClient(settings)
        client.connection = Mock(result={"result": 0})
        entry = {"type": "searchResEntry", "dn": "uid=ada,ou=People,dc=example",
                 "attributes": {"uid": ["ada"], "sn": ["Lovelace"], "userPassword;binary": SECRET,
                                "jpegPhoto": b"binary-" + SECRET.encode(),
                                "whenCreated": datetime(2026, 1, 1, tzinfo=timezone.utc)}}
        for method in (client.users, client.discovery):
            client.connection.extend.standard.paged_search.return_value = iter([entry])
            method()
        user = from_scim({"userName": "ada", "name": {"familyName": "Lovelace"}})
        client.write(user)
        client.write(user, {"_dn": entry["dn"]})
        client._modify(entry["dn"], {"unicodePwd": [(MODIFY_REPLACE, [SECRET])]})
        events = self.records()
        search = next(e for e in events if e["operation"] == "search_request")
        self.assertEqual(search["data"]["base_dn"], settings.ldap_base_dn)
        self.assertEqual(search["data"]["filter"], "(objectClass=inetOrgPerson)")
        returned = next(e for e in events if e["operation"] == "search_entry")
        self.assertEqual(returned["data"]["attributes"]["userPassword;binary"], REDACTED)
        self.assertEqual(returned["data"]["attributes"]["jpegPhoto"], "<binary omitted>")
        self.assertEqual(returned["data"]["attributes"]["whenCreated"], "2026-01-01T00:00:00+00:00")
        added = next(e for e in events if e["operation"] == "add_attributes")
        self.assertIn("inetOrgPerson", added["data"]["object_classes"])
        self.assertEqual(added["data"]["attributes"], client.connection.add.call_args.args[2])
        modified = next(e for e in events if e["operation"] == "modify_attributes")
        self.assertEqual(modified["data"]["changes"]["sn"], [[MODIFY_REPLACE, ["Lovelace"]]])
        self.assertEqual({e["request_id"] for e in events}, {"b" * 32})
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_search_limits_entry_events(self):
        client = LdapClient(Settings(ldap_url="ldaps://directory.invalid",
                                    ldap_bind_dn="cn=service", ldap_password=SECRET,
                                    ldap_base_dn="ou=People"))
        client.connection = Mock(result={"result": 0})
        client.connection.extend.standard.paged_search.return_value = iter([
            {"type": "searchResEntry", "dn": "uid=ada", "attributes": {"uid": ["ada"]}}
        ] * (MAX_ITEMS + 10))
        client.discovery()
        entries = [e for e in self.records() if e["operation"] == "search_entry"]
        self.assertEqual(len(entries), MAX_ITEMS + 1)
        self.assertEqual(entries[-1]["data"], {"truncated": True})

    def test_info_warning_error_and_off_do_not_capture_values(self):
        _, client = self.app_client()
        for level in (logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL + 1):
            with self.subTest(level=level):
                self.output.seek(0)
                self.output.truncate()
                logger.setLevel(level)
                with patch("bridge.traffic.JsonCapture", side_effect=AssertionError("capture at INFO")):
                    response = client.post("/scim/v2/Users",
                                           json={"userName": SECRET, "active": False},
                                           headers={"Authorization": "Bearer " + SCIM})
                    self.assertEqual(response.status_code, 400)
                    debug_event("outbound", "ldap", "add", {"uid": SECRET})
                self.assertNotIn(SECRET, self.output.getvalue())
                self.assertFalse(any(e["level"] == "DEBUG" for e in self.records()))
                if level > logging.CRITICAL:
                    self.assertEqual(self.records(), [])

    def test_raw_asgi_chunk_capture_preserves_message_identity(self):
        messages = [
            {"type": "http.request", "body": b'{"userName":', "more_body": True},
            {"type": "http.request", "body": b'"ada","active":false}', "more_body": False},
        ]
        originals = messages[:]
        sent = []

        async def app(scope, receive, send):
            self.assertIs(await receive(), originals[0])
            self.assertIs(await receive(), originals[1])
            await send({"type": "http.response.start", "status": 400,
                        "headers": [(b"content-type", b"application/scim+json")]})
            await send({"type": "http.response.body", "body": b'{"status":"400"}'})

        async def receive():
            return messages.pop(0)

        async def send(message):
            sent.append(message)

        asyncio.run(TrafficMiddleware(app)(
            {"type": "http", "method": "POST", "path": "/scim/v2/Users",
             "headers": [(b"content-type", b"application/scim+json")]}, receive, send))
        self.assertEqual(sent[-1]["body"], b'{"status":"400"}')
        self.assertEqual(self.records()[0]["data"], {"userName": "ada", "active": False})

    def test_outbound_streams_not_read_and_logging_failures_do_not_affect_traffic(self):
        class Stream(httpx.SyncByteStream):
            def __iter__(self):
                raise AssertionError("stream consumed")

        with TrafficHttpClient(base_url="https://example.invalid/scim/v2/",
                               transport=httpx.MockTransport(lambda r: httpx.Response(
                                   200, stream=Stream(), headers={"content-type": "application/json"}))) as client:
            with client.stream("GET", "Users") as response:
                self.assertFalse(response.is_stream_consumed)
        self.assertEqual(self.records()[-1]["data"]["capture"], "stream_not_read")
        with patch("bridge.traffic.sanitize", side_effect=RuntimeError(SECRET)):
            debug_event("inbound", "scim", "request_payload", {"userName": SECRET})
        with patch.object(logger, "log", side_effect=OSError(SECRET)):
            debug_event("inbound", "scim", "request_payload", {"userName": SECRET})
        self.assertNotIn(SECRET, self.output.getvalue())

    def test_recursive_redaction_and_serialization_bounds(self):
        class Unsafe:
            def __repr__(self):
                raise AssertionError("repr called")

            __str__ = __repr__

        secrets = ["PASSWORD", "userPassword;binary", "unicodePwd", "access_token",
                   "refresh-token", "credentials", "private_key", "encryption-key",
                   "urn:example:User:clientSecret", "Authorization", "Cookie"]
        value = {key: SECRET for key in secrets}
        value.update({
            "nested": [{"path": "urn:example:User:UserPassword", "value": [SECRET]},
                       {"attribute": "unicodePwd", "values": [SECRET]},
                       ["userPassword", [(MODIFY_REPLACE, SECRET)]],
                       {"path": 'emails[password eq "' + SECRET + '"].value', "value": SECRET}],
            "url": "https://example.invalid/" + SECRET,
            "exception": Unsafe(), "bytes": SECRET.encode(),
            "text": "x" * (MAX_STRING + 1), "items": list(range(MAX_ITEMS + 1)),
        })
        result = sanitize(value)
        self.assertNotIn(SECRET, json.dumps(result))
        for key in secrets:
            self.assertEqual(result[key], REDACTED)
        self.assertTrue(result["text"].endswith(TRUNCATED))
        self.assertEqual(result["items"][-1], TRUNCATED)
        deep = {}
        deep["cycle"] = deep
        self.assertIn(TRUNCATED, json.dumps(sanitize(deep)))
        debug_event("outbound", "ldap", "entry", {"long": ["\u0001" * MAX_STRING] * MAX_ITEMS})
        self.assertLessEqual(len(self.output.getvalue().encode()), MAX_BYTES)
        self.assertTrue(self.records()[-1]["data"]["truncated"])
        capture = JsonCapture("application/json")
        capture.add(b"x" * MAX_BYTES)
        capture.add(b"x")
        self.assertEqual(len(capture.body), 0)
        self.assertTrue(capture.data()["truncated"])
        late_path = {"value": SECRET, **{str(i): i for i in range(MAX_ITEMS)}, "path": "password"}
        self.assertNotIn(SECRET, json.dumps(sanitize(late_path)))
        multiline_path = {"path": 'emails[value eq "\n' + SECRET + '"].value', "value": []}
        self.assertNotIn(SECRET, json.dumps(sanitize(multiline_path)))
