import json
import ssl
import unittest
from unittest.mock import Mock, patch

import httpx
from ldap3 import AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND

from bridge import traffic
from bridge.config import Settings
from bridge.connectors import LdapClient, ScimClient, TrafficHttpClient, from_scim


SECRET = "synthetic-sensitive-6f103e"


class ConnectorLoggingTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.emitter = patch("bridge.connectors.emit", side_effect=self.capture)
        self.emitter.start()
        self.addCleanup(self.emitter.stop)

    def capture(self, direction, protocol, operation, result, duration_ms, **metadata):
        self.events.append(dict(direction=direction, protocol=protocol, operation=operation,
                                result=result, duration_ms=duration_ms, **metadata))

    def assert_safe(self):
        serialized = json.dumps(self.events)
        self.assertNotIn(SECRET, serialized)
        for event in self.events:
            self.assertEqual(event["direction"], "outbound")
            self.assertGreaterEqual(event["duration_ms"], 0)
            self.assertNotIn("password", event)
            self.assertNotIn("dn", event)
            self.assertNotIn("filter", event)

    def scim(self, handler):
        client = ScimClient(Settings(scim_url=f"https://example.org/{SECRET}/scim",
                                     scim_token=SECRET))
        client.client.close()
        client.client = TrafficHttpClient(
            base_url=f"https://example.org/{SECRET}/scim/",
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer " + SECRET})
        self.addCleanup(client.client.close)
        return client

    def ldap(self, **settings):
        client = LdapClient(Settings(ldap_url="ldap://directory.example.org",
                                     ldap_bind_dn="cn=" + SECRET, ldap_password=SECRET,
                                     ldap_base_dn="ou=" + SECRET, **settings))
        client.connection = Mock()
        client.connection.result = {"result": 0, "message": SECRET, "dn": SECRET}
        return client

    def entries(self):
        return [{"type": "searchResRef", "uri": SECRET},
                {"type": "searchResEntry", "dn": "uid=" + SECRET,
                 "attributes": {"uid": [SECRET], "sn": [SECRET], "userPassword": SECRET}}]

    def test_scim_pagination_logs_each_request_without_secrets(self):
        requests = []

        def handler(request):
            requests.append(request)
            start = request.url.params["startIndex"]
            return httpx.Response(200, json={
                "Resources": [{"id": SECRET, "userName": SECRET}] if start == "1" else [],
            }, headers={"content-type": "application/scim+json",
                        "set-cookie": SECRET, "authorization": SECRET,
                        "x-diagnostic": SECRET})

        client = self.scim(handler)
        self.assertIn(SECRET, client.users())
        self.assertEqual(len(requests), 2)
        self.assertEqual([e["path"] for e in self.events], ["/Users", "/Users"])
        self.assertEqual([e["status"] for e in self.events], [200, 200])
        self.assertEqual([r.url.params["startIndex"] for r in requests], ["1", "2"])
        self.assert_safe()

    def test_scim_status_categories_preserve_http_errors(self):
        for status, result in [(201, "success"), (302, "redirect"), (400, "client_error"),
                               (401, "unauthorized"), (403, "forbidden"), (404, "not_found"),
                               (408, "timeout"), (409, "conflict"), (429, "rate_limited"),
                               (500, "upstream_error"), (503, "upstream_error")]:
            with self.subTest(status=status):
                client = self.scim(lambda request: httpx.Response(status, text=SECRET))
                response = client.client.get("Users", params={"filter": SECRET})
                self.assertEqual(self.events[-1]["result"], result)
                self.assertEqual(self.events[-1]["status"], status)
                if status >= 300:
                    with self.assertRaises(httpx.HTTPStatusError):
                        response.raise_for_status()
        self.assert_safe()

    def test_scim_transport_errors_are_logged_and_not_retried(self):
        for error_class in (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.ConnectError):
            error = error_class(SECRET)
            handler = Mock(side_effect=error)
            client = self.scim(handler)
            with self.subTest(error=error_class), self.assertRaises(error_class) as raised:
                client.users()
            self.assertIs(raised.exception, error)
            self.assertEqual(handler.call_count, 1)
            self.assertEqual(self.events[-1]["error"], error_class.__name__)
            self.assertEqual(self.events[-1]["result"],
                             "timeout" if issubclass(error_class, httpx.TimeoutException)
                             else "transport_error")
        self.assert_safe()

    def test_scim_discovery_and_writes_have_fixed_routes(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"Resources": [], "totalResults": 0})

        client = self.scim(handler)
        self.assertEqual(client.discovery()["users"], 0)
        user = from_scim({"userName": SECRET, "name": {"familyName": SECRET}})
        client.write(user)
        client.write(user, {"_id": SECRET + "/nested", "_raw": {"meta": {"version": SECRET}}})
        self.assertEqual([e["path"] for e in self.events],
                         ["/Schemas", "/ResourceTypes", "/Users", "/Users", "/Users/{id}"])
        self.assertEqual([e["method"] for e in self.events], ["GET", "GET", "GET", "POST", "PATCH"])
        self.assertEqual(requests[-1].headers["if-match"], SECRET)
        self.assertIn(SECRET.encode(), requests[-1].content)
        self.assert_safe()

    def test_scim_unknown_paths_and_methods_are_redacted(self):
        client = self.scim(lambda request: httpx.Response(200))
        client.client.request(SECRET, SECRET, params={"secret": SECRET})
        client.client.get("https://other.example.org/Users/" + SECRET)
        self.assertEqual(self.events[0]["method"], "OTHER")
        self.assertEqual([e["path"] for e in self.events], ["/<redacted>", "/<redacted>"])
        self.assert_safe()

    def test_scim_userinfo_untrusted_headers_and_exception_names_are_redacted(self):
        client = self.scim(lambda request: httpx.Response(
            200, headers={"content-type": SECRET, "cf-ray": SECRET, "x-request-id": SECRET}))
        client.client.get(f"https://{SECRET}:{SECRET}@example.org/{SECRET}")
        self.assertNotIn("content_type", self.events[-1])
        self.assertNotIn("cf_ray", self.events[-1])
        self.assertNotIn("upstream_request_id", self.events[-1])
        error = type(SECRET, (httpx.TransportError,), {})(SECRET)
        client = self.scim(Mock(side_effect=error))
        with self.assertRaises(httpx.TransportError):
            client.client.get("Users")
        self.assertEqual(self.events[-1]["error"], "Exception")
        self.assert_safe()

    def test_scim_streaming_response_is_not_consumed(self):
        class Stream(httpx.SyncByteStream):
            def __iter__(self):
                raise AssertionError("Logging consumed the stream")

        client = self.scim(lambda request: httpx.Response(200, stream=Stream()))
        with client.client.stream("GET", "Users") as response:
            self.assertFalse(response.is_stream_consumed)
        self.assertEqual(len(self.events), 1)
        self.assert_safe()

    def test_scim_logging_failures_do_not_change_success_or_original_error(self):
        client = self.scim(lambda request: httpx.Response(200))
        with patch("bridge.connectors.destination", side_effect=RuntimeError(SECRET)):
            self.assertEqual(client.client.get("Users").status_code, 200)
        with patch("bridge.connectors.emit", side_effect=RuntimeError(SECRET)):
            self.assertEqual(client.client.get("Users").status_code, 200)
        error = httpx.ReadTimeout(SECRET)
        client = self.scim(Mock(side_effect=error))
        with patch("bridge.connectors.upstream_metadata", side_effect=RuntimeError(SECRET)):
            with self.assertRaises(httpx.ReadTimeout) as raised:
                client.client.get("Users")
        self.assertIs(raised.exception, error)

    def test_ad_activation_disables_referrals_and_verifies_certificates(self):
        for url in ("ldaps://directory.example.org", "ldap://directory.example.org"):
            client = self.ldap(ldap_service="active_directory")
            client.settings.ldap_url = url
            client.settings.ad_enable_new_accounts = True
            connection = Mock(result={"result": 0})
            with patch("bridge.connectors.Server"), patch("bridge.connectors.Tls") as tls, \
                    patch("bridge.connectors.Connection", return_value=connection) as factory:
                client.__enter__()
            self.assertFalse(factory.call_args.kwargs["auto_referrals"])
            self.assertEqual(tls.call_args.kwargs["validate"], ssl.CERT_REQUIRED)
            self.assertEqual(factory.call_args.kwargs["auto_bind"],
                             AUTO_BIND_NO_TLS if url.startswith("ldaps") else AUTO_BIND_TLS_BEFORE_BIND)

    def test_ldap_connect_preserves_auto_bind_and_tls_validation(self):
        for url, start_tls, insecure, expected_bind, mode in [
                ("ldaps://directory.example.org", True, False, AUTO_BIND_NO_TLS, "ldaps"),
                ("ldap://directory.example.org", True, False, AUTO_BIND_TLS_BEFORE_BIND, "starttls"),
                ("ldap://directory.example.org", False, True, AUTO_BIND_NO_TLS, "plain")]:
            client = self.ldap(ldap_start_tls=start_tls, ldap_allow_insecure=insecure)
            client.settings.ldap_url = url
            connection = Mock(result={"result": 0})
            with patch("bridge.connectors.Server") as server, \
                    patch("bridge.connectors.Tls") as tls, \
                    patch("bridge.connectors.Connection", return_value=connection) as factory:
                self.assertIs(client.__enter__(), client)
            self.assertEqual(factory.call_args.kwargs["auto_bind"], expected_bind)
            self.assertTrue(factory.call_args.kwargs["raise_exceptions"])
            self.assertEqual(factory.call_args.kwargs["password"], SECRET)
            self.assertEqual(tls.call_args.kwargs["validate"], ssl.CERT_REQUIRED)
            self.assertEqual(server.call_args.kwargs["use_ssl"], mode == "ldaps")
            self.assertTrue(factory.call_args.kwargs["auto_referrals"])
            self.assertEqual(self.events[-1]["tls_mode"], mode)
            self.assertEqual(self.events[-1]["operation"],
                             "connect_starttls_bind" if mode == "starttls" else "connect_bind")
        self.assert_safe()

    def test_ldap_bind_failure_logs_only_safe_numeric_exception_result(self):
        for code in (49, SECRET, True, {"result": SECRET}):
            client = self.ldap()
            client.connection = None
            error = RuntimeError(SECRET)
            error.result = code
            with patch("bridge.connectors.Server"), \
                    patch("bridge.connectors.Connection", side_effect=error):
                with self.assertRaises(RuntimeError) as raised:
                    client.__enter__()
            self.assertIs(raised.exception, error)
            if type(code) is int:
                self.assertEqual(self.events[-1]["ldap_result"], 49)
                self.assertEqual(self.events[-1]["result"], "unauthorized")
            else:
                self.assertNotIn("ldap_result", self.events[-1])
        self.assert_safe()

    def test_ldap_connect_failure_and_insecure_rejection(self):
        client = self.ldap()
        error = OSError(SECRET)
        with patch("bridge.connectors.Server"), \
                patch("bridge.connectors.Connection", side_effect=error):
            with self.assertRaises(OSError) as raised:
                client.__enter__()
        self.assertIs(raised.exception, error)
        self.assertEqual(self.events[-1]["result"], "error")
        client.settings.ldap_start_tls = False
        with patch("bridge.connectors.Connection") as factory, self.assertRaises(ValueError):
            client.__enter__()
        factory.assert_not_called()
        self.assert_safe()

    def test_ldap_search_consumes_generator_and_logs_counts(self):
        for method in ("users", "discovery"):
            client = self.ldap()
            client.connection.extend.standard.paged_search.return_value = iter(self.entries())
            result = getattr(client, method)()
            self.assertEqual(result["users"] if method == "discovery" else len(result), 1)
            self.assertEqual(self.events[-1]["count"], 1)
            self.assertEqual(self.events[-1]["ldap_result"], 0)
            self.assertEqual(self.events[-1]["result"], "success")
        self.assert_safe()

    def test_ldap_lazy_search_error_is_logged_after_partial_consumption(self):
        for method in ("users", "discovery"):
            error = RuntimeError(SECRET)

            def entries():
                yield self.entries()[1]
                raise error

            client = self.ldap()
            client.connection.extend.standard.paged_search.return_value = entries()
            with self.assertRaises(RuntimeError) as raised:
                getattr(client, method)()
            self.assertIs(raised.exception, error)
            self.assertEqual(self.events[-1]["count"], 1)
            self.assertEqual(self.events[-1]["result"], "error")
        self.assert_safe()

    def test_ldap_nonzero_search_result_preserves_failure(self):
        for method in ("users", "discovery"):
            client = self.ldap()
            client.connection.result = {"result": 50, "message": SECRET}
            client.connection.extend.standard.paged_search.return_value = iter([])
            with self.assertRaises(ValueError):
                getattr(client, method)()
            self.assertEqual(self.events[-1]["ldap_result"], 50)
            self.assertEqual(self.events[-1]["result"], "forbidden")
        self.assert_safe()

    def test_ldap_add_modify_unbind_and_failures(self):
        user = from_scim({"userName": SECRET, "name": {"familyName": SECRET}})
        client = self.ldap()
        client.write(user)
        client.write(user, {"_dn": SECRET})
        client.__exit__(None, None, None)
        self.assertEqual([e["operation"] for e in self.events], ["add", "modify", "unbind"])
        for operation in ("add", "modify", "unbind"):
            error = RuntimeError(SECRET)
            getattr(client.connection, operation).side_effect = error
            with self.subTest(operation=operation), self.assertRaises(RuntimeError) as raised:
                if operation == "unbind":
                    client.__exit__(None, None, None)
                else:
                    client.write(user, {"_dn": SECRET} if operation == "modify" else None)
            self.assertIs(raised.exception, error)
            self.assertEqual(self.events[-1]["operation"], operation)
            self.assertEqual(self.events[-1]["result"], "error")
        self.assert_safe()

    def test_ldap_false_write_result_is_logged_without_changing_behavior(self):
        client = self.ldap()
        client.connection.add.return_value = False
        client.connection.result = {"result": 49, "description": SECRET}
        self.assertIsNone(client.write(from_scim({"userName": SECRET,
                                                "name": {"familyName": SECRET}})))
        self.assertEqual(self.events[-1]["result"], "unauthorized")
        self.assertEqual(self.events[-1]["ldap_result"], 49)
        self.assert_safe()

    def test_ldap_cleanup_does_not_mask_original_exception(self):
        client = self.ldap()
        original = ValueError(SECRET)
        client.connection.unbind.side_effect = RuntimeError(SECRET)
        with patch.object(LdapClient, "__enter__", return_value=client), \
                self.assertRaises(ValueError) as raised:
            with client:
                raise original
        self.assertIs(raised.exception, original)

    def test_ldap_unbind_ignores_stale_result_from_previous_operation(self):
        client = self.ldap()
        for code in (49, 50):
            client.connection.result = {"result": code, "message": SECRET}
            client.connection.unbind.return_value = True
            client.__exit__(None, None, None)
            self.assertEqual(self.events[-1]["operation"], "unbind")
            self.assertEqual(self.events[-1]["result"], "success")
            self.assertNotIn("ldap_result", self.events[-1])
        client.connection.unbind.return_value = False
        client.__exit__(None, None, None)
        self.assertEqual(self.events[-1]["result"], "ldap_error")
        self.assertNotIn("ldap_result", self.events[-1])
        error = RuntimeError(SECRET)
        error.result = 49
        client.connection.unbind.side_effect = error
        with self.assertRaises(RuntimeError) as raised:
            client.__exit__(None, None, None)
        self.assertIs(raised.exception, error)
        self.assertEqual(self.events[-1]["result"], "error")
        self.assertNotIn("ldap_result", self.events[-1])
        self.assert_safe()

    def test_ldap_malformed_result_metadata_never_masks_operation(self):
        client = self.ldap()
        for raw in (None, SECRET, {"result": SECRET}, {"result": [SECRET]},
                    {"result": True}, {"result": 10**100}):
            client.connection.result = raw
            client._add(SECRET, [], {})
            self.assertNotIn("ldap_result", self.events[-1])
        with patch("bridge.connectors.destination", side_effect=RuntimeError(SECRET)):
            client._modify(SECRET, {})
        error = RuntimeError(SECRET)
        client.connection.modify.side_effect = error
        with patch("bridge.connectors.emit", side_effect=RuntimeError(SECRET)):
            with self.assertRaises(RuntimeError) as raised:
                client._modify(SECRET, {})
        self.assertIs(raised.exception, error)
        self.assert_safe()

    def test_ldap_result_accessor_failure_does_not_mask_operation(self):
        class BrokenResult(dict):
            def get(self, *args):
                raise RuntimeError(SECRET)

        client = self.ldap()
        client.connection.result = BrokenResult()
        client.connection.add.return_value = True
        self.assertTrue(client._add(SECRET, [], {}))
        original = ValueError(SECRET)
        client.connection.modify.side_effect = original
        with self.assertRaises(ValueError) as raised:
            client._modify(SECRET, {})
        self.assertIs(raised.exception, original)

    def test_constructor_does_not_log(self):
        client = ScimClient(Settings(scim_url="https://example.org", scim_token=SECRET))
        client.client.close()
        self.ldap()
        self.assertEqual(self.events, [])

    def test_real_json_logger_preserves_safe_metadata_and_correlation(self):
        client = self.scim(lambda request: httpx.Response(
            403, text=SECRET, headers={
                "content-type": "application/scim+json",
                "cf-ray": "0123456789abcdef-LHR",
                "x-request-id": "0123456789abcdef0123456789abcdef",
                "set-cookie": SECRET,
            }))
        ldap = self.ldap()
        ldap.connection.extend.standard.paged_search.return_value = iter(self.entries())
        token = traffic.correlation_id.set("a" * 32)
        try:
            with patch("bridge.connectors.emit", wraps=traffic.emit), \
                    self.assertLogs("bridge.traffic", level="INFO") as captured:
                client.client.get("Users", params={"filter": SECRET})
                ldap.users()
            records = [json.loads(record.getMessage()) for record in captured.records]
        finally:
            traffic.correlation_id.reset(token)
        self.assertEqual(records[0]["path"], "/Users")
        self.assertEqual(records[0]["content_type"], "application/scim+json")
        self.assertEqual(records[0]["cf_ray"], "0123456789abcdef-LHR")
        self.assertEqual(records[0]["upstream_request_id"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(records[1]["count"], 1)
        self.assertEqual(records[1]["ldap_result"], 0)
        self.assertTrue(all(record["request_id"] == "a" * 32 for record in records))
        self.assertNotIn(SECRET, json.dumps(records))


if __name__ == "__main__":
    unittest.main()
