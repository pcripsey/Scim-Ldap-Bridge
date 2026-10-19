import asyncio
import io
import json
import logging
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from bridge.app import create_app
from bridge.config import Settings
from bridge.connectors import TrafficHttpClient
from bridge.self_target import CALLER_HEADER, CALLER_ID, ERROR_HEADER
from bridge.service import SyncService
from bridge.traffic import (
    SafeServerErrors, TrafficMiddleware, configure_logging, correlation_id,
    destination, emit, logger, upstream_metadata,
)


ADMIN = "synthetic-admin-secret-24-characters"
SCIM = "synthetic-scim-secret-24-characters"
SECRET = "synthetic-private-person@example.invalid"


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = create_app(self.directory.name, ADMIN, SCIM)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()
        self.output = io.StringIO()
        self.handler = logging.StreamHandler(self.output)
        self.old_handlers = logger.handlers[:]
        logger.handlers = [self.handler]
        logger.setLevel(logging.INFO)

    def tearDown(self):
        self.client.__exit__(None, None, None)
        logger.handlers = self.old_handlers
        logger.setLevel(logging.INFO)
        self.directory.cleanup()

    def records(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def test_success_auth_validation_and_not_found_have_generated_ids(self):
        cases = [
            ("/scim/v2/ServiceProviderConfig", {"Authorization": "Bearer " + SCIM}, 200),
            ("/api/status", {"Authorization": "Bearer " + SCIM}, 401),
            ("/scim/v2/Users?count=not-an-integer", {"Authorization": "Bearer " + SCIM}, 400),
            ("/scim/v2/Users/" + SECRET, {}, 401),
            ("/unknown/" + SECRET + "%0Aforged?filter=" + SECRET, {}, 404),
        ]
        for path, headers, expected in cases:
            response = self.client.get(path, headers={
                **headers, "X-Request-ID": SECRET, "Cookie": SECRET,
                "Proxy-Authorization": SECRET, "CF-Ray": "0123456789abcdef-AMS",
                "X-Forwarded-For": SECRET,
            })
            self.assertEqual(response.status_code, expected)
            record = self.records()[-1]
            self.assertEqual(record["request_id"], response.headers["x-request-id"])
            self.assertRegex(record["request_id"], r"^[a-f0-9]{32}$")
            self.assertGreaterEqual(record["duration_ms"], 0)
            self.assertIn("timestamp", record)
            self.assertEqual(record["cf_ray"], "0123456789abcdef-AMS")
        output = self.output.getvalue()
        for private in (SECRET, ADMIN, SCIM, "forged", "Authorization", "filter="):
            self.assertNotIn(private, output)
        self.assertEqual(len({item["request_id"] for item in self.records()}), len(cases))
        self.assertEqual(self.records()[-2]["path"], "/scim/v2/Users/{identifier}")
        self.assertEqual(self.records()[-1]["path"], "/<unmatched>")

    def test_disabled_scim_and_unhandled_exception_headers(self):
        self.app.state.scim_token = ""
        response = self.client.get("/scim/v2/ServiceProviderConfig")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.records()[-1]["status"], 503)
        self.assertEqual(response.headers["x-request-id"], self.records()[-1]["request_id"])
        with patch.object(self.app.state.store, "settings", side_effect=RuntimeError(SECRET)):
            response = self.client.get("/api/status", headers={"Authorization": "Bearer " + ADMIN})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.text, "Internal Server Error")
        self.assertEqual(response.headers["x-request-id"], self.records()[-1]["request_id"])
        self.assertEqual(self.records()[-1]["result"], "exception")
        self.assertNotIn(SECRET, self.output.getvalue())
        self.assertEqual(correlation_id.get(), "")

    def test_worker_thread_context_isolation(self):
        barrier = threading.Barrier(2)

        @self.app.get("/thread-probe")
        def probe():
            barrier.wait(timeout=5)
            emit("outbound", "http", "probe", "success", 1)
            return {"id": correlation_id.get()}

        def request():
            return self.client.get("/thread-probe")

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: request(), range(2)))
        ids = {response.headers["x-request-id"] for response in responses}
        self.assertEqual(len(ids), 2)
        for response in responses:
            self.assertEqual(response.json()["id"], response.headers["x-request-id"])
        outbound = [item for item in self.records() if item["direction"] == "outbound"]
        self.assertEqual({item["request_id"] for item in outbound}, ids)
        self.assertEqual(correlation_id.get(), "")

    def test_background_gets_new_id_and_restores_context(self):
        parent = "a" * 32
        token = correlation_id.set(parent)
        try:
            service = SyncService(self.app.state.store)
            captured = []

            def run(settings, run_id):
                captured.append(correlation_id.get())
                return "completed"

            with patch.object(service, "_run", side_effect=run):
                service.run(Settings(), 1, parent)
            self.assertNotEqual(captured[0], parent)
            self.assertEqual(correlation_id.get(), parent)
            self.assertEqual(self.records()[-1]["request_id"], captured[0])
            self.assertEqual(self.records()[-1]["parent_id"], parent)
        finally:
            correlation_id.reset(token)

    def test_proxy_alias_self_call_fails_before_ldap_and_keeps_correlation(self):
        settings = Settings(scim_url="https://unlisted-proxy.example/scim/v2", scim_token=SCIM)
        self.app.state.store.save_settings(settings)
        sent = []

        def forward(request):
            sent.append(request)
            response = self.client.request(request.method, "/scim/v2/Users",
                                           headers=dict(request.headers))
            return httpx.Response(response.status_code, headers=response.headers, content=response.content)

        def http_client(**kwargs):
            return TrafficHttpClient(**kwargs, transport=httpx.MockTransport(forward))

        with patch("bridge.connectors.TrafficHttpClient", side_effect=http_client), \
                patch("bridge.service.LdapClient") as worker_ldap, \
                patch("bridge.app.LdapClient") as inbound_ldap:
            run_id = self.app.state.service.trigger()
            self.app.state.service.worker.join(timeout=5)
            self.assertFalse(self.app.state.service.worker.is_alive())
            inbound_ldap.assert_not_called()
            worker_ldap.return_value.__enter__.return_value.users.assert_not_called()
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].headers[CALLER_HEADER], CALLER_ID)
        records = self.records()
        inbound = next(item for item in records if item["direction"] == "inbound")
        outbound = next(item for item in records if item["direction"] == "outbound")
        reconcile = next(item for item in records if item["operation"] == "reconcile")
        self.assertEqual(inbound["status"], 400)
        self.assertEqual(inbound["reason"], "self_target")
        self.assertEqual(outbound["reason"], "self_target")
        self.assertEqual(outbound["upstream_request_id"], inbound["request_id"])
        self.assertEqual(outbound["request_id"], reconcile["request_id"])
        self.assertEqual(reconcile["result"], "failed")
        self.assertFalse(self.app.state.service.lock.locked())
        self.assertEqual(self.app.state.store.operations(), [])
        self.assertEqual(self.app.state.store.rows("runs")[0]["id"], run_id)
        self.assertIn("remote SCIM provider", self.app.state.store.rows("events")[0]["message"])
        self.assertNotIn(CALLER_ID, self.output.getvalue())
        self.assertNotIn(SCIM, self.output.getvalue())

    def test_busy_response_correlates_when_proxy_strips_loop_marker(self):
        sent = []

        def forward(request):
            sent.append(request)
            response = self.client.get("/scim/v2/Users", headers={"Authorization": "Bearer " + SCIM})
            return httpx.Response(response.status_code, headers=response.headers, content=response.content)

        service = self.app.state.service
        service.lock.acquire()
        try:
            with TrafficHttpClient(base_url="https://proxy.example/scim/v2/",
                                   transport=httpx.MockTransport(forward)) as client:
                with self.assertRaises(httpx.HTTPStatusError):
                    client.get("Users").raise_for_status()
            self.assertTrue(service.lock.locked())
        finally:
            service.lock.release()
        inbound, outbound = self.records()
        self.assertEqual(len(sent), 1)
        self.assertEqual(inbound["status"], 409)
        self.assertEqual(inbound["reason"], "directory_busy")
        self.assertEqual(outbound["reason"], "directory_busy")
        self.assertEqual(outbound["upstream_request_id"], inbound["request_id"])

    def test_caller_header_never_grants_authentication(self):
        response = self.client.get("/scim/v2/Users", headers={CALLER_HEADER: "not-this-process"})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(ERROR_HEADER, response.headers)
        response = self.client.get("/scim/v2/Users", headers={CALLER_HEADER: CALLER_ID})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers[ERROR_HEADER], "self_target")
        self.assertNotIn(CALLER_HEADER, response.headers)

    def test_untrusted_diagnostic_headers_are_not_logged(self):
        self.assertNotIn("reason", upstream_metadata({ERROR_HEADER.lower(): SECRET}))
        self.assertNotIn("reason", upstream_metadata({ERROR_HEADER.lower(): "directory_busy\nforged"}))

    def test_planner_conflicts_have_no_http_conflict_status(self):
        service = self.app.state.service
        with patch.object(service, "_run", return_value="conflicts"):
            service.run(Settings(), 1)
        record = self.records()[-1]
        self.assertEqual(record["reason"], "planner_conflict")
        self.assertNotIn("status", record)

    def test_poll_noise_controls_never_hide_errors(self):
        self.client.get("/healthz")
        self.client.get("/api/status", headers={"Authorization": "Bearer " + ADMIN})
        self.assertEqual(self.records(), [])
        with patch.dict("os.environ", {"BRIDGE_LOG_POLLS": "true"}):
            self.client.get("/healthz")
        self.assertEqual(self.records()[-1]["path"], "/healthz")
        logger.setLevel(logging.DEBUG)
        self.client.get("/healthz")
        self.assertEqual(self.records()[-1]["level"], "DEBUG")
        self.client.get("/api/status")
        self.assertEqual(self.records()[-1]["level"], "WARNING")

    def test_logging_sink_failure_cannot_break_requests_or_mask_errors(self):
        with patch.object(logger, "log", side_effect=OSError(SECRET)):
            self.assertEqual(self.client.get("/healthz").status_code, 200)
            with patch.object(self.app.state.store, "settings", side_effect=RuntimeError(SECRET)):
                response = self.client.get("/api/status", headers={"Authorization": "Bearer " + ADMIN})
                self.assertEqual(response.status_code, 500)

    def test_safe_helpers_and_configuration(self):
        self.assertEqual(destination("https://" + "synthetic:password@" + "example.invalid:8443/private?secret=true"),
                         {"scheme": "https", "host": "example.invalid", "port": 8443})
        self.assertEqual(destination("https://host:invalid")["host"], "<redacted>")
        self.assertEqual(upstream_metadata({
            "content-type": SECRET, "cf-ray": "0123456789abcdef-AMS\nforged",
            "x-request-id": SECRET, "Authorization": SECRET,
        }), {})
        self.assertEqual(upstream_metadata({"content-type": "text/html; charset=utf-8"}),
                         {"content_type": "text/html"})
        count = len(logger.handlers)
        configure_logging()
        configure_logging()
        self.assertEqual(len(logger.handlers), count)
        with patch.dict("os.environ", {"BRIDGE_LOG_LEVEL": "OFF"}):
            configure_logging()
            emit("inbound", "http", "request", "exception", 1)
        self.assertEqual(self.records(), [])
        configure_logging()
        self.assertFalse(logging.getLogger("httpcore.connection").isEnabledFor(logging.DEBUG))

    def test_server_traceback_is_sanitized(self):
        try:
            raise RuntimeError(SECRET)
        except RuntimeError:
            import sys
            record = logging.LogRecord("uvicorn.error", logging.ERROR, "", 0,
                                       "unsafe " + SECRET, (), sys.exc_info())
        SafeServerErrors().filter(record)
        formatted = logging.Formatter().format(record)
        self.assertNotIn(SECRET, formatted)
        self.assertIn("RuntimeError", formatted)
        self.assertIsNone(record.exc_info)

    def test_streaming_is_not_consumed_by_middleware(self):
        messages = []

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"one", "more_body": True})
            self.assertEqual(len(messages), 2)
            await send({"type": "http.response.body", "body": b"two", "more_body": False})

        async def send(message):
            messages.append(message)

        asyncio.run(TrafficMiddleware(app)(
            {"type": "http", "method": "GET", "headers": []}, None, send))
        self.assertEqual(messages[1]["body"], b"one")
        self.assertEqual(messages[2]["body"], b"two")
