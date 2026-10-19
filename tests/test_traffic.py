import asyncio
import io
import json
import logging
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi.testclient import TestClient

from bridge.app import create_app
from bridge.config import Settings
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
