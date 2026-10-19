"""Metadata-only traffic logging. Never pass payloads or exception messages here."""

import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from urllib.parse import urlsplit

from bridge.self_target import ERROR_HEADER


correlation_id = ContextVar("traffic_correlation_id", default="")
logger = logging.getLogger("bridge.traffic")
_lock = threading.Lock()
_fields = {
    "method", "path", "status", "scheme", "host", "port", "tls_mode",
    "error", "count", "ldap_result", "content_type", "cf_ray",
    "upstream_request_id", "parent_id", "reason",
}


def new_id():
    return uuid.uuid4().hex


def elapsed(start):
    return round((time.perf_counter() - start) * 1000, 3)


def destination(url, default_port=None):
    try:
        parsed = urlsplit(str(url))
        host = parsed.hostname or ""
        return {
            "scheme": parsed.scheme if parsed.scheme in {"http", "https", "ldap", "ldaps"} else "other",
            "host": host if len(host) <= 253 and re.fullmatch(r"[a-zA-Z0-9.:\-]+", host) else "<redacted>",
            "port": parsed.port or default_port or (443 if parsed.scheme == "https" else 80),
        }
    except Exception:
        return {"scheme": "other", "host": "<redacted>", "port": default_port}


def upstream_metadata(headers):
    metadata = {}
    try:
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type in {"application/json", "application/scim+json", "text/html", "text/plain"}:
            metadata["content_type"] = content_type
        ray = headers.get("cf-ray", "")
        if re.fullmatch(r"[a-fA-F0-9]{16}-[a-zA-Z]{3}", ray):
            metadata["cf_ray"] = ray
        request_id = headers.get("x-request-id", "")
        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", request_id):
            metadata["upstream_request_id"] = request_id
        reason = headers.get(ERROR_HEADER.lower(), "")
        if reason in {"self_target", "directory_busy", "dry_run", "uniqueness"}:
            metadata["reason"] = reason
    except Exception:
        pass
    return metadata


class SafeServerErrors(logging.Filter):
    def filter(self, record):
        if record.exc_info:
            record.msg = "Application/server exception (%s); see correlated traffic log."
            record.args = (type(record.exc_info[1]).__name__,)
            record.exc_info = None
            record.exc_text = None
        return True


def configure_logging():
    with _lock:
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
        logger.propagate = False
        level = os.environ.get("BRIDGE_LOG_LEVEL", "INFO").upper()
        logger.setLevel({"DEBUG": logging.DEBUG, "INFO": logging.INFO,
                         "WARNING": logging.WARNING, "ERROR": logging.ERROR,
                         "OFF": logging.CRITICAL + 1}.get(level, logging.INFO))
        # These default loggers include full URLs, queries or exception text.
        for name in ("httpx", "httpcore", "ldap3", "uvicorn.access"):
            logging.getLogger(name).disabled = True
            logging.getLogger(name).setLevel(logging.CRITICAL + 1)
        server = logging.getLogger("uvicorn.error")
        if not any(isinstance(item, SafeServerErrors) for item in server.filters):
            server.addFilter(SafeServerErrors())


def emit(direction, protocol, operation, result, duration_ms, **metadata):
    try:
        status = metadata.get("status", 0)
        failed = result not in {"success", "completed"}
        level = logging.ERROR if result == "exception" or (isinstance(status, int) and status >= 500) else (
            logging.WARNING if failed else logging.INFO)
        if (direction == "inbound" and not failed
                and metadata.get("path") in {"/healthz", "/api/status"}
                and os.environ.get("BRIDGE_LOG_POLLS", "false").lower() != "true"):
            level = logging.DEBUG
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": logging.getLevelName(level), "direction": direction,
            "protocol": protocol, "operation": operation, "result": result,
            "duration_ms": duration_ms, "request_id": correlation_id.get() or new_id(),
        }
        record.update({key: value for key, value in metadata.items() if key in _fields})
        logger.log(level, json.dumps(record, ensure_ascii=True, separators=(",", ":")))
    except Exception:
        # A broken log sink must not affect traffic or replace its exception.
        pass


class TrafficMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = new_id()
        scope["traffic_request_id"] = request_id
        token = correlation_id.set(request_id)
        start = time.perf_counter()
        status = 500
        error = None
        reason = None

        async def response_send(message):
            nonlocal status, reason
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"] = [
                    (key, value) for key, value in message.get("headers", [])
                    if key.lower() != b"x-request-id"
                ] + [(b"x-request-id", request_id.encode("ascii"))]
                reason = upstream_metadata({
                    key.decode("latin-1"): value.decode("latin-1")
                    for key, value in message["headers"]
                }).get("reason")
            await send(message)

        try:
            await self.app(scope, receive, response_send)
        except BaseException as exc:
            error = type(exc).__name__
            raise
        finally:
            try:
                route = scope.get("route")
                path = getattr(route, "path", "/<unmatched>")
                # Mount paths can include arbitrary filenames; never record them.
                if not path or path.startswith("/assets"):
                    path = "/assets/{path}"
                method = scope.get("method", "")
                method = method if method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} else "OTHER"
                metadata = {"method": method, "path": path, "status": status}
                if reason:
                    metadata["reason"] = reason
                if error:
                    metadata["error"] = error
                for key, value in scope.get("headers", []):
                    if key == b"cf-ray":
                        safe = upstream_metadata({"cf-ray": value.decode("ascii", errors="ignore")})
                        metadata.update(safe)
                        break
                emit("inbound", "http", "request",
                     "exception" if error else "success" if status < 400 else "http_error",
                     elapsed(start), **metadata)
            except Exception:
                pass
            finally:
                correlation_id.reset(token)
