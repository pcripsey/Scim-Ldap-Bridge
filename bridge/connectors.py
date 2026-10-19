"""Directory transports with metadata logs and redacted DEBUG attribute events."""

import re
import ssl
import time
from functools import wraps
from urllib.parse import quote, urlparse

import httpx
from ldap3 import ALL_ATTRIBUTES, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE, Connection, Server, Tls
from ldap3.utils.dn import escape_rdn

from bridge.config import DEFAULT_ATTRIBUTE_MAPPINGS
from bridge.planner import canonical
from bridge.log_safety import MAX_ITEMS, sensitive_attribute
from bridge.self_target import CALLER_HEADER, CALLER_ID, ERROR_HEADER, SelfTargetError, check_scim_target
from bridge.traffic import (
    JsonCapture, debug_enabled, debug_event, destination, elapsed, emit, upstream_metadata,
)


MAX_USERS = 10000


def _error_type(error):
    name = type(error).__name__
    return name if name in {
        "ValueError", "TypeError", "RuntimeError", "OSError", "TimeoutError",
        "ConnectError", "ReadError", "WriteError", "RemoteProtocolError",
        "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout",
        "LDAPBindError", "LDAPSocketOpenError", "LDAPSocketReceiveError",
        "LDAPSocketSendError", "LDAPStartTLSError", "LDAPInvalidCredentialsResult",
        "LDAPInsufficientAccessRightsResult", "LDAPNoSuchObjectResult",
    } else "Exception"


def _http_result(status):
    if 200 <= status < 300:
        return "success"
    return {401: "unauthorized", 403: "forbidden", 404: "not_found",
            408: "timeout", 409: "conflict", 429: "rate_limited"}.get(
                status, "upstream_error" if status >= 500 else
                "redirect" if 300 <= status < 400 else "client_error")


class TrafficHttpClient(httpx.Client):
    def _payload(self, request, message, operation):
        if not debug_enabled():
            return
        try:
            # Only resource routes on this SCIM base; never OAuth/management URLs.
            path = request.url.raw_path.split(b"?", 1)[0]
            prefix = self.base_url.raw_path.split(b"?", 1)[0].rstrip(b"/") + b"/"
            relative = path[len(prefix):] if path.startswith(prefix) else b""
            if (request.url.scheme != self.base_url.scheme
                    or request.url.host != self.base_url.host
                    or request.url.port != self.base_url.port
                    or not relative
                    or relative.count(b"/") > 1
                    or relative.split(b"/", 1)[0].lower() not in {b"users", b"groups"}):
                return
            capture = JsonCapture(message.headers.get("content-type", ""))
            try:
                capture.add(message.content)
                data = capture.data()
            except (httpx.RequestNotRead, httpx.ResponseNotRead):
                data = {"capture": "stream_not_read"}
            debug_event("outbound", "scim", operation, data)
        except Exception:
            pass

    def _record(self, request, started, response=None, error=None):
        try:
            path = request.url.raw_path.split(b"?", 1)[0]
            prefix = self.base_url.raw_path.split(b"?", 1)[0].rstrip(b"/") + b"/"
            relative = path[len(prefix):] if path.startswith(prefix) else b""
            route = ("/" + relative.decode("ascii") if relative in {
                b"Users", b"Schemas", b"ResourceTypes", b"users", b"schemas", b"resourcetypes"}
                     else "/Users/{id}" if relative.startswith(b"Users/") and relative[6:]
                     and b"/" not in relative[6:] else "/<redacted>")
            method = request.method if request.method in {
                "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
            } else "OTHER"
            metadata = {**destination(str(request.url)), "method": method, "path": route}
            if error is not None:
                metadata["error"] = _error_type(error)
                result = "timeout" if isinstance(error, httpx.TimeoutException) else "transport_error"
            else:
                metadata["status"] = response.status_code
                metadata.update(upstream_metadata(response.headers))
                result = _http_result(response.status_code)
            emit("outbound", "scim", "request", result, elapsed(started), **metadata)
        except Exception:
            pass

    def send(self, request, *args, **kwargs):
        request.headers[CALLER_HEADER] = CALLER_ID
        started = time.perf_counter()
        self._payload(request, request, "request_payload")
        try:
            response = super().send(request, *args, **kwargs)
        except Exception as error:
            self._record(request, started, error=error)
            raise
        self._record(request, started, response=response)
        self._payload(request, response, "response_payload")
        if response.headers.get(ERROR_HEADER) == "self_target":
            response.close()
            raise SelfTargetError()
        return response


def _ldap_operation(operation):
    def decorate(function):
        @wraps(function)
        def logged(self, *args, **kwargs):
            started = time.perf_counter()
            if operation == "search":
                self._traffic_entry_count = 0
            try:
                result = function(self, *args, **kwargs)
            except Exception as error:
                self._record(operation, started, error=error)
                raise
            self._record(operation, started, failed=result is False)
            return result
        return logged
    return decorate


def index_users(users):
    indexed = {}
    folded = set()
    for user in users:
        username = user["userName"]
        if not username or username.casefold() in folded:
            raise ValueError("Missing or duplicate usernames; reconciliation stopped.")
        folded.add(username.casefold())
        indexed[username] = user
    return indexed


def mapping_parts(path):
    if path.startswith("urn:") and ":" in path:
        schema, attribute = path.rsplit(":", 1)
        return (schema, *attribute.split("."))
    return tuple(path.split("."))


def scim_value(resource, path):
    if path == "emails.value":
        emails = resource.get("emails") or []
        selected = next((item for item in emails if item.get("primary")), emails[0] if emails else {})
        return selected.get("value", "")
    value = resource
    for part in mapping_parts(path):
        if not isinstance(value, dict):
            return ""
        value = value.get(part)
    return value if value is not None else ""


def assign_mapping(user, path, value):
    field = {"userName": "userName", "name.givenName": "givenName",
             "name.familyName": "familyName", "displayName": "displayName",
             "emails.value": "email"}.get(path)
    if field:
        if isinstance(value, list):
            value = value[0] if value else ""
        user[field] = str(value or "")
    else:
        if isinstance(value, list):
            if len(value) > 1:
                raise ValueError(f"Multi-valued SCIM attribute '{path}' requires a dedicated mapping.")
            value = value[0] if value else ""
        user.setdefault("_mapped", {})[path] = value


def mapped_value(user, path):
    field = {"userName": "userName", "name.givenName": "givenName",
             "name.familyName": "familyName", "displayName": "displayName",
             "emails.value": "email"}.get(path)
    return user.get(field, "") if field else user.get("_mapped", {}).get(path, "")


def set_scim_value(document, path, value):
    if path == "emails.value":
        emails = document.setdefault("emails", [])
        selected = next((item for item in emails if item.get("primary")), emails[0] if emails else None)
        if value in (None, ""):
            if selected:
                emails.remove(selected)
        elif selected:
            selected["value"] = value
        else:
            emails.append({"value": value, "type": "work", "primary": True})
        return
    parts = mapping_parts(path)
    target = document
    parents = []
    for part in parts[:-1]:
        parents.append((target, part))
        if value in (None, "") and part not in target:
            return
        target = target.setdefault(part, {})
    if value in (None, ""):
        target.pop(parts[-1], None)
        for parent, key in reversed(parents):
            if isinstance(parent.get(key), dict) and not parent[key]:
                del parent[key]
            else:
                break
    else:
        target[parts[-1]] = value


def from_scim(resource, mappings=None):
    user = canonical({})
    for mapping in mappings or DEFAULT_ATTRIBUTE_MAPPINGS:
        assign_mapping(user, mapping.scim_path if hasattr(mapping, "scim_path") else mapping["scim_path"],
                      scim_value(resource, mapping.scim_path if hasattr(mapping, "scim_path") else mapping["scim_path"]))
    return {**user, "_id": resource.get("id"), "_raw": resource}


CORE_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
# LdapClient.write derives the required sn and default cn from these values in any mapping direction.
WRITER_DERIVED_PATHS = ("name.familyName", "displayName")
PATCH_PATH = re.compile(r"(?:urn:[A-Za-z0-9._:-]+:)?[A-Za-z][A-Za-z0-9_$-]*"
                        r"(?:\[[^\[\]]+\])?(?:\.[A-Za-z][A-Za-z0-9_$-]*)?")


def inbound_paths(mappings):
    """SCIM paths that inbound provisioning can apply to LDAP."""
    return [mapping.scim_path for mapping in mappings
            if mapping.direction != "ldap_to_scim" or mapping.scim_path in WRITER_DERIVED_PATHS]


def filter_inbound(document, mappings):
    """Return only the inbound-mapped attributes of a SCIM User document.

    Malformed values on retained paths are copied unchanged so normal type validation still applies.
    """
    filtered = {}
    for path in inbound_paths(mappings):
        if path == "emails.value":
            if "emails" in document:
                emails = document["emails"]
                filtered["emails"] = ([{key: value for key, value in item.items() if key in ("value", "primary")}
                                       if isinstance(item, dict) else item for item in emails]
                                      if isinstance(emails, list) else emails)
            continue
        *parents, leaf = mapping_parts(path)
        source = document
        for part in parents:
            source = source.get(part) if isinstance(source, dict) else None
        if isinstance(source, dict) and leaf in source:
            target = filtered
            for part in parents:
                if not isinstance(target.get(part), dict):
                    target[part] = {}
                target = target[part]
            target[leaf] = source[leaf]
    schemas = document.get("schemas")
    if isinstance(schemas, list):
        filtered["schemas"] = [schema for schema in schemas
                               if schema == CORE_USER_SCHEMA or (isinstance(schema, str) and schema in filtered)]
    return filtered


def _path_parts(path):
    parts = mapping_parts(re.sub(r"\[[^\[\]]*\]", "", path))
    if parts[0].casefold() == CORE_USER_SCHEMA.casefold():
        parts = parts[1:]
    return tuple(part.casefold() for part in parts)


def inbound_patch_target(path, mappings):
    """Whether a PATCH path may address an inbound-mapped attribute.

    Malformed paths are treated as targets so that they are rejected rather than ignored.
    """
    if not isinstance(path, str) or not PATCH_PATH.fullmatch(path) or path.casefold() == CORE_USER_SCHEMA.casefold():
        return True
    target = _path_parts(path)
    for mapped in inbound_paths(mappings):
        if mapped.startswith("urn:") and path.casefold() == mapping_parts(mapped)[0].casefold():
            return True
        parts = _path_parts(mapped)
        shorter = min(len(target), len(parts))
        if target[:shorter] == parts[:shorter]:
            return True
    return False


def scim_document(user, existing=None, mappings=None):
    document = dict(existing or {})
    document["schemas"] = list(dict.fromkeys([
        *(document.get("schemas") or []), "urn:ietf:params:scim:schemas:core:2.0:User",
    ]))
    for mapping in mappings or DEFAULT_ATTRIBUTE_MAPPINGS:
        path = mapping.scim_path if hasattr(mapping, "scim_path") else mapping["scim_path"]
        direction = mapping.direction if hasattr(mapping, "direction") else mapping.get("direction", "both")
        if direction in ("both", "ldap_to_scim"):
            set_scim_value(document, path, mapped_value(user, path))
            if path.startswith("urn:"):
                schema = mapping_parts(path)[0]
                if schema in document and schema not in document["schemas"]:
                    document["schemas"].append(schema)
                elif schema not in document and schema in document["schemas"]:
                    document["schemas"].remove(schema)
    return document


class ScimClient:
    def __init__(self, settings):
        self.entra = None
        if settings.scim_provider == "entra":
            from bridge.entra import EntraScimClient

            self.entra = EntraScimClient(settings)
            return
        if not settings.scim_url or not settings.scim_token:
            raise ValueError("SCIM endpoint and bearer token are required.")
        check_scim_target(settings.scim_url)
        self.settings = settings
        self.discovered_attributes = {}
        self.client = TrafficHttpClient(base_url=settings.scim_url.rstrip("/") + "/", timeout=30,
                                   headers={"Authorization": f"Bearer {settings.scim_token}",
                                            "Accept": "application/scim+json",
                                            "Content-Type": "application/scim+json"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.entra:
            self.entra.close()
        else:
            self.client.close()

    def users(self):
        if self.entra:
            return self.entra.users()
        users = []
        start = 1
        while True:
            response = self.client.get("Users", params={"startIndex": start, "count": 200})
            response.raise_for_status()
            page = response.json()
            resources = page.get("Resources", [])
            if not isinstance(resources, list):
                raise ValueError("Invalid SCIM list response.")
            for resource in resources:
                collect_attribute_samples(resource, self.discovered_attributes)
                users.append(from_scim(resource, self.settings.attribute_mappings))
            if len(users) > MAX_USERS:
                raise ValueError("Directory exceeds the configured safety limit.")
            start += len(resources)
            total = page.get("totalResults")
            if total is not None and len(users) >= total:
                break
            if not resources:
                if total is not None and len(users) < total:
                    raise ValueError("Incomplete SCIM pagination; reconciliation stopped.")
                break
        return index_users(users)

    def discovery(self):
        if self.entra:
            return self.entra.discovery()
        response = self.client.get("Schemas")
        response.raise_for_status()
        schemas = response.json().get("Resources", [])
        resource_response = self.client.get("ResourceTypes")
        resource_response.raise_for_status()
        resource_types = resource_response.json().get("Resources", [])
        response = self.client.get("Users", params={"startIndex": 1, "count": 10})
        response.raise_for_status()
        page = response.json()
        resources = page.get("Resources", [])
        if not isinstance(resources, list):
            raise ValueError("Invalid SCIM list response.")
        for resource in resources:
            collect_attribute_samples(resource, self.discovered_attributes)
        details = schema_attribute_details(schemas)
        names = set(details) | set(self.discovered_attributes)
        return {"schemas": schemas, "resource_types": resource_types, "attributes": [
            {"name": name, **details.get(name, {}), "samples": self.discovered_attributes.get(name, [])[:3]}
            for name in sorted(names)
        ], "users": page.get("totalResults", len(resources))}

    def write(self, user, existing=None):
        if self.entra:
            return self.entra.write(user, existing)
        document = scim_document(user, existing.get("_raw") if existing else None,
                                 self.settings.attribute_mappings)
        if existing:
            if not existing.get("_id"):
                raise ValueError("SCIM user has no stable identifier.")
            operations = []
            for mapping in self.settings.attribute_mappings:
                if mapping.direction not in ("both", "ldap_to_scim"):
                    continue
                path = mapping.scim_path
                if path == "userName":
                    continue
                patch_path = "emails" if path == "emails.value" else path
                if any(operation["path"] == patch_path for operation in operations):
                    continue
                value = document.get("emails", []) if path == "emails.value" else scim_value(document, path)
                if value in (None, "") or (patch_path == "emails" and not value):
                    operations.append({"op": "remove", "path": patch_path})
                else:
                    operations.append({"op": "replace", "path": patch_path, "value": value})
            response = self.client.patch("Users/" + quote(str(existing["_id"]), safe=""),
                                         json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                               "Operations": operations},
                                         headers={"If-Match": existing["_raw"].get("meta", {}).get("version", "*")})
        else:
            response = self.client.post("Users", json=document)
        response.raise_for_status()


class LdapClient:
    def __init__(self, settings):
        if not all((settings.ldap_url, settings.ldap_bind_dn, settings.ldap_password, settings.ldap_base_dn)):
            raise ValueError("LDAP endpoint, bind credentials, and user base DN are required.")
        self.settings = settings
        self.connection = None
        self.discovered_attributes = {}

    def _record(self, operation, started, error=None, failed=False):
        try:
            secure = urlparse(self.settings.ldap_url).scheme == "ldaps"
            metadata = {
                **destination(self.settings.ldap_url, default_port=636 if secure else 389),
                "tls_mode": "ldaps" if secure else "starttls" if self.settings.ldap_start_tls else "plain",
            }
            if operation == "connect_starttls_bind" and metadata["tls_mode"] != "starttls":
                operation = "connect_bind"
            if operation == "search":
                metadata["count"] = self._traffic_entry_count
            result = "success"
            code = None
            if self.connection is not None and operation != "unbind":
                raw = self.connection.result
                code = raw.get("result") if isinstance(raw, dict) else None
            if error is not None and operation != "unbind":
                try:
                    error_code = getattr(error, "result", None)
                    if type(error_code) is int and 0 <= error_code <= 4096:
                        code = error_code
                except Exception:
                    pass
            if type(code) is int and 0 <= code <= 4096:
                metadata["ldap_result"] = code
                if code:
                    result = {32: "not_found", 49: "unauthorized", 50: "forbidden",
                              51: "unavailable", 52: "unavailable"}.get(code, "ldap_error")
            if error is not None:
                metadata["error"] = _error_type(error)
                if result == "success":
                    result = "error"
            elif failed and result == "success":
                result = "ldap_error"
            emit("outbound", "ldap", operation, result, elapsed(started), **metadata)
        except Exception:
            pass

    @_ldap_operation("connect_starttls_bind")
    def __enter__(self):
        parsed = urlparse(self.settings.ldap_url)
        secure = parsed.scheme == "ldaps"
        start_tls = not secure and self.settings.ldap_start_tls
        if not secure and not start_tls and not self.settings.ldap_allow_insecure:
            raise ValueError("Unencrypted LDAP is not allowed by the current configuration.")
        server = Server(parsed.hostname, port=parsed.port or (636 if secure else 389), use_ssl=secure,
                        tls=Tls(validate=ssl.CERT_REQUIRED), connect_timeout=10)
        self.connection = Connection(server, user=self.settings.ldap_bind_dn,
                                     password=self.settings.ldap_password, raise_exceptions=True,
                                     receive_timeout=30,
                                     auto_bind=AUTO_BIND_TLS_BEFORE_BIND if start_tls else AUTO_BIND_NO_TLS)
        return self

    def __exit__(self, *args):
        if self.connection:
            try:
                self._unbind()
            except Exception:
                if not args or args[0] is None:
                    raise

    @_ldap_operation("unbind")
    def _unbind(self):
        return self.connection.unbind()

    @_ldap_operation("search")
    def users(self):
        users = []
        self._search_payload()
        entries = self.connection.extend.standard.paged_search(
            self.settings.ldap_base_dn, self.settings.ldap_user_filter, attributes=ALL_ATTRIBUTES,
            paged_size=200, generator=True)
        for entry in entries:
            if entry["type"] != "searchResEntry":
                continue
            self._traffic_entry_count += 1
            self._entry_payload(entry)
            attrs = entry["attributes"]
            for name, value in attrs.items():
                if not sensitive_attribute(name):
                    samples = value if isinstance(value, list) else [value]
                    bucket = self.discovered_attributes.setdefault(name, [])
                    for sample in samples:
                        sample = str(sample)
                        if sample and sample not in bucket and len(bucket) < 3:
                            bucket.append(sample)
            user = canonical({})
            for mapping in self.settings.attribute_mappings:
                attribute = mapping.ldap_attribute
                found = next((value for name, value in attrs.items() if name.casefold() == attribute.casefold()), "")
                if isinstance(found, list):
                    if mapping.scim_path != "emails.value" and len(found) > 1:
                        raise ValueError(f"Multi-valued LDAP attribute '{attribute}' requires a dedicated mapping.")
                    found = [str(value) for value in found]
                else:
                    found = str(found or "")
                assign_mapping(user, mapping.scim_path, found)
            if not user.get("displayName"):
                user["displayName"] = user.get("userName", "")
            users.append({**user, "_dn": entry["dn"]})
            if len(users) > MAX_USERS:
                raise ValueError("Directory exceeds the configured safety limit.")
        if self.connection.result.get("result", 0) != 0:
            raise ValueError("Incomplete LDAP search; reconciliation stopped.")
        return index_users(users)

    @_ldap_operation("search")
    def discovery(self):
        self._search_payload()
        entries = self.connection.extend.standard.paged_search(
            self.settings.ldap_base_dn, self.settings.ldap_user_filter, attributes=ALL_ATTRIBUTES,
            paged_size=200, generator=True)
        count = 0
        for entry in entries:
            if entry["type"] != "searchResEntry":
                continue
            self._traffic_entry_count += 1
            self._entry_payload(entry)
            count += 1
            for name, value in entry["attributes"].items():
                if not sensitive_attribute(name):
                    values = value if isinstance(value, list) else [value]
                    bucket = self.discovered_attributes.setdefault(name, [])
                    for sample in values:
                        sample = str(sample)
                        if sample and sample not in bucket and len(bucket) < 3:
                            bucket.append(sample)
        if self.connection.result.get("result", 0) != 0:
            raise ValueError("Incomplete LDAP discovery search.")
        return {"schemas": [], "resource_types": [], "attributes": [
            {"name": name, "type": "unknown", "multi_valued": None, "samples": values}
            for name, values in sorted(self.discovered_attributes.items())
        ], "users": count}

    def write(self, user, existing=None):
        if not user["familyName"]:
            raise ValueError("The bridge requires a nonempty familyName (sn).")
        attrs = {}
        for mapping in self.settings.attribute_mappings:
            if mapping.direction not in ("both", "scim_to_ldap"):
                continue
            value = mapped_value(user, mapping.scim_path)
            if value not in (None, ""):
                attrs[mapping.ldap_attribute] = value if isinstance(value, list) else [str(value)]
            elif existing:
                attrs[mapping.ldap_attribute] = []
        username = user["userName"]
        active_directory = self.settings.ldap_service == "active_directory"
        if not active_directory:
            attrs.setdefault("cn", [user["displayName"] or username])
        attrs.setdefault("sn", [user["familyName"]])
        if existing:
            changes = {field: [(MODIFY_REPLACE, value)] for field, value in attrs.items()}
            self._modify(existing["_dn"], changes)
        else:
            username_attribute = next(mapping.ldap_attribute for mapping in self.settings.attribute_mappings
                                      if mapping.scim_path == "userName")
            rdn_attribute = "cn" if active_directory else username_attribute
            if active_directory:
                attrs["cn"] = [username]
                attrs["userAccountControl"] = ["514"]
            dn = f"{rdn_attribute}={escape_rdn(username)},{self.settings.ldap_base_dn}"
            self._add(dn, ["top", "person", "organizationalPerson",
                           "user" if active_directory else "inetOrgPerson"],
                      {**attrs, username_attribute: [username]})

    @_ldap_operation("modify")
    def _modify(self, *args):
        if debug_enabled():
            debug_event("outbound", "ldap", "modify_attributes",
                        {"dn": args[0], "changes": args[1]})
        return self.connection.modify(*args)

    @_ldap_operation("add")
    def _add(self, *args):
        if debug_enabled():
            debug_event("outbound", "ldap", "add_attributes",
                        {"dn": args[0], "object_classes": args[1], "attributes": args[2]})
        return self.connection.add(*args)

    def _search_payload(self):
        if debug_enabled():
            debug_event("outbound", "ldap", "search_request",
                        {"base_dn": self.settings.ldap_base_dn,
                         "filter": self.settings.ldap_user_filter, "attributes": ALL_ATTRIBUTES})

    def _entry_payload(self, entry):
        if debug_enabled():
            if self._traffic_entry_count <= MAX_ITEMS:
                debug_event("outbound", "ldap", "search_entry",
                            {"dn": entry.get("dn"), "attributes": entry.get("attributes")})
            elif self._traffic_entry_count == MAX_ITEMS + 1:
                debug_event("outbound", "ldap", "search_entry", {"truncated": True})


def collect_attribute_samples(value, samples, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            if (sensitive_attribute(key)
                    or key.casefold() in {"id", "meta", "schemas", "groups", "active"}):
                continue
            if not prefix:
                path = key
            elif prefix.startswith("urn:") and prefix.rsplit(":", 1)[-1] in ("User", "Group"):
                path = f"{prefix}:{key}"
            else:
                path = f"{prefix}.{key}"
            collect_attribute_samples(item, samples, path)
    elif isinstance(value, list):
        for item in value:
            collect_attribute_samples(item, samples, prefix)
    elif prefix:
        bucket = samples.setdefault(prefix, [])
        text = str(value)
        if text and text not in bucket and len(bucket) < 3:
            bucket.append(text)


def schema_attribute_details(schemas):
    details = {}

    def visit(schema_id, attributes, parent="", parent_multi=False):
        for attribute in attributes or []:
            name = attribute.get("name")
            if (not name or str(attribute.get("mutability", "")).casefold() in ("readonly", "immutable")
                    or attribute.get("returned") == "never"
                    or name.casefold() in {"id", "meta", "schemas", "groups", "active"}
                    or sensitive_attribute(name)):
                continue
            prefix = f"{parent}.{name}" if parent else (
                f"{schema_id}:{name}" if schema_id.startswith("urn:") and schema_id != "urn:ietf:params:scim:schemas:core:2.0:User" else name)
            multi = parent_multi or bool(attribute.get("multiValued", False))
            if attribute.get("type") != "complex":
                details[prefix] = {"type": attribute.get("type", "unknown"), "multi_valued": multi}
            visit(schema_id, attribute.get("subAttributes"), prefix, multi)

    for schema in schemas:
        if isinstance(schema, dict):
            visit(schema.get("id", ""), schema.get("attributes", []))
    return details