"""Bounded, fail-closed sanitization for DEBUG directory data (never raw text)."""

import math
import re
from datetime import date, datetime
from itertools import islice


REDACTED = "<redacted>"
TRUNCATED = "<truncated>"
MAX_BYTES = 32768
MAX_DEPTH = 8
MAX_ITEMS = 50
MAX_NODES = 500
MAX_STRING = 512

SAFE_DETAILS = {
    "userName must be a nonempty string.",
    "Account status, passwords, and group provisioning are not supported by this mapping.",
    "Invalid SCIM attribute types.",
    "name.familyName is required by the inetOrgPerson schema.",
    "Invalid request parameters or body.",
    "A valid bearer token is required.",
    "Inbound SCIM provisioning is not enabled.",
    "User not found.",
    "Provide between 1 and 50 patch operations.",
    "Unsupported patch operation.",
    "Only name, displayName, and emails can be patched.",
    "userName is immutable in this mapping.",
    "userName already exists.",
    "Invalid or unsupported SCIM filter.",
    "Another directory operation is in progress; retry later.",
    "Inbound writes are blocked while dry-run mode is enabled.",
    "LDAP operation failed; check connector configuration and directory permissions.",
}


def sensitive_attribute(name):
    normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
    return any(term in normalized for term in (
        "password", "passwd", "pwd", "credential", "secret", "token",
        "privatekey", "krbprincipalkey", "authorization", "cookie",
        "encryptionkey", "apikey", "binddn", "keymaterial", "clientassertion", "cursor",
    ))


def sanitize(value):
    """Only serialize known scalar/container types; never call arbitrary repr/str."""
    remaining = MAX_NODES

    def text(item):
        if (re.search(r"(?:https?|ldaps?)://|[?&][^=\s]+=", item, re.I)
                or re.search(r"\bbearer\s|-----BEGIN .*PRIVATE KEY", item, re.I)):
            return REDACTED
        return item if len(item) <= MAX_STRING else item[:MAX_STRING] + TRUNCATED

    def visit(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            return TRUNCATED
        if item is None or type(item) in (bool, int):
            return item
        if type(item) is float:
            return item if math.isfinite(item) else "<non-finite>"
        if type(item) is str:
            return text(item)
        if type(item) in (bytes, bytearray, memoryview):
            return "<binary omitted>"
        if type(item) in (date, datetime):
            return item.isoformat()
        if type(item) is dict:
            result = {}
            # SCIM PATCH and attribute/value LDAP representations.
            selectors = [v for k, v in islice(item.items(), MAX_ITEMS)
                         if type(k) is str and k.casefold() in ("path", "attribute", "name")]
            hidden_value = len(item) > MAX_ITEMS or any(
                type(v) is str and sensitive_attribute(v) for v in selectors)
            for index, (key, val) in enumerate(item.items()):
                if index >= MAX_ITEMS or remaining <= 0:
                    result[TRUNCATED] = True
                    break
                if type(key) is not str:
                    result["<unsupported key>"] = "<omitted>"
                    continue
                safe_key = text(key)
                if (sensitive_attribute(key)
                        or (hidden_value and key.casefold() in ("value", "values"))
                        or (key.casefold() in ("detail", "message", "error_description", "error")
                            and (type(val) is not str or val not in SAFE_DETAILS))):
                    result[safe_key] = REDACTED
                else:
                    # PATCH filters can embed credentials in the path itself.
                    if key.casefold() == "path" and type(val) is str:
                        attribute = val.split("[", 1)[0]
                        val = (attribute + ("[<redacted>]" if "[" in val else "")
                               if re.fullmatch(r"[a-zA-Z0-9_.:;-]+", attribute) else REDACTED)
                    result[safe_key] = visit(val, depth + 1)
            return result
        if type(item) in (list, tuple):
            result = []
            for index, val in enumerate(item):
                if index >= MAX_ITEMS or remaining <= 0:
                    result.append(TRUNCATED)
                    break
                # Also support [attribute, value] change records.
                if index > 0 and type(item[0]) is str and sensitive_attribute(item[0]):
                    result.append(REDACTED)
                else:
                    result.append(visit(val, depth + 1))
            return result
        return "<unsupported value>"

    return visit(value)
