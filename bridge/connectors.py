import ssl
from urllib.parse import quote, urlparse

import httpx
from ldap3 import ALL_ATTRIBUTES, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE, Connection, Server, Tls
from ldap3.utils.dn import escape_rdn

from bridge.config import DEFAULT_ATTRIBUTE_MAPPINGS
from bridge.planner import canonical


MAX_USERS = 10000


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
        return schema, attribute
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
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    if value not in (None, ""):
        target[parts[-1]] = value


def from_scim(resource, mappings=None):
    user = canonical({})
    for mapping in mappings or DEFAULT_ATTRIBUTE_MAPPINGS:
        assign_mapping(user, mapping.scim_path if hasattr(mapping, "scim_path") else mapping["scim_path"],
                      scim_value(resource, mapping.scim_path if hasattr(mapping, "scim_path") else mapping["scim_path"]))
    return {**user, "_id": resource.get("id"), "_raw": resource}


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
                schema, _ = path.rsplit(":", 1)
                if schema not in document["schemas"]:
                    document["schemas"].append(schema)
    return document


class ScimClient:
    def __init__(self, settings):
        if not settings.scim_url or not settings.scim_token:
            raise ValueError("SCIM endpoint and bearer token are required.")
        self.settings = settings
        self.discovered_attributes = {}
        self.client = httpx.Client(base_url=settings.scim_url.rstrip("/") + "/", timeout=30,
                                   headers={"Authorization": f"Bearer {settings.scim_token}",
                                            "Accept": "application/scim+json",
                                            "Content-Type": "application/scim+json"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.client.close()

    def users(self):
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
        return {"schemas": schemas, "resource_types": resource_types, "attributes": [
            {"name": name, "samples": values[:3]} for name, values in sorted(self.discovered_attributes.items())
        ], "users": page.get("totalResults", len(resources))}

    def write(self, user, existing=None):
        document = scim_document(user, existing.get("_raw") if existing else None,
                                 self.settings.attribute_mappings)
        if existing:
            if not existing.get("_id"):
                raise ValueError("SCIM user has no stable identifier.")
            operations = [{"op": "replace", "path": field, "value": document[field]}
                          for field in ("displayName", "name", "emails")]
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
            self.connection.unbind()

    def users(self):
        users = []
        entries = self.connection.extend.standard.paged_search(
            self.settings.ldap_base_dn, "(objectClass=inetOrgPerson)", attributes=ALL_ATTRIBUTES,
            paged_size=200, generator=True)
        for entry in entries:
            if entry["type"] != "searchResEntry":
                continue
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

    def discovery(self):
        entries = self.connection.extend.standard.paged_search(
            self.settings.ldap_base_dn, "(objectClass=inetOrgPerson)", attributes=ALL_ATTRIBUTES,
            paged_size=200, generator=True)
        count = 0
        for entry in entries:
            if entry["type"] != "searchResEntry":
                continue
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
            {"name": name, "samples": values} for name, values in sorted(self.discovered_attributes.items())
        ], "users": count}

    def write(self, user, existing=None):
        if not user["familyName"]:
            raise ValueError("inetOrgPerson requires a nonempty familyName (sn).")
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
        attrs.setdefault("cn", [user["displayName"] or username])
        attrs.setdefault("sn", [user["familyName"]])
        if existing:
            changes = {field: [(MODIFY_REPLACE, value)] for field, value in attrs.items()}
            self.connection.modify(existing["_dn"], changes)
        else:
            username_attribute = next(mapping.ldap_attribute for mapping in self.settings.attribute_mappings
                                      if mapping.scim_path == "userName")
            dn = f"{username_attribute}={escape_rdn(username)},{self.settings.ldap_base_dn}"
            self.connection.add(dn, ["top", "person", "organizationalPerson", "inetOrgPerson"],
                                {**attrs, username_attribute: [username]})


def sensitive_attribute(name):
    normalized = name.casefold().split(";")[0]
    return any(term in normalized for term in (
        "password", "pwd", "credential", "secret", "token", "privatekey", "krbprincipalkey"))


def collect_attribute_samples(value, samples, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            if sensitive_attribute(key):
                continue
            path = f"{prefix}.{key}" if prefix else key
            collect_attribute_samples(item, samples, path)
    elif isinstance(value, list):
        for item in value:
            collect_attribute_samples(item, samples, prefix)
    elif prefix:
        bucket = samples.setdefault(prefix, [])
        text = str(value)
        if text and text not in bucket and len(bucket) < 3:
            bucket.append(text)