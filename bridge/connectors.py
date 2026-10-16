import ssl
from urllib.parse import quote, urlparse

import httpx
from ldap3 import ALL_ATTRIBUTES, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE, Connection, Server, Tls
from ldap3.utils.dn import escape_rdn

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


def from_scim(resource):
    name = resource.get("name") or {}
    emails = resource.get("emails") or []
    email = next((item for item in emails if item.get("primary")), emails[0] if emails else {})
    return {**canonical({"userName": resource.get("userName"), "givenName": name.get("givenName"),
                         "familyName": name.get("familyName"), "displayName": resource.get("displayName"),
                         "email": email.get("value")}), "_id": resource.get("id"), "_raw": resource}


def scim_document(user, existing=None):
    document = dict(existing or {})
    emails = [dict(item) for item in document.get("emails", [])]
    primary = next((index for index, item in enumerate(emails) if item.get("primary")), 0)
    if emails:
        if user["email"]:
            emails[primary]["value"] = user["email"]
        else:
            emails.pop(primary)
    elif user["email"]:
        emails.append({"value": user["email"], "type": "work", "primary": True})
    document.update({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                     "userName": user["userName"], "displayName": user["displayName"],
                     "name": {**document.get("name", {}), "givenName": user["givenName"],
                              "familyName": user["familyName"]}, "emails": emails})
    return document


class ScimClient:
    def __init__(self, settings):
        if not settings.scim_url or not settings.scim_token:
            raise ValueError("SCIM endpoint and bearer token are required.")
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
            users.extend(from_scim(resource) for resource in resources)
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

    def write(self, user, existing=None):
        document = scim_document(user, existing.get("_raw") if existing else None)
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

            def value(name):
                found = attrs.get(name, "")
                return str(found[0] if isinstance(found, list) and found else found or "")

            users.append({**canonical({"userName": value("uid"), "givenName": value("givenName"),
                                       "familyName": value("sn"), "displayName": value("displayName") or value("cn"),
                                       "email": value("mail")}), "_dn": entry["dn"]})
            if len(users) > MAX_USERS:
                raise ValueError("Directory exceeds the configured safety limit.")
        if self.connection.result.get("result", 0) != 0:
            raise ValueError("Incomplete LDAP search; reconciliation stopped.")
        return index_users(users)

    def write(self, user, existing=None):
        if not user["familyName"]:
            raise ValueError("inetOrgPerson requires a nonempty familyName (sn).")
        attrs = {"cn": user["displayName"] or user["userName"], "sn": user["familyName"],
                 "givenName": user["givenName"], "displayName": user["displayName"], "mail": user["email"]}
        if existing:
            changes = {field: [(MODIFY_REPLACE, [value] if value else [])] for field, value in attrs.items()}
            self.connection.modify(existing["_dn"], changes)
        else:
            dn = f"uid={escape_rdn(user['userName'])},{self.settings.ldap_base_dn}"
            self.connection.add(dn, ["top", "person", "organizationalPerson", "inetOrgPerson"],
                                {"uid": user["userName"], **{key: value for key, value in attrs.items() if value}})