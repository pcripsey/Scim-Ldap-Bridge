"""Public-cloud Entra SCIM reads; OAuth credentials never use the traffic client."""

import math
import time

import httpx

from bridge.config import ENTRA_SCIM_URL, Settings
from bridge.self_target import check_scim_target


class EntraScimClient:
    def __init__(self, settings):
        # Revalidate even callers using model_copy/model_construct before sending credentials.
        self.settings = Settings.model_validate(settings.model_dump())
        if self.settings.scim_provider != "entra" or not self.settings.scim_configured:
            raise ValueError("Entra endpoint, tenant, client ID and client secret are required.")
        check_scim_target(self.settings.scim_url)
        from bridge.connectors import TrafficHttpClient

        self.client = TrafficHttpClient(
            base_url=ENTRA_SCIM_URL + "/", timeout=30, follow_redirects=False, trust_env=False,
            headers={"Accept": "application/scim+json"})
        self.token = ""
        self.renew_at = 0
        self.discovered_attributes = {}

    def close(self):
        self.token = ""
        self.renew_at = 0
        self.client.close()

    def _access_token(self):
        now = time.monotonic()
        if self.token and now < self.renew_at:
            return self.token
        self.token = ""
        self.renew_at = 0
        try:
            # Fixed authority and GUID-only tenant prevent authority/path injection.
            with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as oauth:
                response = oauth.post(
                    f"https://login.microsoftonline.com/{self.settings.entra_tenant_id}/oauth2/v2.0/token",
                    data={"grant_type": "client_credentials", "client_id": self.settings.entra_client_id,
                          "client_secret": self.settings.entra_client_secret,
                          "scope": "https://graph.microsoft.com/.default"})
                response.raise_for_status()
                body = response.json()
            token, expires = body["access_token"], body["expires_in"]
            if (not isinstance(token, str) or not token or len(token) > 32768
                    or any(not 33 <= ord(char) <= 126 for char in token)
                    or body.get("token_type", "").lower() != "bearer"
                    or isinstance(expires, bool) or not isinstance(expires, (int, float))
                    or not math.isfinite(expires) or expires <= 0):
                raise ValueError()
        except Exception:
            raise RuntimeError("Entra OAuth authentication failed; check application permissions and credentials.") from None
        self.token = token
        self.renew_at = now + expires - min(60, expires / 2)
        return token

    def _get(self, path, params=None):
        token = self._access_token()
        try:
            response = self.client.get(path, params=params,
                                       headers={"Authorization": "Bearer " + token})
            response.raise_for_status()
            body = response.json()
        except Exception as error:
            from bridge.self_target import SelfTargetError

            if isinstance(error, SelfTargetError):
                raise
            raise RuntimeError("Entra SCIM read failed; check authentication, permissions and source scope.") from None
        if not isinstance(body, dict):
            raise ValueError("Invalid Entra SCIM response.")
        return body

    def users(self):
        from bridge.connectors import MAX_USERS, collect_attribute_samples, from_scim, index_users

        users = []
        ids = set()
        cursors = set()
        cursor = None
        samples = {}
        while True:
            params = {"count": 100}
            if self.settings.scim_filter:
                params["filter"] = self.settings.scim_filter
            if cursor is not None:
                params["cursor"] = cursor
            page = self._get("users", params)
            resources = page.get("resources")
            next_cursor = page.get("nextCursor")
            if (not isinstance(resources, list) or len(resources) > 100
                    or (next_cursor is not None and
                        (not isinstance(next_cursor, str) or len(next_cursor) > 16384))):
                raise ValueError("Invalid Entra SCIM page.")
            if next_cursor and (next_cursor in cursors or not resources):
                raise ValueError("Entra cursor pagination made no progress.")
            for resource in resources:
                if (not isinstance(resource, dict)
                        or not isinstance(resource.get("id"), str) or not resource["id"].strip()
                        or resource["id"] in ids
                        or not isinstance(resource.get("userName"), str) or not resource["userName"].strip()
                        or any(ord(char) < 32 for char in resource["userName"])
                        or not isinstance(resource.get("displayName", ""), (str, type(None)))
                        or ("name" in resource and not isinstance(resource["name"], dict))
                        or any(not isinstance(resource.get("name", {}).get(key), (str, type(None)))
                               for key in ("givenName", "familyName"))
                        or ("emails" in resource and
                            (not isinstance(resource["emails"], list)
                             or any(not isinstance(item, dict)
                                    or not isinstance(item.get("value"), (str, type(None)))
                                    or not isinstance(item.get("primary", False), bool)
                                    for item in resource["emails"])))):
                    raise ValueError("Invalid or duplicate Entra user resource.")
                ids.add(resource["id"])
                collect_attribute_samples(resource, samples)
                users.append(from_scim(resource, self.settings.attribute_mappings))
            if len(users) > MAX_USERS:
                raise ValueError("Directory exceeds the configured safety limit.")
            if not next_cursor:
                break
            cursors.add(next_cursor)
            cursor = next_cursor
        indexed = index_users(users)
        self.discovered_attributes = samples
        return indexed

    def discovery(self):
        from bridge.connectors import schema_attribute_details

        schemas = self._get("schemas").get("Resources")
        resource_types = self._get("resourcetypes").get("Resources")
        if (not isinstance(schemas, list) or not isinstance(resource_types, list)
                or any(not isinstance(item, dict) for item in schemas + resource_types)):
            raise ValueError("Invalid Entra discovery response.")
        users = self.users()
        details = schema_attribute_details(schemas)
        return {"schemas": schemas, "resource_types": resource_types, "attributes": [
            {"name": name, **details.get(name, {}), "samples": self.discovered_attributes.get(name, [])[:3]}
            for name in sorted(set(details) | set(self.discovered_attributes))
        ], "users": len(users)}

    def write(self, user, existing=None):
        raise ValueError("Entra OAuth mode is pull-only; remote writes are disabled.")
