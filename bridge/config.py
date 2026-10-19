import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AttributeMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scim_path: str = Field(min_length=1, max_length=256)
    ldap_attribute: str = Field(min_length=1, max_length=128)
    direction: Literal["both", "scim_to_ldap", "ldap_to_scim"] = "both"

    @field_validator("scim_path")
    @classmethod
    def validate_scim_path(cls, value):
        attribute_path = value.rsplit(":", 1)[-1] if value.startswith("urn:") else value
        parts = re.split(r"[.:]", attribute_path.casefold())
        if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_:.-]*", value)
                or any(part in {"id", "meta", "schemas", "groups", "active"}
                       or any(term in part for term in ("password", "credential", "secret", "token", "privatekey"))
                       for part in parts)):
            raise ValueError("SCIM paths must reference writable, non-sensitive attributes.")
        return value

    @field_validator("ldap_attribute")
    @classmethod
    def validate_ldap_attribute(cls, value):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", value) or value.casefold() in {
                "userpassword", "unicodepwd", "authpassword", "supplementalcredentials",
                "ntpwdhistory", "lmpwdhistory", "krbprincipalkey"}:
            raise ValueError("LDAP attribute must be a valid, non-sensitive attribute name.")
        return value


DEFAULT_ATTRIBUTE_MAPPINGS = [
    {"scim_path": "userName", "ldap_attribute": "uid"},
    {"scim_path": "name.givenName", "ldap_attribute": "givenName"},
    {"scim_path": "name.familyName", "ldap_attribute": "sn"},
    {"scim_path": "displayName", "ldap_attribute": "displayName"},
    {"scim_path": "emails.value", "ldap_attribute": "mail"},
]


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scim_url: str = ""
    scim_token: str = ""
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_password: str = ""
    ldap_base_dn: str = ""
    attribute_mappings: list[AttributeMapping] = Field(default_factory=lambda: [
        AttributeMapping.model_validate(item) for item in DEFAULT_ATTRIBUTE_MAPPINGS
    ])
    ldap_start_tls: bool = True
    ldap_allow_insecure: bool = False
    direction: Literal["bidirectional", "scim_to_ldap", "ldap_to_scim"] = "bidirectional"
    conflict_policy: Literal["manual", "scim_wins", "ldap_wins"] = "manual"
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = False
    dry_run: bool = True

    @model_validator(mode="after")
    def validate_endpoints(self):
        paths = [item.scim_path.casefold() for item in self.attribute_mappings]
        attributes = [item.ldap_attribute.casefold() for item in self.attribute_mappings]
        if len(paths) != len(set(paths)) or len(attributes) != len(set(attributes)):
            raise ValueError("SCIM paths and LDAP attributes must each be unique in the mapping.")
        if not any(item.scim_path == "userName" for item in self.attribute_mappings):
            raise ValueError("A userName mapping is required to identify users.")
        username_mapping = next(item for item in self.attribute_mappings if item.scim_path == "userName")
        if username_mapping.direction != "both":
            raise ValueError("The userName mapping must be enabled in both directions.")
        for value, schemes in ((self.scim_url, ("https", "http")),
                               (self.ldap_url, ("ldaps", "ldap"))):
            if value:
                parsed = urlparse(value)
                if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError("Invalid endpoint URL; credentials must use separate fields.")
                if parsed.query or parsed.fragment:
                    raise ValueError("Endpoint URLs cannot contain queries or fragments.")
        if (self.ldap_url.startswith("ldap://") and not self.ldap_start_tls
                and not self.ldap_allow_insecure):
            raise ValueError("ldap:// endpoints require StartTLS, an ldaps:// endpoint, "
                             "or explicitly allowing unencrypted LDAP.")
        if self.enabled and not all((self.scim_url, self.ldap_url, self.ldap_base_dn,
                                     self.ldap_bind_dn, self.ldap_password, self.scim_token)):
            raise ValueError("Configure both connectors before enabling the schedule.")
        return self