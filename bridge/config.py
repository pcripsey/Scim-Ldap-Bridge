import json
import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ENTRA_SCIM_URL = "https://graph.microsoft.com/rp/scim"


def validate_entra_filter(value):
    if not value:
        return value
    match = re.fullmatch(r'(userName|id|externalId|groups\.value|active) eq (.+)|userName ew (.+)', value)
    if match:
        attribute, operand, suffix = match.groups()
        if attribute == "active" and operand.lower() in {"true", "false"}:
            return value
        if attribute != "active":
            try:
                parsed = json.loads(operand if operand is not None else suffix)
                if isinstance(parsed, str) and parsed and not any(ord(char) < 32 for char in parsed):
                    return value
            except (ValueError, TypeError):
                pass
    raise ValueError('Use one supported source predicate: userName/id/externalId/groups.value eq "value", '
                     'userName ew "suffix", or active eq true/false.')


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
    scim_provider: Literal["generic", "entra"] = "generic"
    scim_url: str = ""
    scim_token: str = Field(default="", repr=False)
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = Field(default="", repr=False)
    scim_filter: str = Field(default="", max_length=2048)
    ldap_service: Literal["generic", "openldap", "389ds", "active_directory"] = "generic"
    ad_enable_new_accounts: bool = Field(default=False, strict=True)
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_password: str = Field(default="", repr=False)
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
    ignore_unsupported_fields: bool = Field(default=False, strict=True)

    @model_validator(mode="before")
    @classmethod
    def service_defaults(cls, values):
        if isinstance(values, dict) and "attribute_mappings" not in values:
            values = dict(values)
            values["attribute_mappings"] = [
                {**item, "ldap_attribute": "sAMAccountName"}
                if values.get("ldap_service") == "active_directory" and item["scim_path"] == "userName"
                else dict(item) for item in DEFAULT_ATTRIBUTE_MAPPINGS
            ]
        return values

    @property
    def ldap_user_filter(self):
        return ("(&(objectClass=user)(objectCategory=person))"
                if self.ldap_service == "active_directory" else "(objectClass=inetOrgPerson)")

    @property
    def scim_configured(self):
        if self.scim_provider == "entra":
            return bool(self.scim_url and self.entra_tenant_id and self.entra_client_id
                        and self.entra_client_secret)
        return bool(self.scim_url and self.scim_token)

    @model_validator(mode="after")
    def validate_endpoints(self):
        if self.ad_enable_new_accounts:
            if self.ldap_service != "active_directory":
                raise ValueError("New account activation is only available for Active Directory.")
            if not (self.ldap_url.lower().startswith("ldaps://")
                    or (self.ldap_url.lower().startswith("ldap://") and self.ldap_start_tls)):
                raise ValueError("AD account activation requires LDAPS or StartTLS.")
        paths = [item.scim_path.casefold() for item in self.attribute_mappings]
        attributes = [item.ldap_attribute.casefold() for item in self.attribute_mappings]
        if len(paths) != len(set(paths)) or len(attributes) != len(set(attributes)):
            raise ValueError("SCIM paths and LDAP attributes must each be unique in the mapping.")
        if not any(item.scim_path == "userName" for item in self.attribute_mappings):
            raise ValueError("A userName mapping is required to identify users.")
        username_mapping = next(item for item in self.attribute_mappings if item.scim_path == "userName")
        if username_mapping.direction != "both":
            raise ValueError("The userName mapping must be enabled in both directions.")
        if self.ldap_service == "active_directory" and any(
                attribute in {"cn", "distinguishedname", "objectclass", "objectcategory", "useraccountcontrol"}
                for attribute in attributes):
            raise ValueError("AD naming, object class, and account status attributes are managed by the bridge "
                             "or native AD tools, not attribute mappings.")
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
        if self.scim_provider == "entra":
            if self.scim_url not in {ENTRA_SCIM_URL, ENTRA_SCIM_URL + "/"}:
                raise ValueError("Entra requires https://graph.microsoft.com/rp/scim (public cloud).")
            for value in (self.entra_tenant_id, self.entra_client_id):
                if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
                    raise ValueError("Entra tenant and client IDs must be GUIDs.")
            if self.direction != "scim_to_ldap":
                raise ValueError("Entra OAuth mode is pull-only; select SCIM to LDAP.")
            validate_entra_filter(self.scim_filter)
        elif self.scim_filter:
            raise ValueError("Source filtering is only supported in Entra mode.")
        if self.enabled and not all((self.scim_configured, self.ldap_url, self.ldap_base_dn,
                                     self.ldap_bind_dn, self.ldap_password)):
            raise ValueError("Configure both connectors before enabling the schedule.")
        return self