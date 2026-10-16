from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scim_url: str = ""
    scim_token: str = ""
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_password: str = ""
    ldap_base_dn: str = ""
    ldap_start_tls: bool = True
    ldap_allow_insecure: bool = False
    direction: Literal["bidirectional", "scim_to_ldap", "ldap_to_scim"] = "bidirectional"
    conflict_policy: Literal["manual", "scim_wins", "ldap_wins"] = "manual"
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = False
    dry_run: bool = True

    @model_validator(mode="after")
    def validate_endpoints(self):
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