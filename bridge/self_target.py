import os
import uuid

import httpx


CALLER_HEADER = "X-SCIM-Bridge-Caller"
ERROR_HEADER = "X-SCIM-Bridge-Error"
CALLER_ID = uuid.uuid4().hex
SELF_TARGET_DETAIL = (
    "Outbound SCIM points to this bridge. Configure the remote SCIM provider URL "
    "and its provider token, not this bridge's inbound provisioning endpoint."
)


class SelfTargetError(ValueError):
    def __init__(self):
        super().__init__(SELF_TARGET_DETAIL)


def endpoint_key(value):
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL:
        raise ValueError("Invalid bridge self URL; use a full HTTP(S) SCIM base URL.") from None
    if (url.scheme not in {"http", "https"} or not url.host or url.userinfo
            or url.query or url.fragment):
        raise ValueError("Invalid bridge self URL; use a full HTTP(S) SCIM base URL.")
    return (url.scheme, url.host.lower().rstrip("."), url.port,
            url.path.rstrip("/"))


def check_scim_target(value, additional_urls=()):
    if not value:
        return
    known = [
        *filter(None, (item.strip() for item in os.environ.get("BRIDGE_SCIM_SELF_URLS", "").split(","))),
        *additional_urls,
    ]
    target = endpoint_key(value)
    if any(target == endpoint_key(alias) for alias in known):
        raise SelfTargetError()
