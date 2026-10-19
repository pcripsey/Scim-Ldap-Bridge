import os
import unittest
from unittest.mock import patch

from bridge.config import Settings
from bridge.connectors import ScimClient
from bridge.self_target import SelfTargetError, check_scim_target


class SelfTargetTests(unittest.TestCase):
    def test_local_bridge_endpoints_are_rejected(self):
        aliases = ("http://localhost:8000/scim/v2/",
                   "http://127.0.0.1:8000/scim/v2",
                   "http://[::1]:8000/scim/v2")
        with patch.dict(os.environ, {"BRIDGE_SCIM_SELF_URLS": ",".join(aliases)}):
            for url in aliases:
                with self.subTest(url=url), self.assertRaises(SelfTargetError):
                    ScimClient(Settings(scim_url=url, scim_token="synthetic-provider-token"))

    def test_public_aliases_are_normalized(self):
        with patch.dict(os.environ, {
            "BRIDGE_SCIM_SELF_URLS": "https://BRIDGE.example.:443/provision/scim/v2/, http://bridge:8000/scim/v2",
        }):
            for url in ("https://bridge.example/provision/scim/v2",
                        "http://bridge:8000/scim/v2/"):
                with self.subTest(url=url), self.assertRaises(SelfTargetError):
                    check_scim_target(url)

    def test_same_host_can_serve_a_separate_provider(self):
        with patch.dict(os.environ, {"BRIDGE_SCIM_SELF_URLS": "https://example.org/scim/v2"}):
            check_scim_target("https://example.org/provider/scim/v2")
            check_scim_target("https://example.org:8443/scim/v2")
            check_scim_target("https://provider.example.org/scim/v2")

    def test_saved_self_target_settings_remain_readable(self):
        settings = Settings(scim_url="http://localhost:8000/scim/v2")
        self.assertEqual(settings.scim_url, "http://localhost:8000/scim/v2")

    def test_malformed_alias_fails_without_exposing_it(self):
        alias = "https://" + "synthetic:private@" + "example.org/scim/v2"
        with patch.dict(os.environ, {"BRIDGE_SCIM_SELF_URLS": alias}):
            with self.assertRaises(ValueError) as raised:
                check_scim_target("https://provider.example.org/scim/v2")
        self.assertNotIn("private", str(raised.exception))
