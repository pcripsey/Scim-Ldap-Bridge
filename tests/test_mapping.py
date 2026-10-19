import unittest

from bridge.config import AttributeMapping, DEFAULT_ATTRIBUTE_MAPPINGS
from bridge.connectors import from_scim, scim_document
from bridge.planner import canonical


class MappingTests(unittest.TestCase):
    def test_custom_extension_values_round_trip(self):
        path = "urn:example:params:scim:schemas:extension:custom:2.0:User:costCode"
        mappings = [AttributeMapping.model_validate(item) for item in DEFAULT_ATTRIBUTE_MAPPINGS]
        mappings.append(AttributeMapping(scim_path=path, ldap_attribute="employeeNumber"))
        source = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "ada",
            "name": {"givenName": "Ada", "familyName": "Lovelace"},
            path.rsplit(":", 1)[0]: {"costCode": "042"},
        }
        user = from_scim(source, mappings)
        self.assertEqual(user["_mapped"][path], "042")
        self.assertIn("_mapped", canonical(user))
        result = scim_document(user, mappings=mappings)
        self.assertEqual(result[path.rsplit(":", 1)[0]]["costCode"], "042")
        self.assertIn(path.rsplit(":", 1)[0], result["schemas"])

    def test_mapping_rejects_sensitive_and_read_only_paths(self):
        for path in ("password", "meta.version", "groups.value", "active"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                AttributeMapping(scim_path=path, ldap_attribute="description")
        with self.assertRaises(ValueError):
            AttributeMapping(scim_path="displayName", ldap_attribute="userPassword")

    def test_email_mapping_preserves_primary_value(self):
        user = from_scim({
            "userName": "ada",
            "emails": [{"value": "ada@example.org", "primary": True},
                       {"value": "other@example.org"}],
        })
        self.assertEqual(user["email"], "ada@example.org")
        output = scim_document(user)
        self.assertEqual(output["emails"], [{"value": "ada@example.org", "type": "work", "primary": True}])


if __name__ == "__main__":
    unittest.main()
