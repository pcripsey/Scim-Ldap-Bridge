import unittest
from unittest.mock import Mock

from bridge.config import AttributeMapping, DEFAULT_ATTRIBUTE_MAPPINGS
from bridge.connectors import (ScimClient, collect_attribute_samples, from_scim,
                               schema_attribute_details, scim_document)
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

    def test_empty_custom_value_removes_existing_scim_attribute(self):
        schema = "urn:example:params:scim:schemas:extension:custom:2.0:User"
        path = schema + ":costCode"
        mappings = [AttributeMapping.model_validate(item) for item in DEFAULT_ATTRIBUTE_MAPPINGS]
        mappings.append(AttributeMapping(scim_path=path, ldap_attribute="employeeNumber"))
        result = scim_document(from_scim({"userName": "ada"}, mappings),
                               {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", schema],
                                schema: {"costCode": "042"}}, mappings)
        self.assertNotIn(schema, result)
        self.assertNotIn(schema, result["schemas"])

    def test_mapping_rejects_sensitive_and_read_only_paths(self):
        for path in ("password", "meta.version", "groups.value", "active"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                AttributeMapping(scim_path=path, ldap_attribute="description")
        with self.assertRaises(ValueError):
            AttributeMapping(scim_path="displayName", ldap_attribute="userPassword")

    def test_arbitrary_multivalued_mapping_is_rejected(self):
        mapping = AttributeMapping(scim_path="employeeNumber", ldap_attribute="employeeNumber")
        with self.assertRaises(ValueError):
            from_scim({"userName": "ada", "employeeNumber": ["42", "43"]},
                      [*DEFAULT_ATTRIBUTE_MAPPINGS, mapping])

    def test_discovery_describes_schema_paths_and_excludes_secrets(self):
        extension = "urn:example:params:scim:schemas:extension:custom:2.0:User"
        details = schema_attribute_details([
            {"id": "urn:ietf:params:scim:schemas:core:2.0:User", "attributes": [
                {"name": "emails", "type": "complex", "multiValued": True,
                 "subAttributes": [{"name": "value", "type": "string", "multiValued": False}]},
            ]},
            {"id": extension, "attributes": [
                {"name": "costCode", "type": "string", "multiValued": False},
            ]},
        ])
        self.assertEqual(details["emails.value"], {"type": "string", "multi_valued": True})
        self.assertEqual(details[extension + ":costCode"]["type"], "string")
        samples = {}
        collect_attribute_samples({extension: {"costCode": "42", "password": "secret"}}, samples)
        self.assertEqual(samples, {extension + ":costCode": ["42"]})

    def test_email_mapping_preserves_primary_value(self):
        user = from_scim({
            "userName": "ada",
            "emails": [{"value": "ada@example.org", "primary": True},
                       {"value": "other@example.org"}],
        })
        self.assertEqual(user["email"], "ada@example.org")
        output = scim_document(user)
        self.assertEqual(output["emails"], [{"value": "ada@example.org", "type": "work", "primary": True}])

    def test_custom_mapping_is_written_to_remote_scim(self):
        from bridge.config import Settings

        mappings = [AttributeMapping.model_validate(item) for item in DEFAULT_ATTRIBUTE_MAPPINGS]
        mappings.append(AttributeMapping(scim_path="employeeNumber", ldap_attribute="employeeNumber"))
        client = ScimClient(Settings(scim_url="https://example.org/scim/v2", scim_token="x" * 24,
                                     attribute_mappings=mappings))
        response = Mock()
        response.raise_for_status.return_value = None
        client.client.patch = Mock(return_value=response)
        try:
            user = from_scim({
                "userName": "ada", "name": {"givenName": "Ada", "familyName": "Lovelace"},
                "employeeNumber": "042",
            }, mappings)
            client.write(user, {"_id": "resource-1", "_raw": {"userName": "ada"}})
            operations = client.client.patch.call_args.kwargs["json"]["Operations"]
            self.assertIn({"op": "replace", "path": "employeeNumber", "value": "042"}, operations)
            client.write(from_scim({"userName": "ada"}, mappings),
                         {"_id": "resource-1", "_raw": {"userName": "ada", "employeeNumber": "042"}})
            clear_operations = client.client.patch.call_args.kwargs["json"]["Operations"]
            self.assertIn({"op": "remove", "path": "employeeNumber"}, clear_operations)
        finally:
            client.client.close()


if __name__ == "__main__":
    unittest.main()
