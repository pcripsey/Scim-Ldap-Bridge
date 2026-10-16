import unittest

from bridge.schema import Catalog, ENTERPRISE_SCHEMA, USER_SCHEMA


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog()
        self.user = {"schemas": [USER_SCHEMA, ENTERPRISE_SCHEMA], "userName": "ada",
                     "name": {"givenName": "Ada", "familyName": "Lovelace"},
                     "emails": [{"value": "ada@example.org", "type": "work"}],
                     ENTERPRISE_SCHEMA: {"department": "Engineering"}}

    def test_enterprise_attributes(self):
        self.assertEqual(self.catalog.get("Users", self.user, ENTERPRISE_SCHEMA + ":department"), "Engineering")

    def test_filtered_multivalue_path(self):
        self.assertEqual(self.catalog.get("Users", self.user, 'emails[type eq "work"].value'), ["ada@example.org"])

    def test_filtered_patch(self):
        result = self.catalog.patch("Users", self.user, [{"op": "replace", "path": 'emails[type eq "work"].value', "value": "augusta@example.org"}])
        self.assertEqual(result["emails"][0]["value"], "augusta@example.org")

    def test_complex_filter(self):
        self.assertTrue(self.catalog.matches("Users", self.user, 'userName eq "ada" and emails[type eq "work" and value co "example"]'))

    def test_read_only_patch_is_rejected(self):
        with self.assertRaises(ValueError):
            self.catalog.patch("Users", self.user, [{"op": "replace", "path": "id", "value": "other"}])

    def test_custom_extension(self):
        urn = "urn:example:params:scim:schemas:extension:custom:2.0:User"
        catalog = Catalog([{"id": urn, "name": "Custom", "attributes": [
            {"name": "costCode", "type": "string", "multiValued": False, "required": False,
             "mutability": "readWrite", "returned": "default", "uniqueness": "none"}]}])
        document = {**self.user, "schemas": [*self.user["schemas"], urn], urn: {"costCode": "42"}}
        self.assertEqual(catalog.get("Users", document, urn + ":costCode"), "42")


if __name__ == "__main__":
    unittest.main()