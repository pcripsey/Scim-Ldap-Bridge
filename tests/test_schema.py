import unittest

from scim2_models import EnterpriseUser, Extension

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

    def test_enterprise_extension_registration(self):
        model = self.catalog.validate("Users", self.user)
        self.assertIsInstance(model[EnterpriseUser], EnterpriseUser)
        self.assertEqual(model[EnterpriseUser].department, "Engineering")
        self.assertEqual(model.model_dump(mode="json", by_alias=True, exclude_none=True)[ENTERPRISE_SCHEMA],
                         self.user[ENTERPRISE_SCHEMA])

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
        self.assertIsInstance(catalog.validate("Users", document)[urn], Extension)
        self.assertEqual(catalog.get("Users", document, ENTERPRISE_SCHEMA + ":department"), "Engineering")

    def test_multiple_custom_extensions(self):
        urns = ["urn:example:params:scim:schemas:extension:" + name + ":2.0:User"
                for name in ("First", "Second")]
        catalog = Catalog([{"id": urn, "name": name, "attributes": [
            {"name": "costCode", "type": "string", "multiValued": False, "required": False,
             "mutability": "readWrite", "returned": "default", "uniqueness": "none"}]}
            for urn, name in zip(urns, ("First", "Second"))])
        document = {**self.user, "schemas": [*self.user["schemas"], *urns],
                    **{urn: {"costCode": str(index)} for index, urn in enumerate(urns)}}
        for index, urn in enumerate(urns):
            self.assertEqual(catalog.get("Users", document, urn + ":costCode"), str(index))
        self.assertEqual(catalog.get("Users", document, ENTERPRISE_SCHEMA + ":department"), "Engineering")


if __name__ == "__main__":
    unittest.main()