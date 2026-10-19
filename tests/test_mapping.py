import unittest
from unittest.mock import Mock, patch

from ldap3 import MODIFY_REPLACE

from bridge.config import AttributeMapping, DEFAULT_ATTRIBUTE_MAPPINGS, Settings
from bridge.connectors import (LdapClient, ScimClient, collect_attribute_samples, from_scim,
                               schema_attribute_details, scim_document)
from bridge.planner import canonical


class MappingTests(unittest.TestCase):
    def ldap_client(self, service):
        client = LdapClient(Settings(
            ldap_service=service, ldap_url="ldaps://directory.example.org",
            ldap_bind_dn="cn=bridge,dc=example,dc=org", ldap_password="test-bind-value",
            ldap_base_dn="ou=people,dc=example,dc=org",
        ))
        client.connection = Mock()
        client.connection.result = {"result": 0}
        return client

    def activating_client(self):
        client = self.ldap_client("active_directory")
        client.settings = Settings.model_validate({
            **client.settings.model_dump(), "ad_enable_new_accounts": True, "dry_run": False,
        })
        client.connection.server.ssl = True
        client.connection.tls_started = False
        client.connection.add.return_value = True
        client.connection.modify.return_value = True
        return client

    def test_new_ad_account_is_initialized_before_activation(self):
        client = self.activating_client()
        user = from_scim({"userName": "ada", "name": {"familyName": "Lovelace"}},
                         client.settings.attribute_mappings)
        with patch("bridge.connectors.secrets.token_urlsafe", return_value="generated-test-value") as random:
            client.write(user)
        random.assert_called_once_with(48)
        calls = client.connection.method_calls
        self.assertEqual([call[0] for call in calls], ["add", "modify", "modify"])
        self.assertEqual(calls[0].args[2]["userAccountControl"], ["514"])
        self.assertEqual(calls[1].args[1], {
            "unicodePwd": [(MODIFY_REPLACE, ['"aA1!generated-test-value"'.encode("utf-16-le")])],
        })
        self.assertEqual(calls[2].args[1], {"userAccountControl": [(MODIFY_REPLACE, ["512"])]})
        self.assertNotIn("password", user)
        self.assertNotIn("unicodePwd", user)

    def test_ad_activation_never_changes_existing_accounts(self):
        client = self.activating_client()
        user = from_scim({"userName": "ada", "name": {"familyName": "Lovelace"}},
                         client.settings.attribute_mappings)
        with patch("bridge.connectors.secrets.token_urlsafe") as random:
            client.write(user, {"_dn": "cn=ada,dc=example,dc=org"})
        random.assert_not_called()
        client.connection.add.assert_not_called()
        changes = client.connection.modify.call_args.args[1]
        self.assertNotIn("unicodePwd", changes)
        self.assertNotIn("userAccountControl", changes)

    def test_ad_activation_rejects_plain_connections_and_dry_runs_before_creation(self):
        for dry_run, ssl, starttls, allowed in (
                (False, False, False, False), (True, True, False, False),
                (False, False, True, True)):
            client = self.activating_client()
            client.settings.dry_run = dry_run
            client.connection.server.ssl = ssl
            client.connection.tls_started = starttls
            user = from_scim({"userName": "ada", "name": {"familyName": "Lovelace"}},
                             client.settings.attribute_mappings)
            if allowed:
                client.write(user)
                self.assertEqual(client.connection.modify.call_count, 2)
            else:
                with self.assertRaises(ValueError):
                    client.write(user)
                client.connection.add.assert_not_called()
                client.connection.modify.assert_not_called()

    def test_ad_activation_stops_after_each_failed_step(self):
        for step in ("add", "password", "activation"):
            for failure in (False, RuntimeError("test directory failure")):
                with self.subTest(step=step, failure=type(failure).__name__):
                    client = self.activating_client()
                    if step == "add":
                        if failure is False:
                            client.connection.add.return_value = False
                        else:
                            client.connection.add.side_effect = failure
                    else:
                        client.connection.modify.side_effect = (
                            [failure] if step == "password" else [True, failure])
                    user = from_scim({"userName": "ada", "name": {"familyName": "Lovelace"}},
                                     client.settings.attribute_mappings)
                    with self.assertRaises((ValueError, RuntimeError)):
                        client.write(user)
                    self.assertEqual(client.connection.modify.call_count,
                                     {"add": 0, "password": 1, "activation": 2}[step])

    def test_ad_activation_configuration_requires_ad_and_tls(self):
        self.assertFalse(Settings().ad_enable_new_accounts)
        for values in (
            {"ldap_service": "generic", "ldap_url": "ldaps://directory.example.org"},
            {"ldap_service": "active_directory", "ldap_url": ""},
            {"ldap_service": "active_directory", "ldap_url": "ldap://directory.example.org",
             "ldap_start_tls": False, "ldap_allow_insecure": True},
            {"ldap_service": "active_directory", "ldap_url": "ldaps://directory.example.org",
             "ad_enable_new_accounts": "true"},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                Settings(**{"ad_enable_new_accounts": True, **values})

    def test_ldap_service_defaults_and_custom_mappings(self):
        for service in ("generic", "openldap", "389ds", "active_directory"):
            with self.subTest(service=service):
                settings = Settings(ldap_service=service)
                self.assertEqual(settings.attribute_mappings[0].ldap_attribute,
                                 "sAMAccountName" if service == "active_directory" else "uid")
                self.assertEqual(settings.attribute_mappings[2].ldap_attribute, "sn")
        custom = [AttributeMapping(scim_path="userName", ldap_attribute="userPrincipalName")]
        self.assertEqual(Settings(ldap_service="active_directory", attribute_mappings=custom).attribute_mappings,
                         custom)
        with self.assertRaises(ValueError):
            Settings(ldap_service="unsupported")

    def test_service_specific_ldap_creation(self):
        for service in ("generic", "openldap", "389ds", "active_directory"):
            with self.subTest(service=service):
                client = self.ldap_client(service)
                user = from_scim({"userName": "ada", "displayName": "Ada Lovelace",
                                  "name": {"familyName": "Lovelace"}}, client.settings.attribute_mappings)
                client.write(user)
                dn, classes, attrs = client.connection.add.call_args.args
                ad = service == "active_directory"
                self.assertEqual(dn, ("cn" if ad else "uid") + "=ada,ou=people,dc=example,dc=org")
                self.assertEqual(classes[-1], "user" if ad else "inetOrgPerson")
                self.assertEqual(attrs["sn"], ["Lovelace"])
                self.assertEqual(attrs["cn"], ["ada" if ad else "Ada Lovelace"])
                if ad:
                    self.assertEqual(attrs["sAMAccountName"], ["ada"])
                    self.assertEqual(attrs["userAccountControl"], ["514"])
                else:
                    self.assertNotIn("userAccountControl", attrs)

    def test_ad_update_does_not_rename_or_activate_account(self):
        client = self.ldap_client("active_directory")
        user = from_scim({"userName": "ada", "displayName": "New name",
                          "name": {"familyName": "Lovelace"}}, client.settings.attribute_mappings)
        client.write(user, {"_dn": "cn=ada,ou=people,dc=example,dc=org"})
        changes = client.connection.modify.call_args.args[1]
        self.assertNotIn("cn", changes)
        self.assertNotIn("userAccountControl", changes)
        self.assertIn("displayName", changes)
        for attribute in ("cn", "userAccountControl", "objectClass", "objectCategory", "distinguishedName"):
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                Settings(ldap_service="active_directory", attribute_mappings=[
                    {"scim_path": "userName", "ldap_attribute": "sAMAccountName"},
                    {"scim_path": "displayName", "ldap_attribute": attribute},
                ])

    def test_ldap_reads_and_discovery_use_service_filter(self):
        for service in ("generic", "openldap", "389ds", "active_directory"):
            client = self.ldap_client(service)
            attribute = client.settings.attribute_mappings[0].ldap_attribute
            client.connection.extend.standard.paged_search.return_value = [{
                "type": "searchResEntry", "dn": "cn=ada,dc=example,dc=org",
                "attributes": {attribute: ["ada"], "sn": ["Lovelace"]},
            }]
            self.assertIn("ada", client.users())
            client.discovery()
            for call in client.connection.extend.standard.paged_search.call_args_list:
                self.assertEqual(call.args[1], "(&(objectClass=user)(objectCategory=person))"
                                 if service == "active_directory" else "(objectClass=inetOrgPerson)")

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
