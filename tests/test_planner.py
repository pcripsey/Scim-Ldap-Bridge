import unittest

from bridge.planner import canonical, plan


def user(name="Ada"):
    return canonical({"userName": "ada", "givenName": name, "familyName": "Lovelace",
                      "displayName": "Ada Lovelace", "email": "ada@example.org"})


class PlannerTests(unittest.TestCase):
    def test_creates_missing_ldap_user(self):
        result = plan({"ada": user()}, {}, {})
        self.assertEqual((result[0].target, result[0].operation), ("ldap", "create"))

    def test_creates_missing_scim_user(self):
        self.assertEqual(plan({}, {"ada": user()}, {})[0].target, "scim")

    def test_identical_users_are_noop(self):
        self.assertEqual(plan({"ada": user()}, {"ada": user()}, {}), [])

    def test_only_scim_changed(self):
        before = {"ada": {"scim": user(), "ldap": user()}}
        result = plan({"ada": user("Augusta")}, {"ada": user()}, before)
        self.assertEqual(result[0].target, "ldap")

    def test_only_ldap_changed(self):
        before = {"ada": {"scim": user(), "ldap": user()}}
        self.assertEqual(plan({"ada": user()}, {"ada": user("Augusta")}, before)[0].target, "scim")

    def test_simultaneous_changes_require_resolution(self):
        before = {"ada": {"scim": user(), "ldap": user()}}
        result = plan({"ada": user("A")}, {"ada": user("B")}, before)
        self.assertEqual(result[0].operation, "conflict")

    def test_first_link_differences_are_conflicts(self):
        self.assertEqual(plan({"ada": user()}, {"ada": user("B")}, {})[0].operation, "conflict")

    def test_explicit_conflict_policy(self):
        result = plan({"ada": user()}, {"ada": user("B")}, {}, policy="ldap_wins")
        self.assertEqual(result[0].target, "scim")

    def test_missing_linked_user_is_not_recreated(self):
        before = {"ada": {"scim": user(), "ldap": user()}}
        self.assertEqual(plan({}, {"ada": user()}, before)[0].operation, "conflict")

    def test_one_way_never_writes_to_source(self):
        self.assertEqual(plan({}, {"ada": user()}, {}, direction="scim_to_ldap"), [])

    def test_ldap_to_scim_never_creates_in_ldap(self):
        self.assertEqual(plan({"ada": user()}, {}, {}, direction="ldap_to_scim"), [])

    def test_one_way_overrides_destination_changes(self):
        for direction, target in (("ldap_to_scim", "scim"), ("scim_to_ldap", "ldap")):
            with self.subTest(direction=direction):
                result = plan({"ada": user("A")}, {"ada": user("B")}, {}, direction=direction)
                self.assertEqual(result[0].target, target)


if __name__ == "__main__":
    unittest.main()