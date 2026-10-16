from dataclasses import dataclass


FIELDS = ("userName", "givenName", "familyName", "displayName", "email")


def canonical(user):
    return {field: str(user.get(field) or "") for field in FIELDS}


@dataclass
class Decision:
    username: str
    target: str | None
    operation: str
    user: dict | None
    reason: str


def plan(scim, ldap, previous, direction="bidirectional", policy="manual"):
    decisions = []
    for username in sorted(scim.keys() | ldap.keys() | previous.keys()):
        left, right = scim.get(username), ldap.get(username)
        before = previous.get(username)
        if left is None and right is None:
            continue
        if before and ((left is None and before.get("scim")) or
                       (right is None and before.get("ldap"))):
            decisions.append(Decision(username, None, "conflict", None,
                                      "A previously linked user is missing; deletion is never propagated."))
            continue
        if left is not None and right is not None and canonical(left) == canonical(right):
            continue
        if direction == "scim_to_ldap":
            source, target = left, "ldap"
        elif direction == "ldap_to_scim":
            source, target = right, "scim"
        elif left is None:
            source, target = right, "scim"
        elif right is None:
            source, target = left, "ldap"
        else:
            left_changed = not before or canonical(left) != before.get("scim")
            right_changed = not before or canonical(right) != before.get("ldap")
            if left_changed and not right_changed:
                source, target = left, "ldap"
            elif right_changed and not left_changed:
                source, target = right, "scim"
            elif policy == "scim_wins":
                source, target = left, "ldap"
            elif policy == "ldap_wins":
                source, target = right, "scim"
            else:
                decisions.append(Decision(username, None, "conflict", None,
                                          "Both sides differ; choose an authoritative source to resolve."))
                continue
        if source is not None:
            existing = right if target == "ldap" else left
            decisions.append(Decision(username, target, "update" if existing else "create",
                                      canonical(source), "Source attributes differ from destination."))
    return decisions