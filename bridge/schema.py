from copy import deepcopy

from scim2_models import EnterpriseUser, Group, Path, Schema, ScimFilter, User


USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


class Catalog:
    def __init__(self, custom_schemas=()):
        extensions = [EnterpriseUser]
        self.schemas = [User.to_schema(), Group.to_schema(), EnterpriseUser.to_schema()]
        for definition in custom_schemas:
            schema = Schema.model_validate(definition)
            if schema.id in {item.id for item in self.schemas}:
                raise ValueError("Custom schema IDs must be unique and cannot replace core schemas.")
            extensions.append(User.from_schema(schema))
            self.schemas.append(schema)
        self.models = {"Users": User[tuple(extensions)], "Groups": Group}

    def validate(self, kind, document):
        return self.models[kind].model_validate(document)

    def get(self, kind, document, path):
        return Path[self.models[kind]](path).get(self.validate(kind, document), strict=False)

    def set(self, kind, document, path, value, add=False):
        model = self.validate(kind, document)
        Path[self.models[kind]](path).set(model, value, is_add=add)
        return model.model_dump(mode="json", by_alias=True, exclude_none=True)

    def patch(self, kind, document, operations):
        model = self.validate(kind, deepcopy(document))
        for operation in operations:
            mode = operation.get("op", "").lower()
            path = operation.get("path")
            if mode not in ("add", "replace", "remove"):
                raise ValueError("Unsupported patch operation.")
            if not path:
                if mode == "remove" or not isinstance(operation.get("value"), dict):
                    raise ValueError("A patch path or object value is required.")
                for name, value in operation["value"].items():
                    if name in ("id", "meta", "schemas", "groups"):
                        raise ValueError("Read-only attributes cannot be patched.")
                    Path[self.models[kind]](name).set(model, value, is_add=mode == "add")
            else:
                if path.split(".")[0] in ("id", "meta", "schemas", "groups"):
                    raise ValueError("Read-only attributes cannot be patched.")
                selected = Path[self.models[kind]](path)
                if mode == "remove":
                    selected.delete(model)
                else:
                    selected.set(model, operation.get("value"), is_add=mode == "add")
        return model.model_dump(mode="json", by_alias=True, exclude_none=True)

    def matches(self, kind, document, expression):
        return ScimFilter[self.models[kind]](expression).match(self.validate(kind, document), strict=True)


def json_value(value):
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return value