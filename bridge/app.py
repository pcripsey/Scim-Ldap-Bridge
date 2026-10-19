import base64
import hmac
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from bridge.config import Settings
from bridge.connectors import (
    LdapClient, ScimClient, filter_inbound, from_scim, inbound_patch_target, scim_document,
)
from bridge.schema import Catalog, ENTERPRISE_SCHEMA, USER_SCHEMA
from bridge.service import BusyError, SyncService
from bridge.self_target import (
    CALLER_HEADER, CALLER_ID, ERROR_HEADER, SELF_TARGET_DETAIL, SelfTargetError, check_scim_target,
)
from bridge.store import Store
from bridge.traffic import TrafficMiddleware, configure_logging


SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
STATIC = Path(__file__).resolve().parent.parent / "web" / "dist"


def opaque_id(username):
    return base64.urlsafe_b64encode(username.encode()).decode().rstrip("=")


def resource(user, mappings=None, base_url=""):
    identifier = opaque_id(user["userName"])
    location = f"{base_url.rstrip('/')}/scim/v2/Users/{identifier}"
    metadata = dict((user.get("_raw") or {}).get("meta") or {})
    metadata.update({"resourceType": "User", "location": location})
    return {**scim_document(user, user.get("_raw"), mappings), "id": identifier,
            "meta": metadata}


def create_app(data_dir=None, admin_token=None, scim_token=None):
    configure_logging()
    @asynccontextmanager
    async def lifespan(app):
        token = admin_token or os.environ.get("BRIDGE_ADMIN_TOKEN", "")
        provisioning = scim_token or os.environ.get("BRIDGE_SCIM_TOKEN", "")
        if len(token) < 24:
            raise RuntimeError("Set BRIDGE_ADMIN_TOKEN to a random secret of at least 24 characters.")
        if provisioning and (len(provisioning) < 24 or hmac.compare_digest(token, provisioning)):
            raise RuntimeError("BRIDGE_SCIM_TOKEN must be at least 24 characters and distinct from the admin token.")
        app.state.admin_token, app.state.scim_token = token, provisioning
        app.state.store = Store(data_dir or os.environ.get("BRIDGE_DATA_DIR", "./data"))
        app.state.service = SyncService(app.state.store)
        app.state.service.start()
        yield
        app.state.service.close()
        app.state.store.close()

    app = FastAPI(title="SCIM LDAP Bridge", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    catalog = Catalog()

    def authenticate(request, expected):
        supplied = request.headers.get("authorization", "")
        if not expected or not hmac.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            raise HTTPException(401, "A valid bearer token is required.", headers={"WWW-Authenticate": "Bearer"})

    def admin(request: Request):
        authenticate(request, request.app.state.admin_token)

    def provisioning(request: Request):
        if request.headers.get(CALLER_HEADER) == CALLER_ID:
            raise HTTPException(400, SELF_TARGET_DETAIL, headers={ERROR_HEADER: "self_target"})
        if not request.app.state.scim_token:
            raise HTTPException(503, "Inbound SCIM provisioning is not enabled.")
        authenticate(request, request.app.state.scim_token)

    @app.exception_handler(HTTPException)
    async def http_error(request, error):
        if request.url.path.startswith("/scim/"):
            return JSONResponse({"schemas": [SCIM_ERROR], "status": str(error.status_code), "detail": error.detail},
                                status_code=error.status_code, headers=error.headers, media_type="application/scim+json")
        return JSONResponse({"detail": error.detail}, status_code=error.status_code, headers=error.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        return await http_error(request, HTTPException(400, "Invalid request parameters or body."))

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        if (request.url.path.startswith("/scim/")
                and response.headers.get("content-type", "").startswith("application/json")):
            response.headers["Content-Type"] = "application/scim+json"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
        if request.url.path.startswith(("/api/", "/scim/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.add_middleware(TrafficMiddleware)

    @app.exception_handler(Exception)
    async def unexpected_error(request, error):
        return PlainTextResponse("Internal Server Error", status_code=500,
                                 headers={"X-Request-ID": request.scope.get("traffic_request_id", "")})

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/api/status", dependencies=[Depends(admin)])
    def status():
        store, service = app.state.store, app.state.service
        settings = store.settings()
        return {"running": service.lock.locked(), "next_run": service.next_run,
                "enabled": settings.enabled, "dry_run": settings.dry_run,
                "configured": bool(settings.scim_url and settings.ldap_url and settings.ldap_base_dn),
                "inbound_enabled": bool(app.state.scim_token), "linked_users": len(store.snapshots()),
                "database": store.data_summary(),
                "runs": store.rows("runs", 30), "events": store.rows("events", 100)}

    @app.get("/api/data/resources", dependencies=[Depends(admin)])
    def stored_resources(source: str | None = Query(None, pattern="^(scim|ldap|inbound)$"),
                         resource_type: str = Query("Users", min_length=1, max_length=100),
                         limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return {"resources": app.state.store.resource_records(source, resource_type, limit, offset)}

    @app.get("/api/data/resource", dependencies=[Depends(admin)])
    def stored_resource(source: str = Query(..., pattern="^(scim|ldap|inbound)$"),
                        resource_type: str = Query("Users", min_length=1, max_length=100),
                        key: str = Query(..., min_length=1)):
        data = app.state.store.resource(source, resource_type, key)
        if data is None:
            raise HTTPException(404, "Stored resource not found.")
        return {"source": source, "resource_type": resource_type, "key": key, "data": data}

    @app.delete("/api/data/pending", dependencies=[Depends(admin)])
    def discard_pending(key: str = Query(..., min_length=1)):
        service, store = app.state.service, app.state.store
        if not service.lock.acquire(blocking=False):
            raise HTTPException(409, "Wait for the active directory operation to finish.")
        try:
            if not store.remove_pending(key):
                raise HTTPException(404, "Queued user not found.")
            store.event("info", "Queued SCIM push user discarded; it was not created in LDAP.", key)
            return {"discarded": True}
        finally:
            service.lock.release()

    @app.get("/api/data/operations", dependencies=[Depends(admin)])
    def stored_operations(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return {"operations": app.state.store.operations(limit, offset)}

    @app.get("/api/settings", dependencies=[Depends(admin)])
    def settings():
        current = app.state.store.settings().model_dump()
        for key in ("scim_token", "ldap_password", "entra_client_secret"):
            current[key + "_configured"] = bool(current.pop(key))
        return current

    @app.put("/api/settings", dependencies=[Depends(admin)])
    def save_settings(request: Request, payload: dict = Body(...)):
        service, store = app.state.service, app.state.store
        if not service.lock.acquire(blocking=False):
            raise HTTPException(409, "Wait for the active directory operation to finish.")
        try:
            old = store.settings()
            confirmation = payload.pop("confirm_scope_reset", False)
            try:
                values = {**old.model_dump(), **payload}
                if values["ldap_service"] != old.ldap_service:
                    values.update(enabled=False, dry_run=True)
                    if values["ldap_service"] != "active_directory":
                        values["ad_enable_new_accounts"] = False
                    if "attribute_mappings" not in payload:
                        values.pop("attribute_mappings")
                current = Settings.model_validate(values)
            except ValidationError as error:
                messages = [item["msg"] for item in error.errors(include_input=False, include_context=False)]
                raise HTTPException(400, "; ".join(messages)) from None
            try:
                check_scim_target(current.scim_url, [str(request.base_url) + "scim/v2"])
            except SelfTargetError:
                raise HTTPException(400, SELF_TARGET_DETAIL) from None
            except ValueError:
                raise HTTPException(400, "Invalid SCIM endpoint or BRIDGE_SCIM_SELF_URLS configuration.") from None
            scope_changed = any(getattr(old, key) != getattr(current, key)
                                for key in ("scim_provider", "entra_tenant_id", "entra_client_id", "scim_filter"))
            if scope_changed and confirmation is not True:
                raise HTTPException(400, "Source identity/scope changes reset inventory and baselines. "
                                    "Review the scope and confirm with confirm_scope_reset=true.")
            reset = scope_changed or any(getattr(old, key) != getattr(current, key)
                                        for key in ("scim_url", "ldap_url", "ldap_base_dn", "ldap_bind_dn",
                                                    "ldap_service"))
            store.save_settings(current, reset=reset)
            service.revision += 1
            store.event("info", "Configuration saved." + (" Identity baselines reset." if reset else ""))
            return {"saved": True}
        finally:
            service.lock.release()

    @app.post("/api/sync", status_code=202, dependencies=[Depends(admin)])
    def sync():
        current = app.state.store.settings()
        if not all((current.scim_configured, current.ldap_url, current.ldap_bind_dn,
                    current.ldap_password, current.ldap_base_dn)):
            raise HTTPException(400, "Configure both connectors before starting a run.")
        try:
            return {"run_id": app.state.service.trigger()}
        except BusyError as error:
            raise HTTPException(409, str(error)) from None

    @app.post("/api/test/{connector}", dependencies=[Depends(admin)])
    def test_connection(connector: str):
        if connector not in ("scim", "ldap"):
            raise HTTPException(404, "Unknown connector.")
        try:
            with (ScimClient if connector == "scim" else LdapClient)(app.state.store.settings()) as client:
                count = len(client.users())
            app.state.store.event("success", f"{connector.upper()} connection verified: {count} users read.")
            return {"ok": True, "users": count}
        except Exception as error:
            if isinstance(error, SelfTargetError):
                raise HTTPException(400, SELF_TARGET_DETAIL) from None
            raise HTTPException(502, f"Connection failed ({type(error).__name__}). Check credentials, TLS, endpoint, and read permissions.") from None

    @app.post("/api/discovery/{connector}", dependencies=[Depends(admin)])
    def discover_attributes(connector: str):
        if connector not in ("scim", "ldap"):
            raise HTTPException(404, "Unknown connector.")
        try:
            with (ScimClient if connector == "scim" else LdapClient)(app.state.store.settings()) as client:
                result = client.discovery()
            return result
        except Exception as error:
            if isinstance(error, SelfTargetError):
                raise HTTPException(400, SELF_TARGET_DETAIL) from None
            raise HTTPException(502, f"Attribute discovery failed ({type(error).__name__}). Check credentials, TLS, endpoint, and read permissions.") from None

    @app.post("/api/mappings/validate", dependencies=[Depends(admin)])
    def validate_mappings(payload: dict = Body(...)):
        try:
            settings = Settings.model_validate({
                **app.state.store.settings().model_dump(),
                "attribute_mappings": payload.get("attribute_mappings"),
            })
        except ValidationError as error:
            messages = [item["msg"] for item in error.errors(include_input=False, include_context=False)]
            raise HTTPException(400, "; ".join(messages)) from None
        try:
            with ScimClient(settings) as scim_client:
                scim = scim_client.discovery()
            with LdapClient(settings) as ldap_client:
                ldap = ldap_client.discovery()
        except Exception as error:
            if isinstance(error, SelfTargetError):
                raise HTTPException(400, SELF_TARGET_DETAIL) from None
            raise HTTPException(502, f"Mapping validation could not inspect both connectors ({type(error).__name__}).") from None
        scim_names = {item["name"].casefold() for item in scim["attributes"]}
        ldap_names = {item["name"].casefold() for item in ldap["attributes"]}
        errors = []
        for mapping in settings.attribute_mappings:
            if mapping.scim_path.casefold() not in scim_names:
                errors.append({"scim_path": mapping.scim_path, "message": "Path was not discovered in the SCIM schema or sample resources."})
            if mapping.ldap_attribute.casefold() not in ldap_names:
                errors.append({"ldap_attribute": mapping.ldap_attribute, "message": "Attribute was not found in the LDAP search base."})
        return {"valid": not errors, "errors": errors, "scim_attributes": len(scim_names),
                "ldap_attributes": len(ldap_names)}

    def directory_operation(callback, write=False):
        service, store = app.state.service, app.state.store
        if not service.lock.acquire(blocking=False):
            raise HTTPException(409, "Another directory operation is in progress; retry later.",
                                headers={ERROR_HEADER: "directory_busy"})
        try:
            settings = store.settings()
            if write and settings.dry_run:
                raise HTTPException(409, "Inbound writes are blocked while dry-run mode is enabled.",
                                    headers={ERROR_HEADER: "dry_run"})
            with LdapClient(settings) as client:
                result = callback(client, client.users())
            if write:
                store.event("success", "Inbound SCIM provisioning completed.")
            return result
        except HTTPException:
            raise
        except Exception as error:
            store.event("error", f"Inbound SCIM operation failed ({type(error).__name__}).")
            raise HTTPException(502, "LDAP operation failed; check connector configuration and directory permissions.") from None
        finally:
            service.lock.release()

    def with_pending(users):
        folded = {name.casefold() for name in users}
        queued = {name: user for name, user in app.state.store.pending_users().items()
                  if name.casefold() not in folded}
        return {**queued, **users}

    def find_pending(identifier):
        return next((user for name, user in app.state.store.pending_users().items()
                     if opaque_id(name) == identifier), None)

    def update_pending(identifier, request, build):
        """Apply an inbound update to a user still waiting to be created in LDAP."""
        service, store = app.state.service, app.state.store
        if find_pending(identifier) is None:
            return None
        if not service.lock.acquire(blocking=False):
            raise HTTPException(409, "Another directory operation is in progress; retry later.",
                                headers={ERROR_HEADER: "directory_busy"})
        try:
            existing = find_pending(identifier)
            if existing is None:
                return None
            user = build(existing)
            if user is not None:
                store.queue_user(user)
                store.event("info", "Queued SCIM push user updated; waiting to be synchronised to LDAP.",
                            user["userName"])
            return resource(user or existing, store.settings().attribute_mappings, str(request.base_url).rstrip("/"))
        finally:
            service.lock.release()

    def find_user(users, identifier):
        user = next((user for user in users.values() if opaque_id(user["userName"]) == identifier), None)
        if user is None:
            raise HTTPException(404, "User not found.")
        return user

    def validate_user(document, filter_fields=True):
        settings = app.state.store.settings()
        if filter_fields and settings.ignore_unsupported_fields:
            document = filter_inbound(document, settings.attribute_mappings)
        if not isinstance(document.get("userName"), str) or not document["userName"].strip():
            raise HTTPException(400, "userName must be a nonempty string.")
        # Mapping paths can never retain these fields, so this only applies when they were not filtered.
        if "active" in document or "password" in document or "groups" in document:
            raise HTTPException(400, "Account status, passwords, and group provisioning are not supported by this mapping.")
        try:
            user = from_scim(document, settings.attribute_mappings)
        except (AttributeError, TypeError, KeyError, ValueError):
            raise HTTPException(400, "Invalid SCIM attribute types.") from None
        if not user["familyName"]:
            detail = ("name.familyName is required by this bridge's Active Directory mapping."
                      if settings.ldap_service == "active_directory"
                      else "name.familyName is required by the inetOrgPerson schema.")
            raise HTTPException(400, detail)
        return user

    @app.get("/scim/v2/ServiceProviderConfig", dependencies=[Depends(provisioning)])
    def provider_config():
        return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 1000}, "changePassword": {"supported": False},
                "sort": {"supported": False}, "etag": {"supported": False},
                "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "Static provisioning token"}]}

    @app.get("/scim/v2/Schemas", dependencies=[Depends(provisioning)])
    def list_schemas():
        supported = [schema for schema in catalog.schemas if schema.id in (USER_SCHEMA, ENTERPRISE_SCHEMA)]
        schemas = [schema.model_dump(mode="json", by_alias=True, exclude_none=True) for schema in supported]
        return {"schemas": [SCIM_LIST], "totalResults": len(schemas), "Resources": schemas}

    @app.get("/scim/v2/Schemas/{schema_id:path}", dependencies=[Depends(provisioning)])
    def get_schema(schema_id: str):
        schema = next((item for item in catalog.schemas
                       if item.id in (USER_SCHEMA, ENTERPRISE_SCHEMA) and item.id == schema_id), None)
        if schema is None:
            raise HTTPException(404, "Schema not found.")
        return schema.model_dump(mode="json", by_alias=True, exclude_none=True)

    @app.get("/scim/v2/ResourceTypes", dependencies=[Depends(provisioning)])
    def list_resource_types():
        resources = [
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User",
             "name": "User", "endpoint": "/Users", "description": "User account",
             "schema": USER_SCHEMA, "schemaExtensions": [{"schema": ENTERPRISE_SCHEMA, "required": False}]},
        ]
        return {"schemas": [SCIM_LIST], "totalResults": len(resources), "Resources": resources}

    @app.get("/scim/v2/ResourceTypes/{resource_type}", dependencies=[Depends(provisioning)])
    def get_resource_type(resource_type: str):
        if resource_type.casefold() != "user":
            raise HTTPException(404, "Resource type not found.")
        return list_resource_types()["Resources"][0]

    @app.get("/scim/v2/Users", dependencies=[Depends(provisioning)])
    def list_users(request: Request, startIndex: int = Query(1, ge=1), count: int = Query(100, ge=0, le=1000),
                   filter: str | None = None):
        def read(client, users):
            selected = sorted(with_pending(users).values(), key=lambda item: item["userName"])
            mappings = app.state.store.settings().attribute_mappings
            if filter:
                try:
                    selected = [user for user in selected
                                if catalog.matches("Users", resource(user, mappings,
                                                                     str(request.base_url).rstrip("/")), filter)]
                except (ValueError, TypeError, KeyError):
                    raise HTTPException(400, "Invalid or unsupported SCIM filter.") from None
            page = selected[startIndex - 1:startIndex - 1 + count]
            return {"schemas": [SCIM_LIST], "totalResults": len(selected), "startIndex": startIndex,
                    "itemsPerPage": len(page), "Resources": [
                        resource(user, mappings, str(request.base_url).rstrip("/")) for user in page]}
        return directory_operation(read)

    @app.get("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def get_user(identifier: str, request: Request):
        mappings = app.state.store.settings().attribute_mappings
        pending = find_pending(identifier)
        if pending is not None:
            return resource(pending, mappings, str(request.base_url).rstrip("/"))
        return directory_operation(lambda client, users: resource(
            find_user(users, identifier), mappings, str(request.base_url).rstrip("/")))

    @app.post("/scim/v2/Users", status_code=201, dependencies=[Depends(provisioning)])
    def create_user(request: Request, payload: dict = Body(...)):
        user = validate_user(payload)
        service, store = app.state.service, app.state.store
        username = user["userName"]
        # The user is stored first and stays queued until LDAP accepts it.
        if not store.add_pending(user):
            raise HTTPException(409, "userName already exists.", headers={ERROR_HEADER: "uniqueness"})
        settings = store.settings()
        if not settings.dry_run and service.lock.acquire(blocking=False):
            try:
                with LdapClient(settings) as client:
                    users = client.users()
                    if any(name.casefold() == username.casefold() for name in users):
                        store.remove_pending(username)
                        raise HTTPException(409, "userName already exists.", headers={ERROR_HEADER: "uniqueness"})
                    service.apply_pending(client, users, only=username)
            except HTTPException:
                raise
            except Exception as error:
                store.pending_attempt(username, type(error).__name__)
            finally:
                service.lock.release()
        if store.pending_user(username) is None:
            store.event("success", "Inbound SCIM provisioning completed.", username)
        else:
            store.event("info", "Inbound SCIM user stored; waiting to be synchronised to LDAP.", username)
        created = resource(user, settings.attribute_mappings, str(request.base_url).rstrip("/"))
        return JSONResponse(created, status_code=201, media_type="application/scim+json",
                            headers={"Location": created["meta"]["location"]})

    @app.put("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def replace_user(identifier: str, request: Request, payload: dict = Body(...)):
        user = validate_user(payload)

        def replace_pending(existing):
            if user["userName"] != existing["userName"]:
                raise HTTPException(400, "userName is immutable in this mapping.")
            return user
        queued = update_pending(identifier, request, replace_pending)
        if queued is not None:
            return queued

        def replace(client, users):
            existing = find_user(users, identifier)
            if user["userName"] != existing["userName"]:
                raise HTTPException(400, "userName is immutable in this mapping.")
            client.write(user, existing)
            return resource(user, app.state.store.settings().attribute_mappings,
                            str(request.base_url).rstrip("/"))
        return directory_operation(replace, write=True)

    @app.patch("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def patch_user(identifier: str, request: Request, payload: dict = Body(...)):
        operations = payload.get("Operations")
        if not isinstance(operations, list) or not operations or len(operations) > 50:
            raise HTTPException(400, "Provide between 1 and 50 patch operations.")

        def patched(existing):
            settings = app.state.store.settings()
            mappings, ignore = settings.attribute_mappings, settings.ignore_unsupported_fields
            document = resource(existing, mappings, str(request.base_url).rstrip("/"))

            def inbound_value(key, item):
                # Treat ignored sub-attributes as absent; an empty result means nothing applicable remains.
                if (key == "name" and isinstance(item, dict)) or (key == "emails" and isinstance(item, list)):
                    return filter_inbound({key: item}, mappings).get(key)
                return item

            applied = False
            for operation in operations:
                if not isinstance(operation, dict) or str(operation.get("op", "")).lower() not in ("add", "replace", "remove"):
                    raise HTTPException(400, "Unsupported patch operation.")
                path, value = operation.get("path"), operation.get("value")
                remove = str(operation["op"]).lower() == "remove"
                if ignore:
                    if path is not None and not inbound_patch_target(path, mappings):
                        continue
                    if path is None and not remove and isinstance(value, dict):
                        value = {key: inbound_value(key, item) for key, item in value.items()
                                 if inbound_patch_target(key, mappings)}
                        value = {key: item for key, item in value.items() if item is not None and item != {}}
                        if not value:
                            continue
                    elif path in ("name", "emails") and not remove:
                        value = inbound_value(path, value)
                        if value is None or value == {}:
                            continue
                applied = True
                if path in ("name.givenName", "name.familyName"):
                    document["name"][path.split(".")[1]] = "" if remove else value
                elif path in ("displayName", "emails", "name"):
                    document[path] = ([] if path == "emails" else {} if path == "name" else "") if remove else value
                elif path is None and not remove and isinstance(value, dict) and value.keys() <= {"name", "displayName", "emails"}:
                    document.update(value)
                else:
                    raise HTTPException(400, "Only name, displayName, and emails can be patched.")
            if not applied:
                # Every operation targeted ignored attributes: a no-op that returns the unchanged resource.
                return None
            return validate_user(document, filter_fields=False)

        queued = update_pending(identifier, request, patched)
        if queued is not None:
            return queued

        def patch(client, users):
            existing = find_user(users, identifier)
            mappings = app.state.store.settings().attribute_mappings
            user = patched(existing)
            if user is None:
                return resource(existing, mappings, str(request.base_url).rstrip("/"))
            client.write(user, existing)
            return resource(user, mappings, str(request.base_url).rstrip("/"))
        return directory_operation(patch, write=True)

    @app.delete("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def delete_user(identifier: str):
        raise HTTPException(405, "Deletion is deliberately disabled; remove users directly in the authoritative directory.")

    if (STATIC / "assets").exists():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

    @app.get("/")
    def console():
        if not (STATIC / "index.html").exists():
            raise HTTPException(503, "Console assets are not built. Run npm ci && npm run build in web/.")
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    return app


app = create_app()