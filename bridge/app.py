import base64
import hmac
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from bridge.config import Settings
from bridge.connectors import LdapClient, ScimClient, from_scim, scim_document
from bridge.service import BusyError, SyncService
from bridge.store import Store


SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
STATIC = Path(__file__).resolve().parent.parent / "web" / "dist"


def opaque_id(username):
    return base64.urlsafe_b64encode(username.encode()).decode().rstrip("=")


def resource(user):
    return {**scim_document(user), "id": opaque_id(user["userName"])}


def create_app(data_dir=None, admin_token=None, scim_token=None):
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

    def authenticate(request, expected):
        supplied = request.headers.get("authorization", "")
        if not expected or not hmac.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            raise HTTPException(401, "A valid bearer token is required.", headers={"WWW-Authenticate": "Bearer"})

    def admin(request: Request):
        authenticate(request, request.app.state.admin_token)

    def provisioning(request: Request):
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
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
        if request.url.path.startswith(("/api/", "/scim/")):
            response.headers["Cache-Control"] = "no-store"
        return response

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
    def stored_resources(source: str | None = Query(None, pattern="^(scim|ldap)$"),
                         resource_type: str = Query("Users", min_length=1, max_length=100),
                         limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return {"resources": app.state.store.resource_records(source, resource_type, limit, offset)}

    @app.get("/api/data/resource", dependencies=[Depends(admin)])
    def stored_resource(source: str = Query(..., pattern="^(scim|ldap)$"),
                        resource_type: str = Query("Users", min_length=1, max_length=100),
                        key: str = Query(..., min_length=1)):
        data = app.state.store.resource(source, resource_type, key)
        if data is None:
            raise HTTPException(404, "Stored resource not found.")
        return {"source": source, "resource_type": resource_type, "key": key, "data": data}

    @app.get("/api/data/operations", dependencies=[Depends(admin)])
    def stored_operations(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return {"operations": app.state.store.operations(limit, offset)}

    @app.get("/api/settings", dependencies=[Depends(admin)])
    def settings():
        current = app.state.store.settings().model_dump()
        for key in ("scim_token", "ldap_password"):
            current[key + "_configured"] = bool(current.pop(key))
        return current

    @app.put("/api/settings", dependencies=[Depends(admin)])
    def save_settings(payload: dict = Body(...)):
        service, store = app.state.service, app.state.store
        if not service.lock.acquire(blocking=False):
            raise HTTPException(409, "Wait for the active directory operation to finish.")
        try:
            old = store.settings()
            try:
                current = Settings.model_validate({**old.model_dump(), **payload})
            except ValidationError as error:
                messages = [item["msg"] for item in error.errors(include_input=False, include_context=False)]
                raise HTTPException(400, "; ".join(messages)) from None
            reset = any(getattr(old, key) != getattr(current, key)
                        for key in ("scim_url", "ldap_url", "ldap_base_dn", "ldap_bind_dn"))
            store.save_settings(current, reset=reset)
            service.revision += 1
            store.event("info", "Configuration saved." + (" Identity baselines reset." if reset else ""))
            return {"saved": True}
        finally:
            service.lock.release()

    @app.post("/api/sync", status_code=202, dependencies=[Depends(admin)])
    def sync():
        current = app.state.store.settings()
        if not all((current.scim_url, current.scim_token, current.ldap_url, current.ldap_bind_dn,
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
            raise HTTPException(502, f"Connection failed ({type(error).__name__}). Check credentials, TLS, endpoint, and read permissions.") from None

    def directory_operation(callback, write=False):
        service, store = app.state.service, app.state.store
        if not service.lock.acquire(blocking=False):
            raise HTTPException(409, "Another directory operation is in progress; retry later.")
        try:
            settings = store.settings()
            if write and settings.dry_run:
                raise HTTPException(409, "Inbound writes are blocked while dry-run mode is enabled.")
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

    def find_user(users, identifier):
        user = next((user for user in users.values() if opaque_id(user["userName"]) == identifier), None)
        if user is None:
            raise HTTPException(404, "User not found.")
        return user

    def validate_user(document):
        if not isinstance(document.get("userName"), str) or not document["userName"].strip():
            raise HTTPException(400, "userName must be a nonempty string.")
        if "active" in document or "password" in document or "groups" in document:
            raise HTTPException(400, "Account status, passwords, and group provisioning are not supported by this mapping.")
        try:
            user = from_scim(document)
        except (AttributeError, TypeError, KeyError):
            raise HTTPException(400, "Invalid SCIM attribute types.") from None
        if not user["familyName"]:
            raise HTTPException(400, "name.familyName is required by the inetOrgPerson schema.")
        return user

    @app.get("/scim/v2/ServiceProviderConfig", dependencies=[Depends(provisioning)])
    def provider_config():
        return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 10000}, "changePassword": {"supported": False},
                "sort": {"supported": False}, "etag": {"supported": False},
                "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "Static provisioning token"}]}

    @app.get("/scim/v2/Users", dependencies=[Depends(provisioning)])
    def list_users(startIndex: int = Query(1, ge=1), count: int = Query(100, ge=0, le=1000), filter: str | None = None):
        match = re.fullmatch(r'\s*userName\s+eq\s+"([^"\\]*)"\s*', filter, re.IGNORECASE) if filter else None
        if filter and not match:
            raise HTTPException(400, 'Only userName eq "value" filters are supported.')

        def read(client, users):
            selected = sorted(users.values(), key=lambda item: item["userName"])
            if match:
                selected = [user for user in selected if user["userName"].casefold() == match[1].casefold()]
            page = selected[startIndex - 1:startIndex - 1 + count]
            return {"schemas": [SCIM_LIST], "totalResults": len(selected), "startIndex": startIndex,
                    "itemsPerPage": len(page), "Resources": [resource(user) for user in page]}
        return directory_operation(read)

    @app.get("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def get_user(identifier: str):
        return directory_operation(lambda client, users: resource(find_user(users, identifier)))

    @app.post("/scim/v2/Users", status_code=201, dependencies=[Depends(provisioning)])
    def create_user(payload: dict = Body(...)):
        user = validate_user(payload)

        def create(client, users):
            if any(name.casefold() == user["userName"].casefold() for name in users):
                raise HTTPException(409, "userName already exists.")
            client.write(user)
            return JSONResponse(resource(user), status_code=201, media_type="application/scim+json",
                                headers={"Location": f"/scim/v2/Users/{opaque_id(user['userName'])}"})
        return directory_operation(create, write=True)

    @app.put("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def replace_user(identifier: str, payload: dict = Body(...)):
        user = validate_user(payload)

        def replace(client, users):
            existing = find_user(users, identifier)
            if user["userName"] != existing["userName"]:
                raise HTTPException(400, "userName is immutable in this mapping.")
            client.write(user, existing)
            return resource(user)
        return directory_operation(replace, write=True)

    @app.patch("/scim/v2/Users/{identifier}", dependencies=[Depends(provisioning)])
    def patch_user(identifier: str, payload: dict = Body(...)):
        operations = payload.get("Operations")
        if not isinstance(operations, list) or not operations or len(operations) > 50:
            raise HTTPException(400, "Provide between 1 and 50 patch operations.")

        def patch(client, users):
            existing = find_user(users, identifier)
            document = resource(existing)
            for operation in operations:
                if not isinstance(operation, dict) or str(operation.get("op", "")).lower() not in ("add", "replace", "remove"):
                    raise HTTPException(400, "Unsupported patch operation.")
                path, value = operation.get("path"), operation.get("value")
                remove = str(operation["op"]).lower() == "remove"
                if path in ("name.givenName", "name.familyName"):
                    document["name"][path.split(".")[1]] = "" if remove else value
                elif path in ("displayName", "emails", "name"):
                    document[path] = ([] if path == "emails" else {} if path == "name" else "") if remove else value
                elif path is None and not remove and isinstance(value, dict) and value.keys() <= {"name", "displayName", "emails"}:
                    document.update(value)
                else:
                    raise HTTPException(400, "Only name, displayName, and emails can be patched.")
            user = validate_user(document)
            client.write(user, existing)
            return resource(user)
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