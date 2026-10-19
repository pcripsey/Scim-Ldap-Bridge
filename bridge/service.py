import threading
import time

from bridge.connectors import LdapClient, ScimClient
from bridge.planner import canonical, plan
from bridge.self_target import SELF_TARGET_DETAIL, SelfTargetError
from bridge.traffic import correlation_id, elapsed, emit, new_id


PENDING_RETRY_SECONDS = 30


class BusyError(Exception):
    pass


def ldap_ready(settings):
    return all((settings.ldap_url, settings.ldap_bind_dn, settings.ldap_password, settings.ldap_base_dn))


class SyncService:
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.worker = None
        self.scheduler = None
        self.next_run = None
        self.revision = 0

    def start(self):
        self.scheduler = threading.Thread(target=self.schedule, daemon=True)
        self.scheduler.start()

    def close(self):
        self.stop.set()
        if self.scheduler:
            self.scheduler.join()
        if self.worker:
            self.worker.join()

    def schedule(self):
        due = None
        pending_due = time.time() + PENDING_RETRY_SECONDS
        revision = self.revision
        while not self.stop.wait(1):
            if time.time() >= pending_due:
                try:
                    self.drain_pending()
                except Exception as error:
                    try:
                        self.store.event("error", f"Queued SCIM push retry failed ({type(error).__name__}).")
                    except Exception:
                        pass
                pending_due = time.time() + PENDING_RETRY_SECONDS
            settings = self.store.settings()
            if revision != self.revision:
                revision, due = self.revision, None
            if not settings.enabled:
                self.next_run = None
                due = None
                continue
            if due is None:
                due = time.time() + settings.interval_seconds
            self.next_run = due
            if time.time() >= due:
                try:
                    self.trigger()
                except BusyError:
                    pass
                due = time.time() + settings.interval_seconds

    def apply_pending(self, client, ldap_users, only=None):
        """Create queued inbound SCIM users in LDAP; the caller must hold self.lock.

        Users stay queued until LDAP accepts them. Users that already exist in LDAP are
        marked as conflicts for administrator review instead of being overwritten.
        """
        created = 0
        existing = {name.casefold() for name in ldap_users}
        for username, user in self.store.pending_users().items():
            if only is not None and username.casefold() != only.casefold():
                continue
            if username.casefold() in existing:
                self.store.pending_attempt(username, "userName already exists in LDAP.", conflict=True)
                self.store.event("warning", "Queued SCIM push user already exists in LDAP; review and discard it.",
                                 username)
                continue
            try:
                client.write(user)
            except Exception as error:
                self.store.pending_attempt(username, type(error).__name__)
                continue
            self.store.remove_pending(username)
            existing.add(username.casefold())
            created += 1
            self.store.event("success", "Queued SCIM push user created in LDAP.", username)
        if created:
            try:
                self.store.replace_resources("ldap", "Users", client.users())
            except Exception as error:
                self.store.event("warning", f"LDAP inventory refresh failed ({type(error).__name__}); "
                                 "run a sync to refresh it.")
        return created

    def drain_pending(self):
        settings = self.store.settings()
        if settings.dry_run or not ldap_ready(settings) or not self.store.pending_users():
            return None
        if not self.lock.acquire(blocking=False):
            return None
        token = correlation_id.set(new_id())
        start = time.perf_counter()
        result = "exception"
        applied = False
        try:
            with LdapClient(settings) as client:
                users = client.users()
                applied = True
                created = self.apply_pending(client, users)
            result = "completed"
            return created
        except Exception as error:
            if not applied:
                for username in self.store.pending_users():
                    self.store.pending_attempt(username, type(error).__name__)
            return None
        finally:
            try:
                emit("internal", "sync", "pending_users", result, elapsed(start))
            finally:
                correlation_id.reset(token)
                self.lock.release()

    def trigger(self):
        if not self.lock.acquire(blocking=False):
            raise BusyError("A directory operation is already in progress.")
        try:
            settings = self.store.settings()
            run_id = self.store.begin_run(settings.dry_run)
            self.worker = threading.Thread(target=self.run, args=(settings, run_id, correlation_id.get()), daemon=True)
            self.worker.start()
            return run_id
        except Exception:
            self.lock.release()
            raise

    def run(self, settings, run_id, parent_id=""):
        token = correlation_id.set(new_id())
        start = time.perf_counter()
        result = "exception"
        try:
            result = self._run(settings, run_id)
        finally:
            try:
                metadata = {"parent_id": parent_id}
                if result == "conflicts":
                    metadata["reason"] = "planner_conflict"
                emit("internal", "sync", "reconcile", result, elapsed(start), **metadata)
            finally:
                correlation_id.reset(token)

    def _run(self, settings, run_id):
        processed = changed = conflicts = errors = 0
        try:
            with ScimClient(settings) as scim_client, LdapClient(settings) as ldap_client:
                scim, ldap = scim_client.users(), ldap_client.users()
                processed = len(scim.keys() | ldap.keys())
                decisions = plan(scim, ldap, self.store.snapshots(), settings.direction, settings.conflict_policy)
                operation_ids = self.store.stage_run(run_id, scim, ldap, decisions, settings.dry_run)
                for decision, operation_id in zip(decisions, operation_ids, strict=True):
                    if decision.operation == "conflict":
                        conflicts += 1
                        self.store.event("warning", decision.reason, decision.username, run_id)
                    elif settings.dry_run:
                        changed += 1
                        self.store.event("info", f"Dry run: would {decision.operation} in {decision.target.upper()}.",
                                         decision.username, run_id)
                    else:
                        self.store.operation_state(operation_id, "applying")
                        try:
                            client, users = (ldap_client, ldap) if decision.target == "ldap" else (scim_client, scim)
                            client.write(decision.user, users.get(decision.username))
                        except Exception as error:
                            errors += 1
                            self.store.operation_state(operation_id, "failed", type(error).__name__)
                            message = SELF_TARGET_DETAIL if isinstance(error, SelfTargetError) else (
                                f"Write failed ({type(error).__name__}); no baseline recorded.")
                            self.store.event("error", message,
                                             decision.username, run_id)
                        else:
                            self.store.operation_state(operation_id, "applied")
                            changed += 1
                            self.store.event("success", f"User {decision.operation} completed in {decision.target.upper()}.",
                                             decision.username, run_id)
                if not settings.dry_run and changed:
                    scim, ldap = scim_client.users(), ldap_client.users()
                    self.store.replace_resources("scim", "Users", scim)
                    self.store.replace_resources("ldap", "Users", ldap)
                for username in scim.keys() & ldap.keys():
                    if canonical(scim[username]) == canonical(ldap[username]):
                        self.store.snapshot(username, canonical(scim[username]), canonical(ldap[username]))
                status = "failed" if errors else "conflicts" if conflicts else "completed"
                self.store.event("info", f"Run finished: {processed} users, {changed} changes, {conflicts} conflicts, {errors} errors.",
                                 run_id=run_id)
        except Exception as error:
            errors += 1
            status = "failed"
            message = SELF_TARGET_DETAIL if isinstance(error, SelfTargetError) else (
                f"Reconciliation stopped ({type(error).__name__}). Check endpoints, credentials, TLS, and schema.")
            self.store.event("error", message,
                             run_id=run_id)
        finally:
            try:
                self.store.finish_run(run_id, status, processed, changed, conflicts, errors)
            finally:
                self.lock.release()
        return status