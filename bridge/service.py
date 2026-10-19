import threading
import time

from bridge.connectors import LdapClient, ScimClient
from bridge.planner import canonical, plan
from bridge.self_target import SELF_TARGET_DETAIL, SelfTargetError
from bridge.traffic import correlation_id, elapsed, emit, new_id


class BusyError(Exception):
    pass


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
        revision = self.revision
        while not self.stop.wait(1):
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