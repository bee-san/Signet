"""Reviewed service lifecycle planning, execution, and rollback."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from signet.lifecycle import (
    LifecycleOperationRecord,
    LifecycleOperationStore,
    LifecyclePlan,
    setup_lifecycle_lock,
)
from signet.setup_platform import _managed_tailnet_port
from signet.setup_state import SetupError, SetupJournal, SetupSpec


class ServicePlatform(Protocol):
    def service_status(self, spec: SetupSpec) -> dict[str, str]: ...

    def manage_services(self, spec: SetupSpec, action: str) -> None: ...

    def verify_service_health(self, spec: SetupSpec) -> None: ...


@dataclass(frozen=True, slots=True)
class ServiceLifecycle:
    root: Path
    platform: ServicePlatform
    spec_factory: Callable[[], SetupSpec]
    journal_factory: Callable[[], SetupJournal]

    def plan(self, action: str) -> LifecyclePlan:
        if action not in {"start", "stop", "restart"}:
            raise SetupError("service plan action must be start, stop, or restart")
        spec = self.spec_factory()
        journal = self.journal_factory()
        services = self.platform.service_status(spec)
        managed_tailnet_port = _managed_tailnet_port(spec)
        validate_service_snapshot(
            services,
            allow_mixed=False,
            tailscale_port=managed_tailnet_port,
        )
        if action == "restart" and set(local_service_states(services).values()) != {"active"}:
            raise SetupError("restart requires both owned Signet services to be active")
        action_steps = {
            "start": ("start_local_services", "verify_instance_bound_service_health"),
            "stop": ("stop_local_services", "verify_local_services_inactive"),
            "restart": (
                "stop_local_services",
                "verify_local_services_inactive",
                "start_local_services",
                "verify_instance_bound_service_health",
            ),
        }
        destructive = () if action == "start" else ("interrupt_local_service_availability",)
        return LifecyclePlan(
            setup_id=journal.setup_id,
            operation="services",
            action=action,
            observed={
                "setup_status": journal.status,
                "setup_spec_digest": journal.spec_digest,
                "previous_lifecycle_plan_id": self._previous_plan_id(),
                "tailscale_serve_port": managed_tailnet_port,
                "services": dict(sorted(services.items())),
            },
            steps=("inspect_owned_service_state", *action_steps[action]),
            automatic_safe_checks=("owned_service_definitions", "service_manager_state"),
            destructive_actions=destructive,
        )

    def apply(self, action: str, plan_id: str) -> dict[str, Any]:
        if action not in {"start", "stop", "restart"}:
            raise SetupError("service plan action must be start, stop, or restart")
        store = LifecycleOperationStore(self.root)
        with setup_lifecycle_lock(self.root):
            self.journal_factory()
            existing = store.load_optional()
            if existing is not None and existing.plan.plan_id == plan_id:
                record = existing
                if record.plan.operation != "services" or record.plan.action != action:
                    raise SetupError("reviewed lifecycle plan does not match the service action")
            else:
                plan = self.plan(action)
                if plan.plan_id != plan_id:
                    raise SetupError("reviewed lifecycle plan no longer matches observed state")
                phase = "restart_stop" if action == "restart" else action
                record = store.begin(plan, phase=phase)
            return self._resume(record, store)

    def rollback(self, plan_id: str) -> dict[str, Any]:
        store = LifecycleOperationStore(self.root)
        with setup_lifecycle_lock(self.root):
            self.journal_factory()
            spec = self.spec_factory()
            record = store.load_optional()
            if (
                record is None
                or record.plan.plan_id != plan_id
                or record.plan.operation != "services"
            ):
                raise SetupError("reviewed lifecycle plan is unavailable for rollback")
            before = service_observation(record.plan)
            managed_tailnet_port = tailscale_port(record.plan)
            current = self.platform.service_status(spec)
            validate_service_snapshot(
                current,
                allow_mixed=True,
                tailscale_port=managed_tailnet_port,
            )
            require_same_service_inventory(before, current)
            if record.status == "rolled_back":
                if current != before:
                    raise SetupError("rolled-back service plan has drifted from its prior state")
                return {"action": "rollback", "services": current, "plan_id": plan_id}
            record.status = "rolling_back"
            record.phase = "rollback"
            record.error_kind = None
            store.save(record)
            before_local = local_service_states(before)
            rollback_action = "start" if set(before_local.values()) == {"active"} else "stop"
            try:
                if current != before:
                    self._attempt(record, store, spec, rollback_action)
                observed = self.platform.service_status(spec)
                validate_service_snapshot(
                    observed,
                    allow_mixed=False,
                    tailscale_port=managed_tailnet_port,
                )
                if observed != before:
                    raise SetupError("service rollback did not restore the reviewed prior state")
                if rollback_action == "start":
                    self.platform.verify_service_health(spec)
            except Exception as exc:
                record.status = "failed"
                record.error_kind = type(exc).__name__
                store.save(record)
                raise SetupError("service plan rollback failed") from exc
            record.status = "rolled_back"
            record.result = {"action": "rollback", "services": observed, "plan_id": plan_id}
            store.save(record)
            return dict(record.result)

    def _resume(
        self,
        record: LifecycleOperationRecord,
        store: LifecycleOperationStore,
    ) -> dict[str, Any]:
        self.journal_factory()
        spec = self.spec_factory()
        before = service_observation(record.plan)
        managed_tailnet_port = tailscale_port(record.plan)
        target = target_service_snapshot(before, record.plan.action)
        current = self.platform.service_status(spec)
        validate_service_snapshot(
            current,
            allow_mixed=True,
            tailscale_port=managed_tailnet_port,
        )
        require_same_service_inventory(before, current)
        if record.status == "completed":
            if current != target:
                raise SetupError("completed service plan has drifted from its reviewed target")
            if record.result is None:
                raise SetupError("completed service plan receipt has no result")
            return dict(record.result)
        if record.status in {"rolling_back", "rolled_back"}:
            raise SetupError("service plan rollback must be resumed explicitly")
        try:
            if record.plan.action == "restart":
                if record.phase == "restart_stop":
                    if set(local_service_states(current).values()) != {"inactive"}:
                        self._attempt(record, store, spec, "stop")
                    current = self.platform.service_status(spec)
                    validate_service_snapshot(
                        current,
                        allow_mixed=False,
                        tailscale_port=managed_tailnet_port,
                    )
                    if set(local_service_states(current).values()) != {"inactive"}:
                        raise SetupError("restart could not quiesce both owned services")
                    record.phase = "restart_start"
                    record.status = "applying"
                    record.error_kind = None
                    store.save(record)
                current = self.platform.service_status(spec)
                if current != target:
                    self._attempt(record, store, spec, "start")
            elif current != target:
                self._attempt(record, store, spec, record.plan.action)
            observed = self.platform.service_status(spec)
            validate_service_snapshot(
                observed,
                allow_mixed=False,
                tailscale_port=managed_tailnet_port,
            )
            if observed != target:
                raise SetupError("service plan did not reach its reviewed target state")
            if record.plan.action in {"start", "restart"}:
                self.platform.verify_service_health(spec)
        except Exception as exc:
            record.status = "failed"
            record.error_kind = type(exc).__name__
            store.save(record)
            raise SetupError("service plan apply failed") from exc
        record.status = "completed"
        record.phase = "completed"
        record.error_kind = None
        record.result = {
            "action": record.plan.action,
            "services": observed,
            "plan_id": record.plan.plan_id,
        }
        store.save(record)
        return dict(record.result)

    def _attempt(
        self,
        record: LifecycleOperationRecord,
        store: LifecycleOperationStore,
        spec: SetupSpec,
        action: str,
    ) -> None:
        record.status = "applying" if record.phase != "rollback" else "rolling_back"
        record.attempts += 1
        record.error_kind = None
        store.save(record)
        self.platform.manage_services(spec, action)

    def _previous_plan_id(self) -> str | None:
        previous = LifecycleOperationStore(self.root).load_optional()
        if previous is None:
            return None
        if previous.status not in {"completed", "rolled_back"}:
            raise SetupError("a reviewed lifecycle plan is incomplete and must be resumed")
        return previous.plan.plan_id


def local_service_states(services: dict[str, str]) -> dict[str, str]:
    return {name: state for name, state in services.items() if not name.startswith("tailscale:")}


def validate_service_snapshot(
    services: dict[str, str],
    *,
    allow_mixed: bool,
    tailscale_port: int | None,
) -> None:
    local = local_service_states(services)
    if len(local) != 2 or any(state not in {"active", "inactive"} for state in local.values()):
        raise SetupError("owned service-manager state is unavailable or ambiguous")
    serve = {name: state for name, state in services.items() if name.startswith("tailscale:")}
    expected_serve = set() if tailscale_port is None else {f"tailscale:{tailscale_port}"}
    if set(serve) != expected_serve or any(state != "active" for state in serve.values()):
        raise SetupError("owned Tailscale Serve state is unavailable or ambiguous")
    if not allow_mixed and len(set(local.values())) != 1:
        raise SetupError("lifecycle planning refuses a mixed Signet service-manager state")


def require_same_service_inventory(before: dict[str, str], current: dict[str, str]) -> None:
    if set(before) != set(current):
        raise SetupError("owned service inventory changed after lifecycle plan review")
    for name, state in before.items():
        if name.startswith("tailscale:") and current[name] != state:
            raise SetupError("owned Tailscale Serve state changed after lifecycle plan review")


def service_observation(plan: LifecyclePlan) -> dict[str, str]:
    services = plan.observed.get("services")
    if not isinstance(services, dict) or any(
        not isinstance(name, str) or not isinstance(state, str) for name, state in services.items()
    ):
        raise SetupError("reviewed lifecycle plan service observation is invalid")
    result = dict(services)
    validate_service_snapshot(
        result,
        allow_mixed=False,
        tailscale_port=tailscale_port(plan),
    )
    return result


def tailscale_port(plan: LifecyclePlan) -> int | None:
    expected = plan.observed.get("tailscale_serve_port")
    if expected is not None and (not isinstance(expected, int) or isinstance(expected, bool)):
        raise SetupError("reviewed lifecycle plan Tailscale expectation is invalid")
    return expected


def target_service_snapshot(before: dict[str, str], action: str) -> dict[str, str]:
    target = dict(before)
    local_target = "inactive" if action == "stop" else "active"
    for name in local_service_states(target):
        target[name] = local_target
    return target
