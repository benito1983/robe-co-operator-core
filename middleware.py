# backend/security/middleware.py
#
# Registers this module's implementations into the core hook slots.
# This is the ONLY file in the package that imports from
# backend.core.security_hooks - every other file is a pure library
# that middleware wires up.
from __future__ import annotations

import logging
from uuid import UUID

from backend.core.events import EventBus
from backend.core.permissions import has_permission
from backend.core.security_hooks import register_hook
from backend.security import anomaly, audit
from backend.security.capabilities import Capability, action_is_subset, verify
from backend.security.events import SECURITY_CAPABILITY_DENIED
from backend.security.repository import CapabilityRepository

logger = logging.getLogger("SecurityMiddleware")

_cap_repo = CapabilityRepository()


# ─── capability check ────────────────────────────────────────────────────


def check_capability_impl(
    subject: str,
    action: str,
    resource: str | None,
    org_id: UUID,
) -> bool:
    """Two-stage check:
      1. RBAC via backend.core.permissions (fast, role-based).
      2. Capability token (signed, short-lived, action-scoped).

    Both must pass. RBAC alone is not enough because roles are
    long-lived; capability alone is not enough because a leaked token
    would otherwise bypass role revocation.

    On deny, publishes SECURITY_CAPABILITY_DENIED with enough context
    to distinguish the two failure modes in the audit log, without
    leaking the token itself."""
    if not _subject_has_rbac_permission(subject, action):
        EventBus().publish(
            SECURITY_CAPABILITY_DENIED,
            {
                "org_id": str(org_id),
                "subject": subject,
                "action": action,
                "resource": resource,
                "reason": "rbac_denied",
            },
        )
        return False

    candidates = _cap_repo.find_candidates(org_id, subject, resource)
    for row in candidates:
        if not action_is_subset(action, row["action"]):
            continue
        cap = _row_to_capability(row)
        if verify(cap, org_id):
            return True

    EventBus().publish(
        SECURITY_CAPABILITY_DENIED,
        {
            "org_id": str(org_id),
            "subject": subject,
            "action": action,
            "resource": resource,
            "reason": "no_valid_capability",
        },
    )
    return False


def _subject_has_rbac_permission(subject: str, action: str) -> bool:
    """RBAC lookup. `subject` is normally a user UUID. Module keys are
    not in the users table and have no RBAC path yet - they fail this
    stage and must rely on a valid capability token alone. That is
    fine for now; a module-level permission model arrives with the
    plugin sandbox."""
    try:
        user_id = UUID(subject)
    except (ValueError, TypeError):
        return False
    return has_permission(user_id, action)


def _row_to_capability(row) -> Capability:
    return Capability(
        id=row["id"],
        org_id=row["org_id"],
        subject=row["subject"],
        action=row["action"],
        resource=row["resource"],
        parent_id=row["parent_id"],
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        signature=bytes(row["signature"]),
    )


# ─── on_event (audit + anomaly combined) ─────────────────────────────────


def on_event_impl(event_type: str, data: dict) -> None:
    """Single 'on_event' implementation. Audit runs first (durable
    record), anomaly second (in-memory rules) - so even if the rule
    engine crashes, the audit entry is already persisted."""
    audit.on_event_impl(event_type, data)
    anomaly.on_event_impl(event_type, data)


# ─── AI guard (pass-through placeholders) ────────────────────────────────


def guard_ai_input_impl(prompt: str, org_id: UUID) -> str:
    """Pass-through for now. Full prompt-injection detection and
    tool-argument validation lands later. Registered anyway so the
    slot is claimed and no other module can quietly replace it."""
    return prompt


def guard_ai_output_impl(response: str, org_id: UUID) -> str:
    """Pass-through for now - see guard_ai_input_impl."""
    return response


# ─── EventBus wiring ──────────────────────────────────────────────────────
# security_hooks.on_event() is a plain function, not itself an EventBus
# subscriber - something has to call it for every event that happens.
# Subscribing to the wildcard "*" pattern (see backend/core/events.py's
# bridged EventBus, which supports fnmatch subscriptions) means every
# publish() in the whole app reaches on_event_impl exactly once, and the
# AUDITED_EVENTS filter inside audit.on_event_impl decides what actually
# gets persisted - keeps this module a pure observer, no other module
# needs to know it exists.


def _on_any_event(data: dict) -> None:
    from backend.core.security_hooks import on_event

    on_event(data.get("type", ""), data)


_subscribed_to_event_bus = False


# ─── public entry point ──────────────────────────────────────────────────


def register_all_hooks() -> None:
    """Idempotent - repeated calls (e.g. re-running app startup in a
    test) must not register duplicate EventBus subscriptions, which
    would otherwise fire on_event_impl (and so audit writes) more than
    once per event."""
    global _subscribed_to_event_bus
    register_hook("check_capability", check_capability_impl)
    register_hook("on_event", on_event_impl)
    register_hook("guard_ai_input", guard_ai_input_impl)
    register_hook("guard_ai_output", guard_ai_output_impl)
    if not _subscribed_to_event_bus:
        EventBus().subscribe("*", _on_any_event)
        _subscribed_to_event_bus = True
    logger.info("Security hooks registered.")
