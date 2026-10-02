# backend/core/security_hooks.py
#
# Part of the Trusted Computing Base (TCB). Deliberately tiny, imports
# nothing from any domain module, and every getter below returns the
# SAFE answer when no implementation is registered. That is the whole
# point: disabling the backend/security module for an org must NOT
# weaken the platform - it only removes the extra detection and audit
# layers, never the enforcement.
#
# Only backend/security/middleware.py is allowed to call register_hook().
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

logger = logging.getLogger("SecurityHooks")

_hooks: dict[str, Callable[..., Any]] = {}


def register_hook(name: str, impl: Callable[..., Any]) -> None:
    """Called by backend/security at module startup. Refuses to silently
    overwrite an existing implementation - if two modules claim the
    same slot, that's a misconfiguration worth a warning."""
    if name in _hooks and _hooks[name] is not impl:
        logger.warning(
            "Hook '%s' already registered by %r - refusing overwrite with %r",
            name,
            _hooks[name],
            impl,
        )
        return
    _hooks[name] = impl
    logger.info("Security hook registered: %s", name)


def is_registered(name: str) -> bool:
    return name in _hooks


def _clear_for_tests() -> None:
    """Test-only helper. Never call from production code."""
    _hooks.clear()


# ─── Capability check ────────────────────────────────────────────────────


def check_capability(
    subject: str,
    action: str,
    resource: str | None,
    org_id: UUID,
) -> bool:
    """Fail-closed: no hook registered means DENY. A crashing hook also
    means DENY. Only a hook that returns literally True grants access.
    This runs IN ADDITION to backend.core.permissions.has_permission() -
    it never replaces the RBAC check."""
    hook = _hooks.get("check_capability")
    if hook is None:
        return False
    try:
        return hook(subject, action, resource, org_id) is True
    except Exception as exc:
        logger.error("check_capability raised, denying: %s", exc)
        return False


# ─── Event tap (audit + anomaly) ─────────────────────────────────────────


def on_event(event_type: str, event_data: dict) -> None:
    """Default: no-op. The security module subscribes here to build the
    hash-chained audit log and run anomaly rules. Never allowed to
    raise into the caller - a broken observer must not break the
    publisher."""
    hook = _hooks.get("on_event")
    if hook is None:
        return
    try:
        hook(event_type, event_data)
    except Exception as exc:
        logger.error("on_event hook raised for %s: %s", event_type, exc)


# ─── AI guard ────────────────────────────────────────────────────────────


def guard_ai_input(prompt: str, org_id: UUID) -> str:
    """Default: pass-through. A security-module implementation may
    sanitize, rewrite or raise (raising = 'do not send this prompt')."""
    hook = _hooks.get("guard_ai_input")
    if hook is None:
        return prompt
    return hook(prompt, org_id)


def guard_ai_output(response: str, org_id: UUID) -> str:
    """Default: pass-through. Implementation may redact, replace with a
    safe fallback, or raise."""
    hook = _hooks.get("guard_ai_output")
    if hook is None:
        return response
    return hook(response, org_id)
