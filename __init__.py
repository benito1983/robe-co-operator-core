# backend/security/__init__.py
#
# Active Security module for RoBe: capability tokens, hash-chained
# audit log, anomaly detection, and (in later steps) plugin sandbox
# and full AI guardrails.
#
# Registered like every other domain module via register(). Enabled
# per org via backend.core.capabilities.enable_module(org, "security").
# The enforcement primitives (org_id isolation, Argon2id, RS256,
# fail-closed permission check) live in backend/core/ and stay active
# regardless of whether this module is enabled.
from backend.core.registry import ModuleInfo, ModuleRegistry


def register(registry: ModuleRegistry) -> None:
    registry.register(
        ModuleInfo(
            key="security",
            name="RoBe Active Security",
            description=(
                "Capability tokens, hash-chained audit log, anomaly "
                "detection and security hooks (audit, AI guard, "
                "capability checks)"
            ),
            version="0.1.0",
            group="RoBe Trust & Security",
        )
    )


PERMISSIONS = [
    ("can_view_audit_log", "Read the hash-chained audit log"),
    ("can_manage_policies", "Create, edit and disable security policies"),
    ("can_issue_capabilities", "Issue capability tokens to users/modules"),
    ("can_revoke_capabilities", "Revoke any capability in the organization"),
    ("can_view_security_dashboard", "View the security dashboard/anomalies"),
]


def register_permissions() -> None:
    from backend.core.permissions import register_permission

    for key, description in PERMISSIONS:
        register_permission(key, description)


def activate() -> None:
    """Wires up the security hooks. Called by app startup AFTER
    register_permissions(). Idempotent - repeated calls are safe."""
    from backend.security import middleware

    middleware.register_all_hooks()


def seed_default_policies(org_id) -> None:
    """Two safe, alert-only starter anomaly policies for one org.
    Idempotent - safe to call whenever the security module is enabled
    for an org (an onboarding flow calling enable_module(org, "security")
    should call this right after, the same way it would call
    backend.core.permissions.create_default_roles() for a brand new
    org). Migration 026's own seed only covers orgs that existed at
    migration time - this is the callable counterpart for every org
    created afterward."""
    from backend.security.repository import PolicyRepository

    PolicyRepository().seed_defaults(org_id)
