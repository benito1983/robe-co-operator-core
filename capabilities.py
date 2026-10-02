# backend/security/capabilities.py
#
# Capability tokens for RoBe - short-lived, HMAC-signed grants that
# authorize ONE subject to perform ONE action on ONE resource within
# ONE organization. This is a SECOND layer on top of the RBAC roles
# in backend/core/permissions.py, not a replacement:
#
#   - RBAC answers "does this user's role include can_view_products?"
#   - Capabilities answer "is there a currently-valid, signed grant
#     for THIS user, for THIS action, on THIS resource, still in
#     scope, not attenuated?"
#
# Attenuation: delegating can only ever NARROW the action scope. A
# capability for "affiliate.*" can be delegated down to
# "affiliate.product.read", never up to "*". Enforced in issue() and
# re-verified by the signature covering all fields.
#
# Signing: HMAC-SHA256 with an HKDF-derived per-org key from the
# platform master key. Deliberately NOT reusing the RSA JWT keypair -
# different lifecycles, independent rotation.
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.core.crypto import CryptoConfig


class CapabilityError(Exception):
    """Raised on issue/verify/delegate failures. German message - can
    surface in an admin UI."""


@dataclass(frozen=True)
class Capability:
    id: UUID
    org_id: UUID
    subject: str  # user_id (as str) or module key
    action: str  # e.g. "affiliate.product.read"
    resource: str | None  # None = any resource
    parent_id: UUID | None
    issued_at: datetime
    expires_at: datetime
    signature: bytes = field(default=b"", compare=False)


# ─── action scope helpers ────────────────────────────────────────────────


def action_is_subset(child: str, parent: str) -> bool:
    """True if `child` is equal to or more specific than `parent`.
    Wildcards use the trailing '.*' form:
        '*'                      allows anything
        'affiliate.*'            allows 'affiliate.product.read'
        'affiliate.product.*'    allows 'affiliate.product.read'
        'affiliate.product.read' allows exactly that
    """
    if parent == "*":
        return True
    if child == parent:
        return True
    if parent.endswith(".*"):
        prefix = parent[:-2]
        return child == prefix or child.startswith(prefix + ".")
    return False


# ─── signing ─────────────────────────────────────────────────────────────


def _org_signing_key(org_id: UUID) -> bytes:
    """HKDF-derives a 32-byte HMAC key from the platform master key,
    scoped to the org. A leak of one derived key does not expose
    another org's key (HKDF's independence property)."""
    master = base64.urlsafe_b64decode(CryptoConfig.SECRET_KEY.encode("ascii"))
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"robe-capability-signing-v1:{org_id}".encode(),
    )
    return hkdf.derive(master)


def _canonical_payload(cap: Capability) -> bytes:
    """Deterministic JSON of the signed fields. Sorted keys, compact
    separators, UTC ISO-8601 timestamps. Do NOT change this function
    without bumping the version in _org_signing_key's info string -
    every existing signature would fail verification."""
    return json.dumps(
        {
            "id": str(cap.id),
            "org_id": str(cap.org_id),
            "subject": cap.subject,
            "action": cap.action,
            "resource": cap.resource,
            "parent_id": str(cap.parent_id) if cap.parent_id else None,
            "issued_at": cap.issued_at.astimezone(UTC).isoformat(),
            "expires_at": cap.expires_at.astimezone(UTC).isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign(cap: Capability, key: bytes) -> bytes:
    return hmac.new(key, _canonical_payload(cap), hashlib.sha256).digest()


# ─── public API ──────────────────────────────────────────────────────────


def issue(
    org_id: UUID,
    subject: str,
    action: str,
    resource: str | None = None,
    parent: Capability | None = None,
    ttl: timedelta = timedelta(hours=1),
) -> Capability:
    """Issues a new capability. With `parent`, the new action must be a
    subset of the parent's action AND the subject must match the
    parent's subject. Without `parent`, it's a root grant - caller is
    responsible for having checked can_issue_capabilities."""
    if parent is not None:
        if parent.subject != subject:
            raise CapabilityError("Delegation darf das Subjekt nicht wechseln.")
        if not action_is_subset(action, parent.action):
            raise CapabilityError(f"Aktion '{action}' ist keine Teilmenge von '{parent.action}'.")
        if parent.expires_at <= datetime.now(UTC):
            raise CapabilityError("Parent-Capability ist bereits abgelaufen.")

    now = datetime.now(UTC)
    unsigned = Capability(
        id=uuid4(),
        org_id=org_id,
        subject=subject,
        action=action,
        resource=resource,
        parent_id=parent.id if parent else None,
        issued_at=now,
        expires_at=now + ttl,
    )
    signature = _sign(unsigned, _org_signing_key(org_id))
    return dataclasses.replace(unsigned, signature=signature)


def verify(cap: Capability, expected_org_id: UUID) -> bool:
    """Full verification: org match, expiry, signature. Does NOT check
    whether the subject currently holds the corresponding RBAC
    permission - that's a separate stage in middleware."""
    if cap.org_id != expected_org_id:
        return False
    if cap.expires_at <= datetime.now(UTC):
        return False
    expected_sig = _sign(cap, _org_signing_key(cap.org_id))
    return hmac.compare_digest(expected_sig, cap.signature)


def delegate(
    parent: Capability,
    subject: str,
    action: str,
    resource: str | None = None,
    ttl: timedelta | None = None,
) -> Capability:
    """Convenience wrapper: delegate() = issue(parent=...). Kept as a
    distinct name because call sites read differently."""
    remaining = parent.expires_at - datetime.now(UTC)
    effective_ttl = ttl or min(timedelta(hours=1), remaining)
    if effective_ttl <= timedelta(0):
        raise CapabilityError("Keine Restlaufzeit für Delegation übrig.")
    return issue(
        org_id=parent.org_id,
        subject=subject,
        action=action,
        resource=resource,
        parent=parent,
        ttl=effective_ttl,
    )
