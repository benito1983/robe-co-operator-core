# backend/security/repository.py
#
# Org-scoped storage for capabilities, audit entries and policies.
# Same Repository Layer shape as every other module on this platform
# (see backend/core/repository.py).
#
# The audit log uses a per-org hash chain: every row stores prev_hash
# (previous row's row_hash for the same org) and row_hash (SHA256 over
# prev_hash + canonical payload + created_at). Appending takes a
# Postgres advisory transaction lock scoped to the org, so two
# concurrent writers serialize instead of racing for the chain tip.
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg2
import psycopg2.extras

from backend.core.repository import OrgScopedRepository, connection


class CapabilityRepository(OrgScopedRepository):
    table = "security_capabilities"

    def save(self, cap) -> None:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO security_capabilities
                        (id, org_id, subject, action, resource, parent_id,
                         issued_at, expires_at, signature)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                (
                    str(cap.id),
                    str(cap.org_id),
                    cap.subject,
                    cap.action,
                    cap.resource,
                    str(cap.parent_id) if cap.parent_id else None,
                    cap.issued_at,
                    cap.expires_at,
                    psycopg2.Binary(cap.signature),
                ),
            )

    def find_candidates(
        self,
        org_id: UUID,
        subject: str,
        resource: str | None,
    ) -> list[dict[str, Any]]:
        """All non-revoked, non-expired capabilities for this subject
        in this org, optionally narrowed by resource. Action-scope
        filtering happens in Python (see capabilities.action_is_subset)
        because SQL LIKE patterns cannot express our wildcard semantics
        cleanly. Callers re-verify signatures - the DB is not trusted
        to have stored them intact."""
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT * FROM security_capabilities
                    WHERE org_id = %s
                      AND subject = %s
                      AND revoked_at IS NULL
                      AND expires_at > now()
                      AND (%s IS NULL OR resource IS NULL OR resource = %s)
                    """,
                    (str(org_id), subject, resource, resource),
                )
                return cur.fetchall()

    def get(self, org_id: UUID, capability_id: UUID) -> dict[str, Any] | None:
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM security_capabilities WHERE id = %s AND org_id = %s",
                    (str(capability_id), str(org_id)),
                )
                return cur.fetchone()

    def list_active(self, org_id: UUID) -> list[dict[str, Any]]:
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT * FROM security_capabilities
                    WHERE org_id = %s AND revoked_at IS NULL AND expires_at > now()
                    ORDER BY issued_at DESC
                    """,
                    (str(org_id),),
                )
                return cur.fetchall()

    def revoke(self, org_id: UUID, capability_id: UUID) -> bool:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                    UPDATE security_capabilities
                    SET revoked_at = now()
                    WHERE id = %s AND org_id = %s AND revoked_at IS NULL
                    """,
                (str(capability_id), str(org_id)),
            )
            return cur.rowcount > 0

    def revoke_by_subject(self, org_id: UUID, subject: str) -> int:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                    UPDATE security_capabilities
                    SET revoked_at = now()
                    WHERE org_id = %s AND subject = %s AND revoked_at IS NULL
                    """,
                (str(org_id), subject),
            )
            return cur.rowcount


class AuditRepository(OrgScopedRepository):
    table = "security_audit_log"

    @staticmethod
    def _entry_hash(prev_hash: bytes | None, payload: dict, created_at: datetime) -> bytes:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        digest = hashlib.sha256()
        digest.update(prev_hash if prev_hash else b"\x00" * 32)
        digest.update(canonical.encode("utf-8"))
        digest.update(created_at.astimezone().isoformat().encode("utf-8"))
        return digest.digest()

    def append(self, org_id: UUID, event_type: str, payload: dict, created_at: datetime) -> bytes:
        """Atomically appends one entry. Advisory transaction lock scoped
        to the org prevents chain forks under concurrency. Returns the
        row_hash of the newly written entry."""
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (str(org_id),))
            cur.execute(
                """
                    SELECT row_hash FROM security_audit_log
                    WHERE org_id = %s
                    ORDER BY sequence DESC LIMIT 1
                    """,
                (str(org_id),),
            )
            row = cur.fetchone()
            prev_hash = bytes(row[0]) if row else None

            row_hash = self._entry_hash(prev_hash, payload, created_at)

            cur.execute(
                """
                    INSERT INTO security_audit_log
                        (org_id, event_type, payload, prev_hash,
                         row_hash, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                (
                    str(org_id),
                    event_type,
                    psycopg2.extras.Json(payload, dumps=lambda d: json.dumps(d, default=str)),
                    psycopg2.Binary(prev_hash) if prev_hash else None,
                    psycopg2.Binary(row_hash),
                    created_at,
                ),
            )
            return row_hash

    def tail(self, org_id: UUID, limit: int = 100) -> list[dict[str, Any]]:
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT sequence, event_type, payload, row_hash, created_at
                    FROM security_audit_log
                    WHERE org_id = %s
                    ORDER BY sequence DESC LIMIT %s
                    """,
                    (str(org_id), limit),
                )
                return cur.fetchall()

    def verify_chain(self, org_id: UUID) -> tuple[bool, int | None]:
        """Recomputes the entire chain. Returns (True, None) if intact,
        (False, sequence_of_first_broken_row) otherwise. O(n) in the
        number of entries - intended for a scheduled integrity job, not
        for every read."""
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT sequence, event_type, payload, prev_hash,
                           row_hash, created_at
                    FROM security_audit_log
                    WHERE org_id = %s
                    ORDER BY sequence ASC
                    """,
                    (str(org_id),),
                )
                rows = cur.fetchall()

        prev: bytes | None = None
        for row in rows:
            expected = self._entry_hash(prev, row["payload"], row["created_at"])
            if expected != bytes(row["row_hash"]):
                return False, row["sequence"]
            prev = bytes(row["row_hash"])
        return True, None


class PolicyRepository(OrgScopedRepository):
    table = "security_policies"

    # Same two safe, alert-only starter policies migration 026 seeds for
    # orgs that already existed when it ran. That seed is necessarily a
    # one-shot INSERT ... SELECT FROM organizations - it cannot cover
    # orgs created afterward. seed_defaults() below is the callable
    # counterpart, meant to run once when the security module is
    # enabled for a (new or existing) org - same "callable, not
    # trigger-driven" convention as backend.core.permissions.
    # create_default_roles(), which nothing in this codebase auto-calls
    # either; an onboarding flow is expected to call both.
    DEFAULT_POLICIES: list[tuple[str, dict, str, str]] = [
        (
            "login_bruteforce_burst",
            {
                "match": {"event_type": "auth.login_failed"},
                "threshold": {"count_in_window": 20, "window_seconds": 60, "same_field": "ip"},
            },
            "alert",
            "warning",
        ),
        ("api_key_change", {"match": {"event_type": "api_key.updated"}}, "alert", "info"),
    ]

    def seed_defaults(self, org_id: UUID) -> None:
        """Idempotent via ON CONFLICT (org_id, name) - safe to call every
        time the security module is (re-)enabled for an org, not just
        once."""
        with connection() as conn, conn.cursor() as cur:
            for name, rule, effect, severity in self.DEFAULT_POLICIES:
                cur.execute(
                    """
                        INSERT INTO security_policies (org_id, name, rule, effect, severity)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (org_id, name) DO NOTHING
                        """,
                    (str(org_id), name, psycopg2.extras.Json(rule), effect, severity),
                )

    def list_enabled(self, org_id: UUID) -> list[dict[str, Any]]:
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, name, rule, effect, severity
                    FROM security_policies
                    WHERE org_id = %s AND enabled = true
                    ORDER BY name ASC
                    """,
                    (str(org_id),),
                )
                return cur.fetchall()

    def list_all(self, org_id: UUID) -> list[dict[str, Any]]:
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, name, rule, effect, severity, enabled, created_at, updated_at
                    FROM security_policies
                    WHERE org_id = %s
                    ORDER BY name ASC
                    """,
                    (str(org_id),),
                )
                return cur.fetchall()

    def create(
        self,
        org_id: UUID,
        name: str,
        rule: dict,
        effect: str,
        severity: str,
    ) -> dict[str, Any]:
        with connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    INSERT INTO security_policies (org_id, name, rule, effect, severity)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, name, rule, effect, severity, enabled, created_at, updated_at
                    """,
                    (str(org_id), name, psycopg2.extras.Json(rule), effect, severity),
                )
                return cur.fetchone()

    def set_enabled(self, org_id: UUID, policy_id: UUID, enabled: bool) -> bool:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                    UPDATE security_policies
                    SET enabled = %s, updated_at = now()
                    WHERE id = %s AND org_id = %s
                    """,
                (enabled, str(policy_id), str(org_id)),
            )
            return cur.rowcount > 0
