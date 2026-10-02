# backend/security/anomaly.py
#
# Deterministic rule engine over recent audit events. Deliberately not
# ML-based yet - the first version needs to be auditable itself, and a
# human-readable rule is easier to defend than an opaque score.
#
# Rule shape (JSONB in security_policies.rule):
#   {
#     "match": {"event_type": "auth.login_failed",
#               "field_equals": {"ip": "..."}},         # optional
#     "threshold": {"count_in_window": 10,
#                   "window_seconds": 60,
#                   "same_field": "ip"}                 # optional
#   }
#
# Effect and severity live in dedicated columns on security_policies,
# not inside the rule JSON. At least one of match/threshold must be
# present. The rule fires when (match holds) AND (threshold met, if
# given).
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from uuid import UUID

from backend.core.events import EventBus
from backend.security.events import SECURITY_ANOMALY_DETECTED

logger = logging.getLogger("SecurityAnomaly")

_BUFFER_SIZE = 1000
_buffer: dict[UUID, list[tuple[datetime, str, dict]]] = defaultdict(list)


def record_event(org_id: UUID, event_type: str, data: dict) -> None:
    """Appends to the in-process ring buffer. Persistence is the audit
    log's job, not this buffer's."""
    buf = _buffer[org_id]
    buf.append((datetime.now(UTC), event_type, data))
    if len(buf) > _BUFFER_SIZE:
        del buf[: len(buf) - _BUFFER_SIZE]


def _matches_match_clause(event_type: str, data: dict, match: dict) -> bool:
    if "event_type" in match and match["event_type"] != event_type:
        return False
    for field, expected in (match.get("field_equals") or {}).items():
        if data.get(field) != expected:
            return False
    return True


def _threshold_met(
    org_id: UUID,
    rule: dict,
    sample_event_type: str,
    sample_data: dict,
    now: datetime,
) -> bool:
    threshold = rule.get("threshold")
    if not threshold:
        return True

    window_start = now - timedelta(seconds=threshold["window_seconds"])
    same_field = threshold.get("same_field")
    sample_key = sample_data.get(same_field) if same_field else None

    count = 0
    for ts, et, data in _buffer.get(org_id, []):
        if ts < window_start:
            continue
        if et != sample_event_type:
            continue
        if same_field and data.get(same_field) != sample_key:
            continue
        count += 1
    return count >= threshold["count_in_window"]


def evaluate(org_id: UUID, event_type: str, data: dict, rules: list[dict]) -> dict | None:
    """Returns the first matching rule (as {"name", "effect",
    "severity"}) or None. First-match-wins because rules are loaded
    sorted by name - reproducible tiebreak."""
    now = datetime.now(UTC)
    for rule in rules:
        rule_body = rule.get("rule") or {}
        if not _matches_match_clause(event_type, data, rule_body.get("match", {})):
            continue
        if not _threshold_met(org_id, rule_body, event_type, data, now):
            continue
        return {
            "name": rule.get("name", "unnamed"),
            "effect": rule.get("effect", "alert"),
            "severity": rule.get("severity", "warning"),
        }
    return None


def on_event_impl(event_type: str, data: dict) -> None:
    """Buffers the event, runs every enabled policy for the org, and
    publishes SECURITY_ANOMALY_DETECTED when a rule fires."""
    org_id_raw = data.get("org_id")
    if not org_id_raw:
        return
    try:
        org_id = UUID(str(org_id_raw))
    except (ValueError, TypeError):
        return

    record_event(org_id, event_type, data)

    from backend.security.repository import PolicyRepository

    try:
        rules = PolicyRepository().list_enabled(org_id)
    except Exception as exc:
        logger.error("Failed to load policies for %s: %s", org_id, exc)
        return

    hit = evaluate(org_id, event_type, data, rules)
    if hit is None:
        return

    EventBus().publish(
        SECURITY_ANOMALY_DETECTED,
        {
            "org_id": str(org_id),
            "rule": hit["name"],
            "effect": hit["effect"],
            "severity": hit["severity"],
            "triggering_event": event_type,
            "triggering_data": data,
        },
    )
