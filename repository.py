# backend/sentinel/repository.py
#
# Datenzugriff fuer RoBe Sentinel (migration 066_sentinel.sql).
#
# Bewusst synchrones psycopg2 ueber backend.core.repository.connection -
# dieselbe Konvention wie jedes andere Modul. Alle Queries sind
# parameterisiert (kein String-Einbau von Werten) und tragen org_id in
# JEDEM WHERE - Multi-Tenant-Isolation sitzt in der Query, nicht in der
# Hoffnung des Aufrufers.
#
# Aktive Massnahmen in diesem Modul: ausschliesslich Sperren AUF EIGENER
# INFRASTRUKTUR (sentinel_bans) und Regeln fuer den bestehenden
# Rule-Engine (security_policies). Kein Gegenangriff, kein Zugriff auf
# fremde Systeme, keine Datenuebermittlung an Dritte.
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg2
import psycopg2.extras

from backend.core.audit import log_action
from backend.core.repository import connection
from backend.sentinel.classification import (
    CORRELATION_WINDOW_SECONDS,
    CRITICAL_SCORE,
    INCIDENT_SCORE_THRESHOLD,
    build_summary,
    classify,
    detect_pattern,
    dominant_technique,
    propose_rule,
    score_events,
    severity_for_score,
)

_REAL = psycopg2.extras.RealDictCursor

# ── Autonome Wirkung (tests/test_sentinel_autonomy.py) ─────────────
#
# VIER Konstanten, die festlegen, WAS Sentinel ohne Menschen tut.
#: Wirkung der automatisch erzeugten Regeln. IMMER alert - eine
#: automatische Zugangssperre kann legitime Nutzer treffen und bleibt
#: eine menschliche Entscheidung (harter Test: TestAutonomyBoundary).
AUTO_LEARN_EFFECT = "alert"
#: Deckel fuer Auto-Learn pro Org. Ohne ihn wuerde ein Regen
#: kritischer Incidents eine Regelflut erzeugen, nach der niemand
#: mehr uebersieht, was wirklich gilt.
AUTO_LEARN_LIMIT = 25
#: Incidents, die so lange ohne neues Event ruhen, schliessen sich
#: selbst (Lazy - es gibt keinen Scheduler-Thread in dieser Plattform).
STALE_AFTER_DAYS = 7
#: Roh-Events aelter als das gelten als ueberfluessig und werden beim
#: naechsten Housekeeping entfernt. Incidents bleiben immer erhalten -
#: der Beweis laeuft nicht ab, nur die Telemetrie.
RETENTION_DAYS = 30


class DuplicateBan(Exception):
    """Fuer diese Quelle gibt es bereits eine aktive Sperre."""


class DuplicateCanary(Exception):
    """Dieser Koeder existiert in dieser Org bereits (zweimal dieselbe
    Falle wuerde sich die Zuordnung verfaelschen)."""


class IncidentNotFound(Exception):
    """Incident existiert in dieser Org nicht (auch nicht bei fremder
    Org - derselbe Fehler wie fuer unbekannt, kein Tenant-Oracle)."""


class AlreadyClosed(Exception):
    """Incident war bereits geschlossen - doppeltes Schliessen verboten."""


class SentinelRepository:
    def __init__(self) -> None:
        # Als Attribut, damit Tests den Kontextmanager direkt nutzen
        # koennen (repo._connection()) statt eines Imports nachzubauen.
        self._connection = connection

    # ── Events (Roh-Telemetrie + Korrelation) ────────────────────────

    def record_event(
        self,
        org_id: UUID,
        *,
        event_type: str,
        source_value: str,
        source_type: str = "ip",
        http_status: int | None = None,
        path: str | None = None,
        request_id: str | None = None,
        user_agent: str | None = None,
        ip: str | None = None,
        user_id: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Speichert ein Ereignis UND korreliert es sofort - eine
        Transaktion, damit kein Event ohne Pruefung in der DB stehen
        bleibt. Gibt {"event", "incident"} zurueck (incident kann None
        sein, wenn die Schwelle noch nicht erreicht ist)."""
        observation = classify(event_type, {"path": path or "", "details": details or {}})

        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                event = self._insert_event(
                    cur,
                    org_id,
                    event_type=event_type,
                    source_value=source_value,
                    source_type=source_type,
                    http_status=http_status,
                    path=path,
                    request_id=request_id,
                    user_agent=user_agent,
                    ip=ip,
                    user_id=user_id,
                    details=details,
                    observation=observation,
                )
                incident = self._correlate(cur, org_id, source_type, source_value)
                if incident is not None:
                    # Autonomer Lernschritt in DERSelben Transaktion:
                    # der Incident und die daraus erzeugte Regel
                    # entstehen gemeinsam oder gar nicht.
                    self._auto_learn(cur, org_id, incident)
        return {"event": event, "incident": incident}

    def _auto_learn(self, cur, org_id: UUID, incident: dict[str, Any]) -> dict[str, Any] | None:
        """Kritische Incidents lernen SELBST (tests/
        test_sentinel_autonomy.py::TestAutoLearn).

        Vier Stellschrauben:
          - nur ab CRITICAL_SCORE (darunter lohnt eine Regel nicht)
          - nur mit klassifizierter Technik (sonst keine Aussage)
          - nur EINMAL pro Incident (learned_policy_id gesetzt)
          - nur bis AUTO_LEARN_LIMIT pro Org (Regelsturm-Schutz)

        Wirkung: AUTO_LEARN_EFFECT (alert) - nie block/freeze.
        Der Name entspricht dem manuellen learn-Endpunkt, damit es
        pro Incident IMMER nur eine Regel gibt (Doppel-Regel wuerde
        die anomaly.py doppelt zaehlen)."""
        technique = incident.get("technique")
        if not technique or incident.get("learned_policy_id"):
            return None
        score = int(incident.get("score") or 0)
        if score < CRITICAL_SCORE:
            return None

        incident_id = UUID(str(incident["id"]))
        # cursor_factory=RealDictCursor: Zeilen sind Dicts, keine Tupel.
        cur.execute(
            """
            SELECT count(*) AS cnt FROM sentinel_incidents
             WHERE org_id = %s AND learned_policy_id IS NOT NULL
            """,
            (str(org_id),),
        )
        if int(cur.fetchone()["cnt"]) >= AUTO_LEARN_LIMIT:
            return None

        rule = propose_rule(
            technique,
            incident.get("pattern") or {},
            str(incident.get("source_type") or "ip"),
        )
        policy_name = f"sentinel_{technique}_{incident_id.hex[:8]}"
        # Eigener Cursor statt PolicyRepository: dieselbe Transaktion
        # wie der Incident, damit beides nie auseinanderlaeuft.
        cur.execute(
            """
            INSERT INTO security_policies (org_id, name, rule, effect, severity)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                str(org_id),
                policy_name,
                psycopg2.extras.Json(rule),
                AUTO_LEARN_EFFECT,
                severity_for_score(score),
            ),
        )
        policy_id = UUID(str(cur.fetchone()["id"]))
        cur.execute(
            """
            UPDATE sentinel_incidents
               SET learned_policy_id = %s, updated_at = now()
             WHERE org_id = %s AND id = %s
            """,
            (str(policy_id), str(org_id), str(incident_id)),
        )
        log_action(
            cur,
            org_id,
            None,  # kein Mensch - automatischer Lernschritt
            "sentinel",
            "sentinel_incident",
            incident_id,
            "auto_learn",
            {"policy_id": str(policy_id), "rule": rule, "effect": AUTO_LEARN_EFFECT},
        )
        # Der Caller gibt dieses Dict an die API zurueck - er darf nach
        # soeben erzeugter Regel nicht mehr "keine Regel" behaupten.
        # (Der RETURNING-Stamm kam VOR diesem Update.)
        incident["learned_policy_id"] = policy_id
        return {"policy_id": policy_id, "name": policy_name}

    def close_stale_incidents(self, org_id: UUID) -> int:
        """Schliesst ruhende Incidents (Lazy, beim naechsten Listen).

        Es gibt keinen Scheduler-Thread in dieser Plattform - deshalb
        passiert die Aufraeumarbeit dort, wo sowieso auf die Daten
        zugegriffen wird. closed_by bleibt NULL: kein Mensch hat das
        entschieden, und die Spalte soll nicht luegen."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    UPDATE sentinel_incidents
                       SET status = 'closed',
                           closed_at = now(),
                           close_note = %s,
                           updated_at = now()
                     WHERE org_id = %s
                       AND status = 'open'
                       AND last_seen_at < now() - make_interval(days => %s)
                    """,
                    (
                        f"automatisch geschlossen: {STALE_AFTER_DAYS} Tage ohne neues Ereignis",
                        str(org_id),
                        STALE_AFTER_DAYS,
                    ),
                )
                return int(cur.rowcount or 0)

    def _insert_event(
        self,
        cur,
        org_id: UUID,
        *,
        event_type: str,
        source_value: str,
        source_type: str,
        http_status: int | None,
        path: str | None,
        request_id: str | None,
        user_agent: str | None,
        ip: str | None,
        user_id: UUID | None,
        details: dict[str, Any] | None,
        observation: dict[str, Any] | None,
    ) -> dict[str, Any]:
        cur.execute(
            """
            INSERT INTO sentinel_events (
                org_id, source_type, source_value, event_type, http_status,
                path, request_id, user_agent, ip, user_id, details,
                technique, confidence
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, org_id, occurred_at, source_type, source_value,
                      event_type, http_status, path, request_id, user_agent,
                      ip, user_id, details, technique, confidence
            """,
            (
                str(org_id),
                source_type,
                source_value,
                event_type,
                http_status,
                path,
                request_id,
                user_agent,
                ip,
                str(user_id) if user_id else None,
                psycopg2.extras.Json(details or {}),
                (observation or {}).get("technique"),
                (observation or {}).get("confidence"),
            ),
        )
        return cur.fetchone()

    def _events_in_window(
        self, cur, org_id: UUID, source_value: str, window_seconds: int
    ) -> list[dict[str, Any]]:
        cur.execute(
            """
            SELECT id, occurred_at, source_type, source_value, event_type,
                   http_status, path, user_agent, ip, user_id, details,
                   technique, confidence
            FROM sentinel_events
            WHERE org_id = %s AND source_value = %s
              AND occurred_at >= now() - make_interval(secs => %s)
            ORDER BY occurred_at ASC
            """,
            (str(org_id), source_value, int(window_seconds)),
        )
        return list(cur.fetchall())

    def _correlate(
        self, cur, org_id: UUID, source_type: str, source_value: str
    ) -> dict[str, Any] | None:
        """Korrelation: Score ueber das Fenster, und ab der Schwelle ein
        Incident (offen, pro Quelle genau einer)."""
        events = self._events_in_window(cur, org_id, source_value, CORRELATION_WINDOW_SECONDS)
        score = score_events(events)
        if score < INCIDENT_SCORE_THRESHOLD:
            return None

        pattern = detect_pattern(events, CORRELATION_WINDOW_SECONDS)
        technique = dominant_technique(pattern) or (events[-1].get("technique") if events else None)
        entry_tech = technique
        mitre_id = None
        if entry_tech:
            from backend.sentinel.classification import TECHNIQUES

            mitre_id = TECHNIQUES[entry_tech]["mitre_id"]
        title, summary = build_summary(technique, score, pattern, source_value)
        severity = severity_for_score(score)
        first_seen = min(e["occurred_at"] for e in events)
        last_seen = max(e["occurred_at"] for e in events)

        cur.execute(
            """
            INSERT INTO sentinel_incidents (
                org_id, source_type, source_value, severity, status, score,
                technique, mitre_id, title, summary, pattern, behavior,
                first_seen_at, last_seen_at, event_count
            ) VALUES (%s, %s, %s, %s, 'open', %s, %s, %s, %s, %s, %s, %s,
                      %s, %s, %s)
            ON CONFLICT (org_id, source_value) WHERE status = 'open'
            DO UPDATE SET
                score = GREATEST(sentinel_incidents.score, EXCLUDED.score),
                severity = EXCLUDED.severity,
                technique = EXCLUDED.technique,
                mitre_id = EXCLUDED.mitre_id,
                title = EXCLUDED.title,
                summary = EXCLUDED.summary,
                pattern = EXCLUDED.pattern,
                behavior = EXCLUDED.behavior,
                event_count = EXCLUDED.event_count,
                first_seen_at = LEAST(sentinel_incidents.first_seen_at,
                                      EXCLUDED.first_seen_at),
                last_seen_at = GREATEST(sentinel_incidents.last_seen_at,
                                        EXCLUDED.last_seen_at),
                updated_at = now()
            RETURNING *
            """,
            (
                str(org_id),
                source_type,
                source_value,
                severity,
                score,
                technique,
                mitre_id,
                title,
                summary,
                psycopg2.extras.Json(pattern),
                psycopg2.extras.Json(pattern),
                first_seen,
                last_seen,
                len(events),
            ),
        )
        return cur.fetchone()

    def list_events(
        self,
        org_id: UUID,
        *,
        source_value: str | None = None,
        technique: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses = ["org_id = %s"]
        params: list[Any] = [str(org_id)]
        if source_value:
            clauses.append("source_value = %s")
            params.append(source_value)
        if technique:
            clauses.append("technique = %s")
            params.append(technique)
        if since is not None:
            clauses.append("occurred_at >= %s")
            params.append(since)
        where = " AND ".join(clauses)
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(f"SELECT count(*) AS cnt FROM sentinel_events WHERE {where}", params)
                total = int(cur.fetchone()["cnt"])
                cur.execute(
                    f"""
                    SELECT id, org_id, occurred_at, source_type, source_value,
                           event_type, http_status, path, request_id,
                           user_agent, ip, user_id, details, technique, confidence
                    FROM sentinel_events
                    WHERE {where}
                    ORDER BY occurred_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    [*params, int(limit), int(offset)],
                )
                return list(cur.fetchall()), total

    def purge_old(self, org_id: UUID, keep_days: int = 30) -> int:
        """DSGVO-Reinigung: Telemetrie verliert nach dem Zweck ihre
        Aufbewahrung. Incidents bleiben erhalten (forensischer Beleg)."""
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM sentinel_events
                    WHERE org_id = %s AND occurred_at < now() - make_interval(days => %s)
                    """,
                    (str(org_id), int(keep_days)),
                )
                return int(cur.rowcount or 0)

    # ── Incidents ────────────────────────────────────────────────────

    def list_incidents(
        self,
        org_id: UUID,
        *,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses = ["org_id = %s"]
        params: list[Any] = [str(org_id)]
        if status:
            clauses.append("status = %s")
            params.append(status)
        if severity:
            clauses.append("severity = %s")
            params.append(severity)
        where = " AND ".join(clauses)
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(f"SELECT count(*) AS cnt FROM sentinel_incidents WHERE {where}", params)
                total = int(cur.fetchone()["cnt"])
                cur.execute(
                    f"""
                    SELECT * FROM sentinel_incidents
                    WHERE {where}
                    ORDER BY last_seen_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    [*params, int(limit), int(offset)],
                )
                return list(cur.fetchall()), total

    def get_incident(self, org_id: UUID, incident_id: UUID) -> dict[str, Any] | None:
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    "SELECT * FROM sentinel_incidents WHERE org_id = %s AND id = %s",
                    (str(org_id), str(incident_id)),
                )
                return cur.fetchone()

    def close_incident(
        self, org_id: UUID, incident_id: UUID, user_id: UUID, note: str = ""
    ) -> dict[str, Any]:
        """Schliesst mit Audit-Eintrag in derselben Transaktion - die
        Entscheidung des Menschen und ihre Begruendung duerfen nie
        getrennt voneinander gespeichert werden."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    "SELECT * FROM sentinel_incidents WHERE org_id = %s AND id = %s",
                    (str(org_id), str(incident_id)),
                )
                incident = cur.fetchone()
                if incident is None:
                    raise IncidentNotFound(str(incident_id))
                if incident["status"] == "closed":
                    raise AlreadyClosed(str(incident_id))
                cur.execute(
                    """
                    UPDATE sentinel_incidents
                    SET status = 'closed', closed_at = now(), closed_by = %s,
                        close_note = %s, updated_at = now()
                    WHERE org_id = %s AND id = %s AND status = 'open'
                    RETURNING *
                    """,
                    (str(user_id), note, str(org_id), str(incident_id)),
                )
                closed = cur.fetchone()
                log_action(
                    cur,
                    org_id,
                    user_id,
                    "sentinel",
                    "sentinel_incident",
                    incident_id,
                    "close",
                    {"note": note, "score": incident["score"]},
                )
                return closed

    def mark_learned(
        self, org_id: UUID, incident_id: UUID, policy_id: UUID, user_id: UUID, rule: dict
    ) -> dict[str, Any]:
        """Vermerkt die aus diesem Incident ERZEGTE Regel - der Beleg
        der Lernschleife, dauerhaft mit dem Vorfall verknuepft."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    UPDATE sentinel_incidents
                    SET learned_policy_id = %s, updated_at = now()
                    WHERE org_id = %s AND id = %s
                    RETURNING *
                    """,
                    (str(policy_id), str(org_id), str(incident_id)),
                )
                updated = cur.fetchone()
                if updated is None:
                    raise IncidentNotFound(str(incident_id))
                log_action(
                    cur,
                    org_id,
                    user_id,
                    "sentinel",
                    "sentinel_incident",
                    incident_id,
                    "learn",
                    {"policy_id": str(policy_id), "rule": rule},
                )
                return updated

    def timeline(self, org_id: UUID, incident_id: UUID, pad_seconds: int = 60) -> dict[str, Any]:
        """Forensische Rekonstruktion: alle Ereignisse der Quelle um den
        Vorfall herum, chronologisch, plus das Verhaltensprofil."""
        incident = self.get_incident(org_id, incident_id)
        if incident is None:
            raise IncidentNotFound(str(incident_id))

        window_from = incident["first_seen_at"] - timedelta(seconds=pad_seconds)
        window_to = incident["last_seen_at"] + timedelta(seconds=pad_seconds)
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    SELECT id, occurred_at, event_type, http_status, path,
                           request_id, user_agent, ip, user_id, details,
                           technique, confidence, source_type, source_value
                    FROM sentinel_events
                    WHERE org_id = %s AND source_value = %s
                      AND occurred_at >= %s AND occurred_at <= %s
                    ORDER BY occurred_at ASC
                    """,
                    (str(org_id), incident["source_value"], window_from, window_to),
                )
                events = list(cur.fetchall())

        return {
            "incident": incident,
            "events": events,
            "window": {"from": window_from, "to": window_to},
            "behavior": detect_pattern(events, CORRELATION_WINDOW_SECONDS),
        }

    # ── Sperren (die einzige aktive Massnahme) ──────────────────────

    def list_bans(
        self, org_id: UUID, *, active_only: bool = False, limit: int = 200
    ) -> tuple[list[dict[str, Any]], int]:
        clauses = ["b.org_id = %s"]
        params: list[Any] = [str(org_id)]
        if active_only:
            clauses.append("b.active = true")
            clauses.append("(b.expires_at IS NULL OR b.expires_at > now())")
        where = " AND ".join(clauses)
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(f"SELECT count(*) AS cnt FROM sentinel_bans b WHERE {where}", params)
                total = int(cur.fetchone()["cnt"])
                cur.execute(
                    f"""
                    SELECT b.* FROM sentinel_bans b
                    WHERE {where}
                    ORDER BY b.created_at DESC
                    LIMIT %s
                    """,
                    [*params, int(limit)],
                )
                return list(cur.fetchall()), total

    def list_active_bans(self, org_id: UUID) -> list[dict[str, Any]]:
        """Nur GUELTIGE Sperren - abgelaufene zaehlen nicht mehr, auch
        wenn ihre Zeile noch existiert (Befristung ohne Aufraeumen)."""
        items, _ = self.list_bans(org_id, active_only=True, limit=1000)
        return items

    def get_incident_for_org(self, org_id: UUID, incident_id: UUID) -> dict[str, Any] | None:
        return self.get_incident(org_id, incident_id)

    def create_ban(
        self,
        org_id: UUID,
        *,
        subject_type: str,
        subject: str,
        reason: str = "",
        incident_id: UUID | None = None,
        created_by: UUID | None = None,
        ttl_minutes: int | None = None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                if incident_id is not None:
                    cur.execute(
                        "SELECT 1 FROM sentinel_incidents WHERE org_id = %s AND id = %s",
                        (str(org_id), str(incident_id)),
                    )
                    if cur.fetchone() is None:
                        raise IncidentNotFound(str(incident_id))
                expires_at = (
                    datetime.now(UTC) + timedelta(minutes=int(ttl_minutes)) if ttl_minutes else None
                )
                try:
                    cur.execute(
                        """
                        INSERT INTO sentinel_bans (
                            org_id, subject_type, subject, reason, incident_id,
                            created_by, expires_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING *
                        """,
                        (
                            str(org_id),
                            subject_type,
                            subject,
                            reason,
                            str(incident_id) if incident_id else None,
                            str(created_by) if created_by else None,
                            expires_at,
                        ),
                    )
                except psycopg2.errors.UniqueViolation:
                    raise DuplicateBan(f"{subject_type}:{subject}")
                ban = cur.fetchone()
                log_action(
                    cur,
                    org_id,
                    created_by,
                    "sentinel",
                    "sentinel_ban",
                    UUID(ban["id"]),
                    "create",
                    {
                        "subject_type": subject_type,
                        "subject": subject,
                        "reason": reason,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                    },
                )
        # Erst NACH dem Commit invalidieren - sonst kann eine parallele
        # Anfrage den alten Stand neu laden und ihn als gueltig cachen.
        # SOFORT wirksam: die naechste Anfrage sieht die Sperre.
        from backend.sentinel import enforcement

        enforcement.invalidate_cache()
        return ban

    def lift_ban(
        self, org_id: UUID, ban_id: UUID, user_id: UUID, note: str = ""
    ) -> dict[str, Any] | None:
        """Undo: Sperre aufheben (bleibt als Beleg in der DB stehen).
        None, wenn es sie in dieser Org nicht (mehr) gibt."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    UPDATE sentinel_bans
                    SET active = false, lifted_at = now(), lifted_by = %s,
                        lift_note = %s
                    WHERE org_id = %s AND id = %s AND active = true
                    RETURNING *
                    """,
                    (str(user_id), note, str(org_id), str(ban_id)),
                )
                ban = cur.fetchone()
                if ban is None:
                    return None
                log_action(
                    cur,
                    org_id,
                    user_id,
                    "sentinel",
                    "sentinel_ban",
                    ban_id,
                    "lift",
                    {"note": note, "subject": ban["subject"]},
                )
        from backend.sentinel import enforcement

        enforcement.invalidate_cache()
        return ban

    def is_banned(self, org_id: UUID, subject_type: str, subject: str) -> bool:
        """Pruefung fuer den Request-Pfad (Middleware): ist diese Quelle
        aktuell gesperrt? True NUR fuer gueltige, nicht abgelaufene
        Sperren auf EIGENER Infrastruktur."""
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM sentinel_bans
                    WHERE org_id = %s AND subject_type = %s AND subject = %s
                      AND active = true
                      AND (expires_at IS NULL OR expires_at > now())
                    LIMIT 1
                    """,
                    (str(org_id), subject_type, subject),
                )
                return cur.fetchone() is not None

    # ── Dashboard ────────────────────────────────────────────────────

    def overview(self, org_id: UUID) -> dict[str, Any]:
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    SELECT
                        count(*) FILTER (WHERE status = 'open') AS open_incidents,
                        count(*) FILTER (WHERE status = 'open'
                                             AND severity = 'critical') AS critical_incidents
                    FROM sentinel_incidents
                    WHERE org_id = %s
                    """,
                    (str(org_id),),
                )
                incidents = cur.fetchone()

                cur.execute(
                    """
                    SELECT count(*) AS cnt FROM sentinel_bans
                    WHERE org_id = %s AND active = true
                      AND (expires_at IS NULL OR expires_at > now())
                    """,
                    (str(org_id),),
                )
                active_bans = int(cur.fetchone()["cnt"])

                cur.execute(
                    """
                    SELECT count(*) AS cnt FROM sentinel_events
                    WHERE org_id = %s AND occurred_at >= now() - interval '24 hours'
                    """,
                    (str(org_id),),
                )
                events_24h = int(cur.fetchone()["cnt"])

                cur.execute(
                    """
                    SELECT technique, count(*) AS cnt
                    FROM sentinel_events
                    WHERE org_id = %s AND technique IS NOT NULL
                      AND occurred_at >= now() - interval '7 days'
                    GROUP BY technique
                    ORDER BY cnt DESC
                    LIMIT 5
                    """,
                    (str(org_id),),
                )
                top = [
                    {"technique": row["technique"], "count": int(row["cnt"])}
                    for row in cur.fetchall()
                ]

        return {
            "open_incidents": int(incidents["open_incidents"] or 0),
            "critical_incidents": int(incidents["critical_incidents"] or 0),
            "active_bans": active_bans,
            "events_24h": events_24h,
            "top_techniques": top,
        }

    # ── Canary Assets (migration 067_canary_assets.sql) ─────────────
    #
    # Jede Anfrage traegt org_id in JEDEM WHERE - ausser
    # get_path_canaries(), der den Pfad-Ausloeser ohne Token-Zugriff
    # bedient (siehe backend/sentinel/canary.py).

    def list_canaries(self, org_id: UUID) -> list[dict[str, Any]]:
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    SELECT id, org_id, kind, label, trigger_value, active,
                           created_at, triggered_at, triggered_by, trigger_count
                      FROM canary_assets
                     WHERE org_id = %s
                     ORDER BY created_at DESC, id
                    """,
                    (str(org_id),),
                )
                return list(cur.fetchall())

    def create_canary(
        self,
        org_id: UUID,
        *,
        kind: str,
        label: str,
        trigger_value: str,
        created_by: UUID | None = None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                try:
                    cur.execute(
                        """
                        INSERT INTO canary_assets (
                            org_id, kind, label, trigger_value
                        ) VALUES (%s, %s, %s, %s)
                        RETURNING *
                        """,
                        (str(org_id), kind, label, trigger_value),
                    )
                except psycopg2.errors.UniqueViolation:
                    raise DuplicateCanary(f"{kind}:{trigger_value}") from None
                canary = cur.fetchone()
                log_action(
                    cur,
                    org_id,
                    created_by,
                    "sentinel",
                    "canary_asset",
                    UUID(canary["id"]),
                    "create",
                    {"kind": kind, "label": label, "trigger_value": trigger_value},
                )
                return canary

    def get_canary(self, org_id: UUID, canary_id: UUID) -> dict[str, Any] | None:
        """404 ist die einzige Antwort fuer fremde oder unbekannte
        IDs - kein Tenant-Oracle."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    SELECT id, org_id, kind, label, trigger_value, active,
                           created_at, triggered_at, triggered_by, trigger_count
                      FROM canary_assets
                     WHERE org_id = %s AND id = %s
                    """,
                    (str(org_id), str(canary_id)),
                )
                return cur.fetchone()

    def get_canary_by_trigger(
        self, org_id: UUID, kind: str, trigger_value: str
    ) -> dict[str, Any] | None:
        """Lookup im Anmeldungs-Pfad: genau eine aktive Falle, ein
        Treffer - Index canary_assets_user_active_idx."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    SELECT id, org_id, kind, label, trigger_value, active,
                           triggered_at, triggered_by, trigger_count
                      FROM canary_assets
                     WHERE org_id = %s AND kind = %s
                       AND trigger_value = %s AND active
                     LIMIT 1
                    """,
                    (str(org_id), kind, trigger_value),
                )
                return cur.fetchone()

    def get_path_canaries(self, trigger_value: str) -> list[dict[str, Any]]:
        """ALLE aktiven Pfad-Fallen mit diesem Pfad, ueber Orgs hinweg.

        Der Honeypot-Pfad laeuft ohne Token und kennt deshalb keine
        Org - fuer jede betroffene Org wird danach eigens ausgeloest.
        Index canary_assets_path_active_idx."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    SELECT org_id, kind, label, trigger_value
                      FROM canary_assets
                     WHERE kind = 'honeypot_path'
                       AND trigger_value = %s
                       AND active
                    """,
                    (trigger_value,),
                )
                return list(cur.fetchall())

    def set_canary_active(
        self, org_id: UUID, canary_id: UUID, active: bool, user_id: UUID | None
    ) -> dict[str, Any] | None:
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    UPDATE canary_assets
                       SET active = %s
                     WHERE org_id = %s AND id = %s
                    RETURNING id, org_id, kind, label, trigger_value, active,
                              created_at, triggered_at, triggered_by, trigger_count
                    """,
                    (bool(active), str(org_id), str(canary_id)),
                )
                canary = cur.fetchone()
                if canary is None:
                    return None
                log_action(
                    cur,
                    org_id,
                    user_id,
                    "sentinel",
                    "canary_asset",
                    UUID(canary["id"]),
                    "enable" if active else "disable",
                    {"active": bool(active)},
                )
                return canary

    def delete_canary(self, org_id: UUID, canary_id: UUID, user_id: UUID | None) -> bool:
        """Loescht die Falle - der Verlauf (Events/Incidents) bleibt
        davon unabhaengig bestehen."""
        with self._connection() as conn:
            with conn.cursor(cursor_factory=_REAL) as cur:
                cur.execute(
                    """
                    DELETE FROM canary_assets
                     WHERE org_id = %s AND id = %s
                    RETURNING id, kind, trigger_value
                    """,
                    (str(org_id), str(canary_id)),
                )
                deleted = cur.fetchone()
                if deleted is None:
                    return False
                log_action(
                    cur,
                    org_id,
                    user_id,
                    "sentinel",
                    "canary_asset",
                    UUID(deleted["id"]),
                    "delete",
                    {"kind": deleted["kind"], "trigger_value": deleted["trigger_value"]},
                )
                return True
