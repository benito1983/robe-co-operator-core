# backend/sentinel/routes.py
#
# RoBe Sentinel API (Active Defense mit Attack Intelligence).
# Contract: see tests/test_sentinel.py header.
#
# Zwei Gates, wie ueberall auf der Plattform: Lesen braucht
# can_view_senteln (korrekt: can_view_sentinel), alles was Ereignisse
# einspeist, Incidents schliesst, Regeln lernt oder Sperren setzt,
# braucht can_manage_sentinel. Alle Mutationen landen ueber das
# Repository in der signierten audit_log-Kette.
#
# Es gibt hier bewusst KEINE Route, die etwas ausserhalb dieser Org
# bewirkt: keine IPs von Dritten abfragen, nichts an Feeds senden,
# keine Gegenmassnahmen gegen fremde Hosts. Siehe backend/sentinel/
# __init__.py fuer die Grenze und TestDefensiveBoundary fuer den Test.
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, model_validator

from backend.core.api_deps import require_module_and_permission
from backend.core.schemas import BaseRequestModel
from backend.sentinel import classification
from backend.sentinel.canary import generate_trigger_value
from backend.sentinel.repository import (
    RETENTION_DAYS,
    AlreadyClosed,
    DuplicateBan,
    DuplicateCanary,
    IncidentNotFound,
    SentinelRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sentinel", tags=["sentinel"])

_repo = SentinelRepository()

_gate_view = require_module_and_permission("sentinel", "can_view_sentinel")
_gate_manage = require_module_and_permission("sentinel", "can_manage_sentinel")


def _org_id(claims: dict) -> UUID:
    return UUID(claims["org_id"])


def _user_id(claims: dict) -> UUID:
    return UUID(claims["user_id"])


# ── Schemas ───────────────────────────────────────────────────────


class IngestEventRequest(BaseRequestModel):
    event_type: str = Field(..., min_length=1, max_length=200)
    source_value: str = Field(..., min_length=1, max_length=255)
    source_type: Literal["ip", "user"] = "ip"
    http_status: int | None = Field(None, ge=100, le=599)
    path: str | None = Field(None, max_length=2048)
    request_id: str | None = Field(None, max_length=64)
    user_agent: str | None = Field(None, max_length=512)
    ip: str | None = Field(None, max_length=45)
    details: dict[str, Any] | None = None


class CloseIncidentRequest(BaseRequestModel):
    note: str = Field("", max_length=2000)


class LearnRequest(BaseRequestModel):
    effect: Literal["alert", "block", "freeze"] = "alert"
    severity: Literal["info", "warning", "critical"] = "warning"


class CreateBanRequest(BaseRequestModel):
    subject_type: Literal["ip", "user"]
    subject: str = Field(..., min_length=1, max_length=255)
    reason: str = Field("", max_length=500)
    incident_id: UUID | None = None
    ttl_minutes: int | None = Field(
        None,
        ge=1,
        le=43200,  # max. 30 Tage - laenger braucht eine Sperre nicht
    )


class CreateCanaryRequest(BaseRequestModel):
    """Neue Falle anlegen.

    trigger_value ist bewusst OPTIONAL: fehlt er, erzeugt der Server
    einen zufaelligen Wert (siehe canary.generate_trigger_value) -
    eine Falle, die der Client frei definieren koennte, waere mit
    etwas Recherche vorhersehbar."""

    kind: Literal["honeypot_user", "honeypot_path"]
    label: str = Field(..., min_length=1, max_length=200)
    trigger_value: str | None = Field(None, max_length=512)

    @model_validator(mode="after")
    def _check_conditional(self) -> CreateCanaryRequest:
        if not self.label.strip():
            raise ValueError("label darf nicht nur aus Leerzeichen bestehen")
        if self.kind == "honeypot_path":
            if not self.trigger_value:
                raise ValueError(
                    "honeypot_path braucht trigger_value - ein Pfad-Koeder "
                    "muss exakt den Pfad nennen, den es zu legen gilt"
                )
            if not self.trigger_value.startswith("/"):
                raise ValueError("trigger_value muss mit / beginnen")
        return self


# ── Dashboard + Katalog ───────────────────────────────────────────


def _housekeeping(org_id: UUID) -> None:
    """Lazy Aufraeumarbeit beim Lesen (tests/test_sentinel_autonomy.py
    ::TestHousekeeping).

    Es gibt in dieser Plattform keinen Scheduler-Thread - deshalb
    passiert das, wo ohnehin auf die Daten zugegriffen wird:
      - alte Roh-Events verlieren nach RETENTION_DAYS ihren Zweck
        (DSGVO), Incidents bleiben als forensischer Beleg stehen
      - Incidents, die STALE_AFTER_DAYS ruhen, schliessen sich selbst
        statt ewig "open" in der Liste zu stehen.

    Fehler hier duerfen die Antwort nie verhindern - deshalb nur
    loggen. Die Tests sehen trotzdem, ob wirklich aufgeraumt wurde."""
    try:
        _repo.purge_old(org_id, keep_days=RETENTION_DAYS)
        _repo.close_stale_incidents(org_id)
    except Exception:
        logger.warning("Sentinel-Housekeeping fehlgeschlagen", exc_info=True)


@router.get("/overview")
def overview(claims: dict = Depends(_gate_view)):
    _housekeeping(_org_id(claims))
    return _repo.overview(_org_id(claims))


@router.get("/techniques")
def techniques(claims: dict = Depends(_gate_view)):
    """MITRE ATT&CK Katalog - dieselbe Quelle, die classify() benutzt."""
    return {"items": classification.catalogue()}


# ── Telemetrie ────────────────────────────────────────────────────


@router.get("/events")
def list_events(
    source_value: str | None = Query(None, max_length=255),
    technique: str | None = Query(None, max_length=64),
    since: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    claims: dict = Depends(_gate_view),
):
    items, total = _repo.list_events(
        _org_id(claims),
        source_value=source_value,
        technique=technique,
        since=since,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": total}


@router.post("/events", status_code=201)
def ingest_event(body: IngestEventRequest, claims: dict = Depends(_gate_manage)):
    """Ereignis einspeisen UND sofort korrelieren. Ab der Score-Schwelle
    entsteht (oder wächst) ein Incident fuer diese Quelle."""
    return _repo.record_event(
        _org_id(claims),
        event_type=body.event_type,
        source_value=body.source_value,
        source_type=body.source_type,
        http_status=body.http_status,
        path=body.path,
        request_id=body.request_id,
        user_agent=body.user_agent,
        ip=body.ip,
        details=body.details,
    )


# ── Incidents ─────────────────────────────────────────────────────


@router.get("/incidents")
def list_incidents(
    status: Literal["open", "closed"] | None = Query(None),
    severity: Literal["info", "warning", "critical"] | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    claims: dict = Depends(_gate_view),
):
    _housekeeping(_org_id(claims))
    items, total = _repo.list_incidents(
        _org_id(claims), status=status, severity=severity, limit=limit, offset=offset
    )
    return {"items": items, "total": total}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: UUID, claims: dict = Depends(_gate_view)):
    incident = _repo.get_incident(_org_id(claims), incident_id)
    if incident is None:
        # Gleiche Antwort fuer unbekannt UND fremd - kein Tenant-Oracle.
        raise HTTPException(404, "Incident nicht gefunden")
    return incident


@router.get("/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: UUID, claims: dict = Depends(_gate_view)):
    """Forensische Rekonstruktion: alle Ereignisse der Quelle um den
    Vorfall herum, chronologisch, mit Verhaltensprofil."""
    try:
        return _repo.timeline(_org_id(claims), incident_id)
    except IncidentNotFound:
        raise HTTPException(404, "Incident nicht gefunden")


@router.post("/incidents/{incident_id}/close")
def close_incident(
    incident_id: UUID, body: CloseIncidentRequest, claims: dict = Depends(_gate_manage)
):
    try:
        return _repo.close_incident(_org_id(claims), incident_id, _user_id(claims), note=body.note)
    except IncidentNotFound:
        raise HTTPException(404, "Incident nicht gefunden")
    except AlreadyClosed:
        raise HTTPException(409, "Incident ist bereits geschlossen")


@router.post("/incidents/{incident_id}/learn")
def learn_from_incident(
    incident_id: UUID, body: LearnRequest, claims: dict = Depends(_gate_manage)
):
    """DER LERNSCHRITT: aus dem beobachteten Muster wird eine
    security_policies-Regel - dieselbe Tabelle, die anomaly.py bereits
    auswertet. Ab jetzt erkennt RoBe diesen Angriff frueher, ohne dass
    ein Mensch die Regel tippen musste."""
    org_id = _org_id(claims)
    incident = _repo.get_incident(org_id, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident nicht gefunden")
    if incident.get("learned_policy_id"):
        raise HTTPException(409, "Aus diesem Incident wurde bereits gelernt")
    if not incident.get("technique"):
        raise HTTPException(
            422,
            "Incident hat keine klassifizierte Technik - daraus liesse "
            "sich keine aussagekraeftige Regel bauen",
        )

    rule = classification.propose_rule(
        incident["technique"], incident.get("pattern") or {}, incident["source_type"]
    )

    from backend.security.repository import PolicyRepository

    policy_name = f"sentinel_{incident['technique']}_{incident_id.hex[:8]}"
    try:
        policy = PolicyRepository().create(org_id, policy_name, rule, body.effect, body.severity)
    except Exception as exc:  # Namenskonflikt sauber als 409 statt 500
        if "uq" in str(exc).lower() or "unique" in str(exc).lower():
            raise HTTPException(409, "Eine Regel mit diesem Namen existiert bereits") from exc
        raise

    _repo.mark_learned(org_id, incident_id, policy["id"], _user_id(claims), rule)
    return {
        "policy": policy,
        "technique": incident["technique"],
        "mitre_id": incident["mitre_id"],
    }


# ── Sperren (einzige aktive Massnahme, immer reversibel) ──────────


@router.get("/bans")
def list_bans(
    active_only: bool = Query(False),
    limit: int = Query(200, ge=1, le=500),
    claims: dict = Depends(_gate_view),
):
    items, total = _repo.list_bans(_org_id(claims), active_only=active_only, limit=limit)
    return {"items": items, "total": total}


@router.post("/bans", status_code=201)
def create_ban(body: CreateBanRequest, claims: dict = Depends(_gate_manage)):
    try:
        return _repo.create_ban(
            _org_id(claims),
            subject_type=body.subject_type,
            subject=body.subject,
            reason=body.reason,
            incident_id=body.incident_id,
            created_by=_user_id(claims),
            ttl_minutes=body.ttl_minutes,
        )
    except DuplicateBan:
        raise HTTPException(409, "Fuer diese Quelle gibt es bereits eine aktive Sperre")
    except IncidentNotFound:
        raise HTTPException(404, "Incident nicht gefunden")


@router.delete("/bans/{ban_id}")
def lift_ban(
    ban_id: UUID,
    note: str = Query("", max_length=500),
    claims: dict = Depends(_gate_manage),
):
    """Undo: Sperre aufheben. Die Zeile bleibt als Beleg stehen - nur
    active=false, damit die Quelle wieder darf."""
    ban = _repo.lift_ban(_org_id(claims), ban_id, _user_id(claims), note=note)
    if ban is None:
        raise HTTPException(404, "Sperre nicht gefunden")
    return {"lifted": True, "ban": ban}


# ── Canary Assets (migration 067_canary_assets.sql) ───────────────
# Vertrag: tests/test_canary.py


@router.get("/canaries")
def list_canaries(claims: dict = Depends(_gate_view)):
    return {"items": _repo.list_canaries(_org_id(claims))}


@router.post("/canaries", status_code=201)
def create_canary(body: CreateCanaryRequest, claims: dict = Depends(_gate_manage)):
    trigger_value = body.trigger_value or generate_trigger_value(body.kind)
    try:
        return _repo.create_canary(
            _org_id(claims),
            kind=body.kind,
            label=body.label,
            trigger_value=trigger_value,
            created_by=_user_id(claims),
        )
    except DuplicateCanary:
        raise HTTPException(409, "Fuer diese Quelle gibt es bereits eine Falle")


@router.get("/canaries/{canary_id}")
def get_canary(canary_id: UUID, claims: dict = Depends(_gate_view)):
    canary = _repo.get_canary(_org_id(claims), canary_id)
    if canary is None:
        raise HTTPException(404, "Canary nicht gefunden")
    return canary


@router.post("/canaries/{canary_id}/disable")
def disable_canary(canary_id: UUID, claims: dict = Depends(_gate_manage)):
    """Falle abschalten - der Koeder-Verlauf bleibt erhalten, damit
    die forensische Frage "wann, von wem, wie oft" beantwortbar ist."""
    canary = _repo.set_canary_active(_org_id(claims), canary_id, False, _user_id(claims))
    if canary is None:
        raise HTTPException(404, "Canary nicht gefunden")
    return canary


@router.post("/canaries/{canary_id}/enable")
def enable_canary(canary_id: UUID, claims: dict = Depends(_gate_manage)):
    canary = _repo.set_canary_active(_org_id(claims), canary_id, True, _user_id(claims))
    if canary is None:
        raise HTTPException(404, "Canary nicht gefunden")
    return canary


@router.delete("/canaries/{canary_id}", status_code=204)
def delete_canary(canary_id: UUID, claims: dict = Depends(_gate_manage)):
    """Falle entfernen. Events und Incidents, die sie ausloeste, bleiben
    bestehen - ein Beweis verfaellt nicht mit der Falle."""
    if not _repo.delete_canary(_org_id(claims), canary_id, _user_id(claims)):
        raise HTTPException(404, "Canary nicht gefunden")
    return None
