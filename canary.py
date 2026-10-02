"""Canary Assets - Koeder, die niemand legitimerweise anfasst.

Erster Baustein der RoBe Holo Shield Cyber-Resilienzschicht
(Nutzerentscheidung 2026-09-27: "Erkennen + sperren + forensische
Tiefenanalyse", nur eigene Telemetrie, KEIN hack back).

Die Philosophie dahinter: Nicht verhindern, dass ein Angreifer
jemandwann eindringt, sondern verhindern, dass ein Eindringen zu
einem ERFOLG wird. Ein Canary ist ein Asset mit reizvollem Namen, das
niemals legitimerweise gebraucht wird. Wer es anfasst, verraet sich
selbst - und das mit dem hoechstmoglichen Verdachtsgrad, den eine
Plattform ohne aussere Beobachtung erhalten kann.

Zwei Ausloeser, beide ohne Eingriff in fremden Code:

  1. honeypot_user - ein Username, den es nie gab. auth_service.py
     meldet jeden Fehlversuch ueber den bestehenden EventBus
     ("auth.login_failed", reason user_not_found) - genau DIESER
     einen Zweig hoert canary mit. Ein Fehlversuch eines ECHTEN
     Accounts laeuft ueber reason wrong_password und bleibt ohne
     Wirkung. auth_service.py selbst wird nicht angefasst (weniger
     Risiko im sicherheitskritischsten Pfad der Plattform).

  2. honeypot_path - ein reizvoller Pfad ohne Token-Zugriff. Wird er
     aufgerufen, liefert die Plattform einen kuenstlichen Koeder mit
     der Signatur ROBECANARY. NIE echte Daten, NIE ein Header, der
     die Falle verraet - eine Falle, die sichtbar waere, waere keine.

Beide Ausloeser erzeugen dasselbe Sentinel-Event
(canary.asset_touched) mit der Technik "canary_touch", deren Gewicht
die Incident-Schwelle allein uebersteigt: Ein Canary-Treffer ist per
Definition ein Beweis, keine Vermutung. Danach greift die bekannte
Kette Incident -> forensische Timeline -> learn() -> security_policies.

Fail-safe: Jede Canary-Verarbeitung laeuft in einem try/except. Im
Zweifel passiert nichts - die Anmeldung des Nutzers darf durch eine
defekte Falle nie beeintraechtigt werden.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response

logger = logging.getLogger(__name__)

# Die EventType-/Technik-Namen, die der Rest der Plattform erwartet
# (siehe classification.py TECHNIQUES + _EVENT_TECHNIQUES).
CANARY_EVENT = "canary.asset_touched"
CANARY_TECHNIQUE = "canary_touch"

# Massenaufrufe duerfen die Incident-Kette nicht fluten: derselbe
# Angreifer mit derselben Quelle loest innerhalb dieses Fensters NUR
# BEIM ERSTEN Mal einen Event aus. Gezaehlt wird weiterhin immer -
# der forensische Verlauf bleibt vollstaendig.
RATE_LIMIT_SECONDS = 60

# Signatur des Koeders. Steckt IM Inhalt, nie in einem Header - ein
# Header wuerde die Falle verraten, bevor sie gegriffen hat.
DECOY_SIGNATURE = b"ROBECANARY"

# Die reizvollen Pfade. Bewusst eine feste, kleine Liste: eine Route,
# die ALLES beantwortet, wuerde echte 404-Muster verhalten und jedes
# beliebige Misslingen zu einem Alarm machen.
HONEYPOT_PATHS = frozenset(
    {
        "/api/backup/restore",
        "/api/backup/patient_archive.db",
        "/api/admin/export-all",
        "/api/.env",
    }
)

_subscribed_to_event_bus = False


# ─── Koeder ────────────────────────────────────────────────────────────────


def decoy_payload(path: str) -> bytes:
    """Kuenstlicher Datenstrom fuer die Falle.

    Aus einer hash-abgeleiteten Quelle, NICHT aus einem echten
    Dateipfad - sonst wuerde die Falle genau das leaken, was sie
    schuetzen soll. Die Signatur steht am Anfang: wer den Koeder
    analysiert, sieht sofort, dass er erwischt wurde - aber erst
    NACHDEM die Beruehrung bereits als Event gespeichert ist."""
    digest = hashlib.sha256(f"robe-canary:{path}".encode()).digest()
    return DECOY_SIGNATURE + b"\x00" + digest * 8


def generate_trigger_value(kind: str) -> str:
    """Serverseitige Erzeugung des Koeder-Werts.

    Der Client darf eine Falle nicht frei definieren - sonst waere
    sie mit etwas Recherche vorhersehbar (und ein Missbrauch der
    API wuerde Koeder erschaffen, die zufaellig echten Usernames
    entsprechen)."""
    if kind == "honeypot_user":
        # Sieht aus wie ein Servicekonto, passt in die
        # Username-Limites (3-32 Zeichen, siehe validation.py).
        return f"svc_backup_{secrets.token_hex(4)}"
    return f"/api/backup/{secrets.token_hex(6)}.db"


# ─── Ausloeser ─────────────────────────────────────────────────────────────


def record_trigger(
    org_id: UUID,
    *,
    kind: str,
    label: str,
    trigger_value: str,
    source_value: str,
    ip: str | None = None,
    path: str | None = None,
) -> bool:
    """Beantwortet einen Koeder-Treffer.

    Immer: Zaehler und Zeitpunkt hoch (der forensische Verlauf bleibt
    vollstaendig, auch wenn die Alarmierung rate-limited ist).
    Rate-limited: der Event, der den Incident ausloest.

    Gibt zurueck, ob ein neuer Event erzeugt wurde - nur damit
    Aufrufer und Tests abfragen koennen, was passiert ist. Wirft nie:
    Fehler hier duerfen eine Anmeldung nicht beeintraechtigen."""
    from backend.core.repository import connection
    from backend.sentinel.repository import SentinelRepository

    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE canary_assets
                   SET trigger_count = trigger_count + 1,
                       triggered_at = now(),
                       triggered_by = %s
                 WHERE org_id = %s
                   AND kind = %s
                   AND trigger_value = %s
                   AND active
                """,
                (source_value, str(org_id), kind, trigger_value),
            )
            if cur.rowcount == 0:
                # Inzwischen deaktiviert oder geloescht - dann wird
                # auch nichts alarmiert.
                return False

            cur.execute(
                """
                SELECT 1
                  FROM sentinel_events
                 WHERE org_id = %s
                   AND event_type = %s
                   AND source_value = %s
                   AND occurred_at > now() - make_interval(secs => %s)
                 LIMIT 1
                """,
                (str(org_id), CANARY_EVENT, source_value, RATE_LIMIT_SECONDS),
            )
            if cur.fetchone() is not None:
                return False

    SentinelRepository().record_event(
        org_id,
        event_type=CANARY_EVENT,
        source_value=source_value,
        source_type="ip",
        path=path,
        ip=ip,
        details={"canary_kind": kind, "canary_label": label},
    )
    return True


def on_login_failed(data: dict[str, Any]) -> None:
    """EventBus-Subscriber fuer auth.login_failed.

    Reagiert AUSSCHLIESSLICH auf reason == user_not_found: nur dann
    hat jemand einen Namen ausprobiert, den es nicht gibt. Ein
    falsches Passwort bei einem echten Account ist normale
    Verhaltensweite und darf keine Falle ausloesen.

    Fail-safe: Jede Exception wird gefangen und nur geloggt. Diese
    Funktion sitzt im Anmeldungs-Pfad der Plattform - sie darf nie
    einen Login in einen 500er verwandeln."""
    try:
        if data.get("reason") != "user_not_found":
            return
        username = str(data.get("username") or "")
        org_raw = data.get("org_id")
        if not username or not org_raw:
            return
        try:
            org_id = UUID(str(org_raw))
        except ValueError:
            return

        from backend.sentinel.repository import SentinelRepository

        repo = SentinelRepository()
        canary = repo.get_canary_by_trigger(org_id, "honeypot_user", username)
        if canary is None or not canary.get("active", True):
            return

        ip = str(data.get("ip") or "") or "unknown"
        record_trigger(
            org_id,
            kind="honeypot_user",
            label=canary["label"],
            trigger_value=username,
            source_value=ip,
            ip=ip,
        )
    except Exception:
        logger.warning("Canary-Ausloeser fehlgeschlagen", exc_info=True)


def hit_honeypot_path(path: str, ip: str) -> bytes | None:
    """Prueft einen Pfad gegen alle aktiven Fallen dieser Plattform.

    Die Route laeuft bewusst OHNE Token (so greifen Angreifer auch
    wirklich zu), sie kennt also keine Org - deshalb wird ueber alle
    Orgs mit passendem, aktiven Canary gesucht. Wenn keine Falle
    steht, bleibt die Route unsichtbar (404, ohne Event)."""
    if path not in HONEYPOT_PATHS:
        return None
    try:
        from backend.sentinel.repository import SentinelRepository

        hits = SentinelRepository().get_path_canaries(path)
        if not hits:
            return None
        for row in hits:
            try:
                record_trigger(
                    UUID(str(row["org_id"])),
                    kind="honeypot_path",
                    label=row["label"],
                    trigger_value=path,
                    source_value=ip,
                    ip=ip,
                    path=path,
                )
            except Exception:
                logger.warning("Canary-Pfad-Trigger fehlgeschlagen", exc_info=True)
    except Exception:
        logger.warning("Canary-Pfad-Pruefung fehlgeschlagen", exc_info=True)
        return None
    return decoy_payload(path)


# ─── Hooks ─────────────────────────────────────────────────────────────────


def install_hooks() -> None:
    """Haengt den Login-Ausloeser an den bestehenden EventBus.

    Idempotent: mehrmaliges Startup (Tests, Neustart) darf den
    Subscriber nicht doppelt registrieren - sonst entstehen doppelte
    Events und doppelte Incidents aus EINEM Anmeldeversuch."""
    global _subscribed_to_event_bus
    if _subscribed_to_event_bus:
        return
    from backend.core.events import EventBus

    EventBus().subscribe("auth.login_failed", on_login_failed)
    _subscribed_to_event_bus = True
    logger.info("Canary-Login-Ausloeser registriert.")


# ─── Honeypot-Routen (bewusst ohne Auth) ───────────────────────────────────


honeypot_router = APIRouter()


def _client_ip(request: Request) -> str:
    """Gleiche IP-Auflösung wie der Login-Pfad (main.py:517) - hinter
    einem Tunnel waere request.client.host die interne Adresse des
    Tunnels, nicht die des Aufrufers. Die trusted-Proxy-Liste liegt in
    main und wird lazy gelesen, damit es keinen Import-Zyklus gibt."""
    try:
        import main as app_module
        from backend.core.rate_limit import resolve_client_ip

        return resolve_client_ip(request.scope, getattr(app_module, "_trusted_proxies", []))
    except Exception:
        return request.client.host if request.client else "unknown"


def _serve_trap(path: str, request: Request) -> Response:
    payload = hit_honeypot_path(path, _client_ip(request))
    if payload is None:
        # Keine Falle fuer diesen Pfad: unsichtbar, ohne Hinweis darauf,
        # dass es hier etwas zu finden gaebe.
        raise HTTPException(status_code=404, detail="Not Found")
    return Response(content=payload, media_type="application/octet-stream")


@honeypot_router.get("/api/backup/restore", include_in_schema=False)
def _trap_restore(request: Request) -> Response:
    return _serve_trap("/api/backup/restore", request)


@honeypot_router.get("/api/backup/patient_archive.db", include_in_schema=False)
def _trap_patient_archive(request: Request) -> Response:
    return _serve_trap("/api/backup/patient_archive.db", request)


@honeypot_router.get("/api/admin/export-all", include_in_schema=False)
def _trap_export_all(request: Request) -> Response:
    return _serve_trap("/api/admin/export-all", request)


@honeypot_router.get("/api/.env", include_in_schema=False)
def _trap_env(request: Request) -> Response:
    return _serve_trap("/api/.env", request)
