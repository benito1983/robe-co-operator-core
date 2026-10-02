"""Enforcement - Sperren WIRKEN endlich auf der Zugangsstelle.

Vor diesem Modul existierte `SentinelRepository.is_banned()`, wurde
aber von niemandem aufgerufen: eine gesperrte Quelle kam trotzdem
rein. Diese Middleware schliesst genau diese Luecke - sie ist der
einzige Hakan, der an jeder geschuetzten Anfrage sitzt, bevor die
Antwort entsteht.

Vorbild: backend/core/rate_limit.py::RateLimitMiddleware (pure-ASGI,
gleiche IP-Aufloesung, gleicher frueher Abbruch).

Grenzen, bewusst und dokumentiert (Tests: TestAutonomyBoundary):

  PASS_THROUGH_PATHS
      /auth/login hat kein Token und damit keine Org. Diese
      Middleware blockiert dort NICHT - der bestehende
      Brute-Force-Throttle (auth_service._check_bruteforce) greift
      weiterhin. Eine Sperre ohne Org-Kontext waere cross-tenant.

  PUBLIC_PATHS
      /health und /ready bleiben immer erreichbar. Monitoring darf
      nie durch eine Sperre sterben, sonst sieht niemand mehr, dass
      ueberhaupt gesperrt wurde.

Fail-open (bewusst): Jeder Fehler in der Pruefung laesst die Anfrage
durch. Verfuegbarkeit steht ueber der Sperre - im schlimmsten Fall
kommt eine gebannte Quelle ein weiteres Mal rein, im Gegenzug kann
ein Defekt in diesem Modul nie den Zugang aller Nutzer stilllegen.

Der Cache wird beim Setzen/Aufheben einer Sperre SOFORT invalidiert
(enforcement.invalidate_cache() aus dem Repository) - es gibt kein
Zeitfenster, in dem die Sperre noch durchwaert.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)

#: Bewusst nicht erfasst: ohne Token gibt es keine Org, eine Sperre
#: ohne Org-Kontext wuerde fremde Organisationen treffen.
PASS_THROUGH_PATHS: tuple[str, ...] = ("/auth/login",)

#: Monitoring bleibt immer frei.
PUBLIC_PATHS: tuple[str, ...] = ("/health", "/ready")

#: Break-glass: NUR das Aufheben einer Sperre bleibt erreichbar, auch
#: fuer die gesperrte Quelle selbst. Ohne diese Ausnahme waere jede
#: Sperre unumkehrbar, sobald sie greift (der eigene DELETE landete in
#: der eigenen 403) - auch fuer einen Admin, der sich aus Versehen
#: selbst gesperrt hat. Schutz dagegen braucht der Angreifer nicht:
#: er braucht zusaetzlich eine gueltige Verwaltungs-Berechtigung UND
#: die UUID der Sperre, und genau diese Liste (GET /bans) bleibt
#: gesperrt. Gegenueber fremden Orgs ohnehin wirkungslos, weil der
#: Endpunkt die Sperren an die Org aus dem Token bindet.
LIFT_PATH_PREFIX = "/api/sentinel/bans/"

#: Gebannter Zugriff: absichtlich blaender als jede andere 401/403 -
#: die Antwort nennt weder Grund noch Subjekt noch Modul, sonst
#: wuerde sie zum Oracle fuer den Angreifer.
BLOCKED_DETAIL = "Zugriff gesperrt"

#: (org_id, subject_type, subject) -> True. Nur POSITIVE Treffer werden
#: gespeichert; nach dem ersten Laden ist die Pruefung ein dict-Lookup
#: ohne DB-Zugriff pro Anfrage.
_cache: dict[tuple[str, str, str], bool] = {}
_cache_valid = False


def invalidate_cache() -> None:
    """Naechste Anfrage laedt die Sperren neu.

    Wird aus backend/sentinel/repository.py beim Setzen und Aufheben
    einer Sperre aufgerufen (direkt, nicht ueber den EventBus - so
    greift die Aenderung in derselben Anfrage, ohne Verzoegerung)."""
    global _cache_valid
    _cache.clear()
    _cache_valid = False


def _load_cache() -> None:
    """Alle aktiven Sperren dieser Plattform laden.

    Ueber alle Orgs hinweg, weil die Middleware die Org erst aus dem
    Token kennt - die Tenant-Sicherheit steckt in der Cache-KOENNTE
    (Key enthaelt org_id), nicht in der Abfrage. Unabhaengig von der
    Anzahl der Sperren ein einziger SELECT, nicht einer pro Request."""
    global _cache_valid
    from backend.core.repository import connection

    try:
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT org_id, subject_type, subject
                      FROM sentinel_bans
                     WHERE active
                       AND (expires_at IS NULL OR expires_at > now())
                    """
                )
                rows = cur.fetchall()
        _cache.clear()
        for org_id, subject_type, subject in rows:
            _cache[(str(org_id), str(subject_type), str(subject))] = True
        _cache_valid = True
    except Exception:
        logger.warning("Sperren-Cache konnte nicht geladen werden", exc_info=True)
        _cache_valid = True  # kein Endlos-Ladeversuch pro Anfrage


def is_blocked(org_id: UUID | str, subject_type: str, subject: str) -> bool:
    """Prueft EINE Quelle gegen die aktiven Sperren (org-scoped)."""
    if not _cache_valid:
        _load_cache()
    return (str(org_id), subject_type, str(subject)) in _cache


def _claims_from_scope(scope: dict[str, Any]) -> dict[str, Any] | None:
    """Token aus dem Scope lesen und verifizieren.

    Ohne gueltiges Token gibt es keine Pruefung - dann entscheidet der
    normale Gate mit 401. Fehler sind hier KEIN Grund abzulehnen,
    denn die Pruefung ist Zusatz, nicht Ersatz fuer die Authentifizierung."""
    for name, value in scope.get("headers", ()):
        if name == b"authorization":
            raw = value.decode("latin-1")
            if not raw.lower().startswith("bearer "):
                return None
            try:
                from backend.core.api_deps import get_current_claims

                return get_current_claims(raw)
            except Exception:
                return None
    return None


def _client_ip(scope: dict[str, Any]) -> str:
    """Gleiche IP-Aufloesung wie RateLimit und Login (main.py:517)."""
    try:
        import main as app_module
        from backend.core.rate_limit import resolve_client_ip

        return resolve_client_ip(scope, getattr(app_module, "_trusted_proxies", ()))
    except Exception:
        client = scope.get("client")
        return client[0] if client else "unknown"


class SentinelBanMiddleware:
    """Pure-ASGI-Middleware:403, bevor irgendetwas anderes passiert."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if path in PUBLIC_PATHS or path in PASS_THROUGH_PATHS:
            return await self.app(scope, receive, send)
        if scope.get("method") == "DELETE" and path.startswith(LIFT_PATH_PREFIX):
            return await self.app(scope, receive, send)

        try:
            claims = _claims_from_scope(scope)
            if claims is None:
                # Kein Token: der Gate entscheidet (401).
                return await self.app(scope, receive, send)

            org_id = claims.get("org_id")
            if not org_id:
                return await self.app(scope, receive, send)

            ip = _client_ip(scope)
            user_id = claims.get("user_id")
            blocked = is_blocked(org_id, "ip", ip) or (
                bool(user_id) and is_blocked(org_id, "user", str(user_id))
            )
        except Exception:
            logger.warning("Sperren-Pruefung fehlgeschlagen", exc_info=True)
            return await self.app(scope, receive, send)

        if not blocked:
            return await self.app(scope, receive, send)
        return await self._reject(send)

    async def _reject(self, send: Any) -> None:
        body = json.dumps({"detail": BLOCKED_DETAIL}, ensure_ascii=False).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
