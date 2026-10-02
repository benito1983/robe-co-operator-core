# backend/sentinel/classification.py
#
# Threat Classification + MITRE ATT&CK Mapping + Behavior Analysis.
#
# PURE FUNCTIONS: kein DB-Zugriff, kein Netzwerk, keine Zeit-Defaults
# ausser dem, was der Aufrufer mitgibt. Genau deshalb ist die ganze
# Lernkette einzeln testbar (tests/test_sentinel.py) und kann niemals
# einen ausgehenden Angriff ausloesen - es gibt hier schlicht nichts,
# was ausfuehren koennte.
#
# Die Kette:
#   classify()          -> Welche Technik steckt in diesem Ereignis?
#   score_events()      -> Wie schwer wiegt die Summe dieser Quelle?
#   detect_pattern()    -> Wie verhaelt sich der Angreifer ueber Zeit?
#   propose_rule()      -> Welche security_policies-Regel erkennt das
#                          beim NAECHSTEN Mal frueher? (Der Lernschritt.)
#
# Scoring ist bewusst ein Gewichtungs-Register statt eines Modells:
# nachvollziehbar, begruendbar, im Audit erklaerbar - ein Score, den
# niemand erklaeren kann, waere vor einem Betriebsrat, einem Kunden
# oder einem Gericht wertlos.
from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from backend.core.validation import (
    contains_sql_injection_pattern,
    contains_xss_pattern,
)

#: Zeitfenster, ueber das hinweg Ereignisse EINER Quelle zu einem
#: Incident korreliert werden. 15 Minuten fasst einen Brute-Force-Lauf
#: ohne dabei den naechsten, zufaelligen Fehlversuch desselben
#: Besuchers dazuzuziehen.
CORRELATION_WINDOW_SECONDS = 900

#: Summen-Score, ab dem aus Roh-Ereignissen ein Incident wird.
INCIDENT_SCORE_THRESHOLD = 40

#: Score, ab dem ein Incident als kritisch gilt.
CRITICAL_SCORE = 80

#: Technik-Katalog = das ATT&CK-Vokabular des Moduls. `event_type` ist
#: die Bruecke zurueck in die eigene Telemetrie, `weight` die
#: Schweregewichtung im Score. Fuer den Lernschritt (propose_rule)
#: steckt dieselbe `event_type` auch dort - die erzeugte Regel zielt
#: also genau auf das Ereignis, das den Angriff bereits offenbart hat.
TECHNIQUES: dict[str, dict[str, Any]] = {
    "credential_stuffing": {
        "mitre_id": "T1110.004",
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "event_type": "auth.login_failed",
        "weight": 10,
        "description": "Massenhafte Anmeldeversuche mit Listendaten.",
    },
    "active_scanning": {
        "mitre_id": "T1595.001",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "event_type": "http.404",
        "weight": 4,
        "description": "Abfrage oeffentlicher Pfade auf Existenz und Schwachstellen.",
    },
    "authorization_probing": {
        "mitre_id": "T1595.002",
        "name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "event_type": "http.403",
        "weight": 8,
        "description": "Systematisches Pruefen, welche Pfade wirklich gesperrt sind.",
    },
    "injection": {
        "mitre_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "event_type": "validation.rejected",
        "weight": 15,
        "description": "Einschleusen von Anweisungen in Eingabefelder.",
    },
    "rate_abuse": {
        "mitre_id": "T1498.001",
        "name": "Direct Network Flood",
        "tactic": "Impact",
        "event_type": "http.429",
        "weight": 6,
        "description": "Ueberlastung durch schieren Anfrageandrang.",
    },
    # ── Canary Assets (migration 067) ───────────────────────────────
    # Ein Beruehren eines Canaries ist KEINE Vermutung, sondern ein
    # Beweis: niemand legitimerweise kommt an diesen Konto-Namen
    # (honeypot_user) oder diesen Pfad (honeypot_path) heran. Deshalb
    # uebersteigt das Gewicht allein die Incident-Schwelle - es darf
    # nicht erst mehrere Treffer brauchen, um zu wirken.
    "canary_touch": {
        # T1078 "Valid Accounts": der Angreifer versucht, ueber
        # Account-/Zugangsmaterial Zugriff zu erhalten, das ihm nicht
        # gehoert. Der Koeder-Pfad ist derselbe Fall mit anderem
        # Ausloeser (Zugriff auf ungesicherte Zugangsdatei).
        "mitre_id": "T1078",
        "name": "Canary Asset Beruehrung",
        "tactic": "Initial Access",
        "event_type": "canary.asset_touched",
        "weight": 90,
        "description": (
            "Ein Koeder wurde angefasst - hochverdaechtiger "
            "Zugriffsversuch auf ein Asset, das es nie legitimerweise gibt."
        ),
    },
}

#: Ereignistypen, die ueberhaupt eine Technik signalisieren koennen.
#: Alles andere (http.request, auth.login_success, ...) bleibt UNBE-
#: WERTET - sonst meldet Sentinel den Alltag als Angriff.
_EVENT_TECHNIQUES: dict[str, tuple[tuple[str, float], ...]] = {
    "auth.login_failed": (("credential_stuffing", 0.6),),
    "http.401": (("credential_stuffing", 0.5),),
    "http.403": (("authorization_probing", 0.5),),
    "http.404": (("active_scanning", 0.5),),
    "http.429": (("rate_abuse", 0.5),),
    "validation.rejected": (("injection", 0.75),),
    # Volle Konfidenz: ein Canary wird nur von jemandem beruehrt, der
    # ihn nicht benoetigt - das ist gemessen, nicht geschaetzt.
    "canary.asset_touched": (("canary_touch", 1.0),),
}

#: Pfade, die kein menschlicher Besucher zufaellig aufruft - deren
#: Auftauchen ist ein deutlich staerkerer Hinweis auf ein Werkzeug.
_SCANNER_PATH_MARKERS = (
    "/wp-admin",
    "/wp-login",
    "/.env",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/.git",
    "/actuator",
    "/cgi-bin",
    "/shell",
    "/setup-config",
    "/wp-config",
    "/vendor/phpunit",
    "/api/v1/../",
    "/etc/passwd",
)


def classify(event_type: str, data: dict[str, Any]) -> dict[str, Any] | None:
    """Ordnet einem Ereignis eine ATT&CK-Technik zu (oder None).

    Rueckgabe: {"technique", "mitre_id", "confidence", "evidence"}.
    confidence 0 < c <= 1 - die Aussage "wie sicher bin ich mir".
    """
    candidates = _EVENT_TECHNIQUES.get(event_type)
    if not candidates:
        return None

    evidence: list[str] = [f"event_type={event_type}"]
    path = str(data.get("path") or "")
    details = data.get("details") or {}

    injection_payload = contains_sql_injection_pattern(path) or contains_xss_pattern(
        path if isinstance(path, str) else ""
    )
    if not injection_payload and isinstance(details, dict):
        blob = " ".join(str(v) for v in details.values())
        injection_payload = contains_sql_injection_pattern(blob) or contains_xss_pattern(blob)

    scanner_path = any(marker in path for marker in _SCANNER_PATH_MARKERS)

    technique, confidence = candidates[0]
    if scanner_path:
        evidence.append("scanner_path")
    if injection_payload:
        evidence.append("attack_pattern_in_input")

    # Staerkere Belege heben die Sicherheit der Zuordnung an - immer
    # innerhalb (0, 1], nie 0 (sonst wuerde der Score verschwinden).
    if scanner_path:
        confidence = min(1.0, confidence + 0.3)
    if injection_payload and technique == "injection":
        confidence = min(1.0, confidence + 0.15)
    confidence = round(max(0.01, min(1.0, confidence)), 2)

    entry = TECHNIQUES[technique]
    return {
        "technique": technique,
        "mitre_id": entry["mitre_id"],
        "confidence": confidence,
        "evidence": evidence,
    }


def score_events(events: list[dict[str, Any]]) -> int:
    """Summiert die Gewichte aller klassifizierbaren Ereignisse und
    kapppt auf 0..100 - ein einzelner Wert, den ein Mensch lesen kann."""
    total = 0
    for event in events:
        obs = classify(str(event.get("event_type") or ""), event)
        if obs is None:
            continue
        total += int(TECHNIQUES[obs["technique"]]["weight"])
    return int(min(100, max(0, total)))


def _as_timestamp(value: Any) -> float | None:
    """datetime/ISO-String/Zahl -> epoch Sekunden. None, wenn nicht
    auswertbar - der Caller faengt das ab statt hier zu raten."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.timestamp()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.timestamp()
    return None


def detect_pattern(
    events: list[dict[str, Any]], window_seconds: int = CORRELATION_WINDOW_SECONDS
) -> dict[str, Any]:
    """Verhaltensanalyse ueber ein Ereignis-Fenster.

    Liefert Zahlen statt Text - deshalb kann daraus sowohl der
    Incident-Body als auch die spaeter gelernte Regel gebaut werden.
    """
    count = len(events)
    paths = {str(e["path"]) for e in events if e.get("path")}
    statuses = {int(e["http_status"]) for e in events if isinstance(e.get("http_status"), int)}
    user_agents = {str(e["user_agent"]) for e in events if e.get("user_agent")}

    per_type: dict[str, int] = {}
    for event in events:
        key = str(event.get("event_type") or "")
        per_type[key] = per_type.get(key, 0) + 1

    stamps = [t for t in (_as_timestamp(e.get("occurred_at")) for e in events) if t]
    span_seconds = (max(stamps) - min(stamps)) if len(stamps) >= 2 else 0.0
    effective_window = float(span_seconds) if span_seconds > 0 else float(window_seconds)
    rate = (count / (effective_window / 60.0)) if effective_window > 0 else float(count)

    return {
        "event_count": count,
        "window_seconds": int(window_seconds),
        "distinct_paths": len(paths),
        "distinct_statuses": len(statuses),
        "distinct_user_agents": len(user_agents),
        "events_per_minute": round(rate, 2),
        "event_types": dict(sorted(per_type.items())),
    }


def dominant_technique(pattern: dict[str, Any]) -> str | None:
    """Technik mit dem groessten Beitrag zum Score - die, fuer die sich
    ein Mensch die Warnung ansehen wuerde."""
    best: str | None = None
    best_weight = 0
    for event_type, count in (pattern.get("event_types") or {}).items():
        candidates = _EVENT_TECHNIQUES.get(str(event_type))
        if not candidates:
            continue
        technique = candidates[0][0]
        weight = int(TECHNIQUES[technique]["weight"]) * int(count)
        if weight > best_weight:
            best, best_weight = technique, weight
    return best


def severity_for_score(score: int) -> str:
    return "critical" if score >= CRITICAL_SCORE else "warning"


def propose_rule(
    technique: str | None,
    pattern: dict[str, Any],
    source_field: str,
) -> dict[str, Any]:
    """Der Lernschritt: aus dem beobachteten Muster diejenige
    security_policies-Regel bauen, die anomaly.py auswertet.

    shape: {"match": {"event_type": ...},
            "threshold": {"count_in_window", "window_seconds", "same_field"}}
    """
    entry = TECHNIQUES.get(str(technique)) if technique else None
    event_type = entry["event_type"] if entry else "unknown"

    observed = int(pattern.get("event_count") or 0)
    window = int(pattern.get("window_seconds") or CORRELATION_WINDOW_SECONDS)
    # Die Regel soll frueher zuschlagen als der beobachtete Vorfall
    # endete (0.8), aber nie unter 3 Faelle fallen - sonst loest ein
    # einziger Fehlversuch eine Dauer-Sperre aus. Und nie ueber 50:
    # eine Regel, die erst bei 500 Angriffen greift, schuetzt nicht.
    count_in_window = max(3, min(50, round(observed * 0.8))) if observed else 3

    return {
        "match": {"event_type": event_type},
        "threshold": {
            "count_in_window": count_in_window,
            "window_seconds": max(1, window),
            "same_field": source_field,
        },
    }


def build_summary(
    technique: str | None,
    score: int,
    pattern: dict[str, Any],
    source_value: str,
) -> tuple[str, str]:
    """Titel + Kurzbeschreibung eines Incidents (deutsch, weil Nutzer-
    sichtbar)."""
    entry = TECHNIQUES.get(str(technique)) if technique else None
    name = entry["name"] if entry else "Verdachtiges Verhalten"
    mitre = f" ({entry['mitre_id']})" if entry else ""
    title = f"{name} gegen {source_value}{mitre}"
    summary = (
        f"{pattern.get('event_count', 0)} Ereignisse in "
        f"{pattern.get('window_seconds', 0)} s, Score {score}/100, "
        f"{pattern.get('distinct_paths', 0)} verschiedene Pfade, "
        f"{pattern.get('events_per_minute', 0):g} Ereignisse/Minute."
    )
    return title, summary


def catalogue() -> list[dict[str, Any]]:
    """ATT&CK-Katalog fuer die UI - gleiche Quelle wie classify()."""
    return [
        {
            "technique": key,
            "mitre_id": value["mitre_id"],
            "name": value["name"],
            "tactic": value["tactic"],
            "event_type": value["event_type"],
            "weight": value["weight"],
            "description": value["description"],
        }
        for key, value in sorted(TECHNIQUES.items(), key=lambda kv: kv[1]["mitre_id"])
    ]


def confidence_bucket(confidence: float | None) -> str:
    """Lesbare Stufe fuer die UI - raw floats sehen in einer Liste
    wie Messrauschen aus."""
    if confidence is None:
        return "unknown"
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def normalise_score(value: float) -> int:
    """Hilfsfremde Eingaben (z. B. Prozentwerte) auf 0..100 kappen."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return 0
    if not math.isfinite(float(value)):
        return 0
    return int(min(100, max(0, round(float(value)))))
