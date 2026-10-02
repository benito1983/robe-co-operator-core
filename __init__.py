# backend/sentinel/__init__.py
#
# RoBe Sentinel - Active Defense mit Attack Intelligence.
#
# Harte Grenze (Nutzerentscheidung 2026-09-27, als Test erzwungen in
# tests/test_sentinel.py::TestDefensiveBoundary):
#
#   RoBe DARF:       erkennen, blockieren, isolieren, taeuschen, dokumentieren.
#   RoBe DARF NICHT: fremde Systeme beschaedigen oder sich dort einwisten.
#
# Alles in diesem Paket liest ausschliesslich die EIGENE Telemetrie und
# wirkt ausschliesslich AUF DER EIGENEN INFRASTRUKTUR (Sperren, Regeln,
# Forensik). Es gibt bewusst keine Verbindung nach aussen, kein Scanning
# fremder Hosts, kein Zurueckschlagen - das ist kein Vertrag, den man
# einhalten muss, sondern ein baulicher Zwang: das Grenz-Test schreibt
# das Paket auf, sobald jemals eine Bibliothek fuer ausgehende Angriffe
# hinzukommt.
#
# Lernschleife ("RoBe lernt aus dem Angriff"):
#   Attack Event -> Threat Classification -> Attack Pattern -> MITRE
#   ATT&CK -> Behavior Analysis -> Detection Rule -> Security Agent.
#   Die erzeugte Detection Rule landet als security_policies-Zeile,
#   die anomaly.py bereits auswertet - derselbe Angriff wird beim
#   naechsten Mal frueher erkannt, ohne dass ein Mensch sie tippt.
from __future__ import annotations

from backend.core.registry import ModuleInfo, ModuleRegistry


def register(registry: ModuleRegistry) -> None:
    registry.register(
        ModuleInfo(
            key="sentinel",
            name="RoBe Sentinel",
            description=(
                "Active Defense mit Attack Intelligence: Angriffe auf die "
                "eigene Infrastruktur erkennen, korrelieren und blockieren, "
                "MITRE ATT&CK zuordnen, forensisch rekonstruieren und daraus "
                "automatisch Detection Rules lernen. Dazu Canary Assets: "
                "Koeder legen, die niemand legitimerweise anfasst, und ihre "
                "Beruehrung als Hochverdacht dokumentieren. Verteidigung nur - "
                "Sentinel greift nie fremde Systeme an."
            ),
            version="0.2.0",
        )
    )


PERMISSIONS = [
    ("can_view_sentinel", "Sentinel-Dashboard, Incidents, Timeline und Ereignisse lesen"),
    (
        "can_manage_sentinel",
        "Ereignisse einspeisen, Incidents schliessen, Regeln lernen, Sperren und "
        "Canary-Fallen setzen/aufheben",
    ),
]


def register_permissions() -> None:
    from backend.core.permissions import register_permission

    for key, description in PERMISSIONS:
        register_permission(key, description)


def install_hooks() -> None:
    """Canary-Ausloeser an den bestehenden EventBus haengen (idempotent).

    Aufgerufen aus dem Lifespan in main.py - derselbe Platz, an dem
    auch security.activate() seine Hooks registriert. Ohne diesen
    Aufruf gibt es Canary-Fallen, aber niemand, der sie hoert."""
    from backend.sentinel import canary

    canary.install_hooks()
