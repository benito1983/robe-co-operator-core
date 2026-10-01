# main.py
#
# First real composition root for RoBe Co-Operator: wires the Core
# platform (Postgres-backed auth/RBAC/capability-profiles, see
# backend/core/) together with the connected domain modules
# (backend/knowledge/, wrapping the standalone "Knowledge System"
# project's knowledge_module package; backend/crm/, Postgres-backed
# contacts; backend/professor/, the central orchestrator routing to
# AI/content/decision/studio services; backend/ai/, org-scoped AI
# provider selection and credentials; backend/affiliate/, product/
# campaign/tracking-link management with Amazon/YouTube integrations and
# ML sales predictions; backend/credits/, wrapping the standalone
# "Robe Credit-System" project's robe_credits package - hash-chained
# credit ledger, transfers, savings goals; backend/marketplace/,
# wrapping "Robe Marketplace" - listings/purchases/publisher payouts,
# settled via robe_bridges.CreditsPaymentProvider/CreditsPayoutProvider
# on top of robe_credits; backend/codes/, org-scoped sandboxed Python
# execution using "RoBe Codes"' RestrictedPython engine - JavaScript
# deliberately not exposed, see backend/codes/routes.py) - nothing here
# is module-specific except each router mount.
#
# Also reports real signals (failed logins, rate-limit violations) to
# Chronos (infra/chronos/ - platform infrastructure, not a tenant module,
# runs as its own docker-compose service) via
# backend.core.chronos_bridge.report_to_chronos() - see that module's
# docstring for why this replaces raw packet capture for this deployment.
#
# Start:
#   uvicorn main:app --host 127.0.0.1 --port 8000
from __future__ import annotations

import logging
import math
import os
import sys
import threading
from contextlib import asynccontextmanager
from uuid import UUID

# Windows defaults stdout/stderr to the console codepage (cp1252) once
# they're not an interactive console (e.g. run under a process manager,
# piped to a log file, or - the case that surfaced this - a test/uvicorn
# worker whose output is captured) - several wrapped standalone modules
# (RoBe neural network/ClearSearch among them) print emoji status
# messages, which then raises UnicodeEncodeError and crashes the
# request that triggered the print, not just a cosmetic log glitch.
# UTF-8 can represent any of them, so this is a safe, one-time,
# process-wide fix rather than patching every wrapped module's prints -
# must happen before anything else has a chance to print.
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

import backend.affiliate as affiliate_module_plugin
import backend.affiliate.redirect as affiliate_redirect
import backend.affiliate.routes as affiliate_routes
import backend.agent as agent_module_plugin
import backend.agent.routes as agent_routes
import backend.ai as ai_module_plugin
import backend.ai.routes as ai_routes
import backend.aimedia as aimedia_module_plugin
import backend.aimedia.routes as aimedia_routes
import backend.bookcreator as bookcreator_module_plugin
import backend.bookcreator.routes as bookcreator_routes
import backend.circuitlab as circuitlab_module_plugin
import backend.circuitlab.orchestration_routes as circuitlab_orchestration_routes
import backend.circuitlab.routes as circuitlab_routes
import backend.clearsearch as clearsearch_module_plugin
import backend.clearsearch.routes as clearsearch_routes
import backend.code_agent as code_agent_module_plugin
import backend.code_agent.routes as code_agent_routes
import backend.codes as codes_module_plugin
import backend.codes.routes as codes_routes
import backend.collaborate_module as collaborate_module_plugin
import backend.collaborate_module.routes as collaborate_routes
import backend.community_module as community_module_plugin
import backend.community_module.routes as community_routes
import backend.content_creator as content_creator_module_plugin
import backend.content_creator.routes as content_creator_routes
import backend.content_manager as content_manager_module_plugin
import backend.content_manager.routes as content_manager_routes
import backend.corporate_memory as corporate_memory_module_plugin
import backend.corporate_memory.routes as corporate_memory_routes
import backend.credits as credits_module_plugin
import backend.credits.routes as credits_routes
import backend.crm as crm_module_plugin
import backend.crm.routes as crm_routes
import backend.dependency_graph as dependency_graph_module_plugin
import backend.dependency_graph.routes as dependency_graph_routes
import backend.design as design_module_plugin
import backend.design.routes as design_routes
import backend.early_warning as early_warning_module_plugin
import backend.early_warning.routes as early_warning_routes
import backend.failure_point as failure_point_module_plugin
import backend.failure_point.routes as failure_point_routes
import backend.game_engine as game_engine_module_plugin
import backend.game_engine.routes as game_engine_routes
import backend.gdpr.routes as gdpr_routes
import backend.gps as gps_module_plugin
import backend.gps.routes as gps_routes
import backend.holo_presence as holo_presence_module_plugin
import backend.holo_presence.routes as holo_presence_routes
import backend.knowledge as knowledge_module_plugin
import backend.knowledge.routes as knowledge_routes
import backend.logocreator as logocreator_module_plugin
import backend.logocreator.routes as logocreator_routes
import backend.mail as mail_module_plugin
import backend.mail.routes as mail_routes
import backend.marketplace as marketplace_module_plugin
import backend.marketplace.routes as marketplace_routes
import backend.media_hotspots as media_hotspots_module_plugin
import backend.media_hotspots.routes as media_hotspots_routes
import backend.medialibrary as medialibrary_module_plugin
import backend.medialibrary.routes as medialibrary_routes

# OPT-IN ONLY, admin discretion - see backend/ml/__init__.py for why
# (synchronous compute-heavy training, per-org shared "active model").
import backend.ml as ml_module_plugin
import backend.ml.routes as ml_routes
import backend.monitor_agent.routes as monitor_agent_routes
import backend.operator.routes as operator_routes
import backend.payments as payments_module_plugin
import backend.payments.routes as payments_routes
import backend.professor as professor_module_plugin
import backend.professor.routes as professor_routes
import backend.profile.routes as profile_routes
import backend.projects as projects_module_plugin
import backend.projects.routes as projects_routes
import backend.schaltzentrale.routes as schaltzentrale_routes
import backend.security as security_module_plugin
import backend.security.routes as security_routes
import backend.sentinel as sentinel_module_plugin
import backend.sentinel.canary as sentinel_canary
import backend.sentinel.routes as sentinel_routes
import backend.sitebuilder as sitebuilder_module_plugin
import backend.sitebuilder.routes as sitebuilder_routes
import backend.skillforge as skillforge_module_plugin
import backend.skillforge.routes as skillforge_routes
import backend.studio as studio_module_plugin
import backend.studio.routes as studio_routes
import backend.vault.routes as vault_routes
import backend.video_ai as video_ai_module_plugin
import backend.video_ai.routes as video_ai_routes
import backend.wissenszweig as wissenszweig_module_plugin
import backend.wissenszweig.routes as wissenszweig_routes
from backend.core import api_deps, auth_repository
from backend.core.auth_exceptions import AuthenticationError, RateLimitExceededError
from backend.core.auth_service import AuthService
from backend.core.capabilities import sync_registry_to_db
from backend.core.chronos_bridge import report_to_chronos
from backend.core.config import DBConfig
from backend.core.rate_limit import InMemoryRateLimiter, RateLimitMiddleware, resolve_client_ip
from backend.core.registry import ModuleRegistry, discover_and_register
from backend.core.repository import connection
from backend.core.request_logging import RequestIDMiddleware, configure_logging, request_id_var
from backend.core.web_security import security_headers
from backend.schaltzentrale.middleware import ExternalCommGateMiddleware, install_httpx_patch
from backend.sentinel.enforcement import SentinelBanMiddleware

log = logging.getLogger("backend.main")

_auth_service: AuthService | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    DBConfig.validate()

    log.info("[Startup] Discovering domain modules ...")
    registry = ModuleRegistry()
    discover_and_register(registry)
    sync_registry_to_db(registry)
    log.info(
        "[Startup] %d module(s) registered: %s",
        len(registry),
        ", ".join(m.key for m in registry.all()),
    )

    # Install HTTPX patch for external_comm enforcement
    install_httpx_patch()

    knowledge_module_plugin.register_permissions()
    crm_module_plugin.register_permissions()
    professor_module_plugin.register_permissions()
    ai_module_plugin.register_permissions()
    affiliate_module_plugin.register_permissions()
    credits_module_plugin.register_permissions()
    marketplace_module_plugin.register_permissions()
    codes_module_plugin.register_permissions()
    medialibrary_module_plugin.register_permissions()
    media_hotspots_module_plugin.register_permissions()
    clearsearch_module_plugin.register_permissions()
    community_module_plugin.register_permissions()
    collaborate_module_plugin.register_permissions()
    agent_module_plugin.register_permissions()
    studio_module_plugin.register_permissions()
    content_manager_module_plugin.register_permissions()
    design_module_plugin.register_permissions()
    mail_module_plugin.register_permissions()
    ml_module_plugin.register_permissions()
    projects_module_plugin.register_permissions()
    security_module_plugin.register_permissions()
    wissenszweig_module_plugin.register_permissions()
    skillforge_module_plugin.register_permissions()
    sitebuilder_module_plugin.register_permissions()
    logocreator_module_plugin.register_permissions()
    bookcreator_module_plugin.register_permissions()
    content_creator_module_plugin.register_permissions()
    video_ai_module_plugin.register_permissions()
    aimedia_module_plugin.register_permissions()
    marketplace_module_plugin.register_permissions()
    payments_module_plugin.register_permissions()
    circuitlab_module_plugin.register_permissions()
    game_engine_module_plugin.register_permissions()
    gps_module_plugin.register_permissions()
    code_agent_module_plugin.register_permissions()
    dependency_graph_module_plugin.register_permissions()
    failure_point_module_plugin.register_permissions()
    corporate_memory_module_plugin.register_permissions()
    early_warning_module_plugin.register_permissions()
    holo_presence_module_plugin.register_permissions()
    sentinel_module_plugin.register_permissions()
    # Canary-Ausloeser hoert auf auth.login_failed (bestehender EventBus)
    # und braucht deshalb keine eigene Aenderung an auth_service.py.
    # Idempotent - ein zweiter Lifespan haengt keinen zweiten Subscriber.
    sentinel_module_plugin.install_hooks()
    # AFTER register_permissions(): wires check_capability/on_event/
    # guard_ai_* into backend.core.security_hooks (see that module's
    # header on why disabling backend/security can never weaken
    # enforcement, only remove the extra audit/anomaly/capability layers).
    security_module_plugin.activate()

    global _auth_service
    _auth_service = AuthService()
    api_deps.init(_auth_service, registry)

    log.info("[Startup] Discovering skills ...")
    from backend.skillforge.registry import SkillRegistry, discover_and_register_skills

    skill_registry = SkillRegistry()
    discover_and_register_skills(skill_registry)
    skillforge_routes.init(skill_registry)
    log.info(
        "[Startup] %d skill(s) registered: %s",
        len(skill_registry),
        ", ".join(s.key for s in skill_registry.all()),
    )

    log.info("[Startup] Loading KnowledgeService ...")
    from knowledge_module import KnowledgeService

    # ../features_Module/Knowledge System, not ../Knowledge System - not
    # siblings, see docker-compose.yml's comment on the same path.
    data_dir = os.environ.get(
        "ROBE_KNOWLEDGE_DATA_DIR",
        "../features_Module/Knowledge System/data",
    )
    knowledge_service = KnowledgeService(data_dir)
    knowledge_routes.init(knowledge_service)
    app.state.knowledge_service = knowledge_service
    # Professor-Bruecke: ask_grounded greift damit auch auf die
    # Wissensdatenbank zu (semantisch + keyword), siehe
    # backend/professor/knowledge_bridge.py. Das Embedding-Modell laedt
    # im HINTERGRUND (erster Aufruf kostet sonst auf der ersten
    # Nutzerfrage Minuten unter RAM-Druck - Live-Befund 2026-09-25).
    from backend.professor import knowledge_bridge

    knowledge_bridge.set_knowledge_service(knowledge_service)
    threading.Thread(
        target=knowledge_bridge.warm_up,
        name="knowledge-warmup",
        daemon=True,
    ).start()

    log.info("[Startup] Loading ClearSearchService ...")
    from backend.clearsearch.bridge import ClearSearchService

    clearsearch_service = ClearSearchService()
    clearsearch_routes.init(clearsearch_service)
    app.state.clearsearch_service = clearsearch_service

    log.info("[Startup] Starting module Watchdog Agent ...")
    from backend.monitor_agent.watchdog import start_watchdog

    start_watchdog(registry)

    log.info("[Startup] Ready.")

    yield

    log.info("[Shutdown] Closing KnowledgeService ...")
    try:
        knowledge_service.close()
    except Exception as e:
        log.warning("close() meldete: %s: %s", type(e).__name__, e)


app = FastAPI(title="RoBe Co-Operator", version="0.1.0", lifespan=lifespan)

_cors_origins = [o.strip() for o in os.environ.get("ROBE_CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)


# FastAPI's auto-generated introspection pages - Swagger UI/ReDoc load
# their JS/CSS from a CDN and run inline scripts to bootstrap, which the
# strict default-src 'self' CSP below correctly blocks for real API
# responses but would also block here, breaking the docs UI itself with
# no security benefit (these paths serve no tenant data, only the
# platform's own OpenAPI schema).
_DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path in _DOCS_PATHS:
            return response
        hsts = os.environ.get("ROBE_HTTPS", "0") == "1"
        for k, v in security_headers(hsts=hsts).items():
            response.headers[k] = v
        return response


app.add_middleware(_SecurityHeadersMiddleware)

# Trusted-proxy-aware client-IP resolution - computed once, used both by
# rate limiting below AND by /auth/login's Chronos report (see that
# endpoint) so both agree on the same real client IP instead of two
# implementations that could drift apart.
_trusted_proxies = [
    p.strip() for p in os.environ.get("ROBE_TRUSTED_PROXIES", "").split(",") if p.strip()
]

# Rate-Limiting: in-process, kein Redis/Netzwerk (offline-first - siehe
# memory feedback_offline_first). Default AN mit grosszuegigem Limit,
# nicht Knowledge Systems "aus" per Default - dieses System ist auf
# oeffentliche Erreichbarkeit hin gebaut, "sicher per Default" passt
# besser als "muss manuell aktiviert werden". 0 = aus, fuer lokale Dev-
# Iteration falls das Limit dabei stoert.
_rate_limit_rpm = int(os.environ.get("ROBE_RATE_LIMIT_RPM", "120") or "0")
if _rate_limit_rpm > 0:
    app.add_middleware(
        RateLimitMiddleware,
        limiter=InMemoryRateLimiter(rpm=_rate_limit_rpm),
        trusted_proxies=_trusted_proxies,
        on_limit_exceeded=lambda client_ip, path: report_to_chronos(
            "rate_limited",
            client_ip,
            payload=path,
        ),
    )

# Reihenfolge (Starlette stapelt von innen nach aussen, zuletzt
# hinzugefuegt = aussen = sieht die Anfrage zuerst): SentinelBan ->
# RequestID -> RateLimit -> SecurityHeaders -> CORS -> App. Request-ID
# zuerst, damit sie schon in einer 429-Antwort/deren Logs verfuegbar
# ist - gleiches Prinzip wie in Knowledge Systems api.py (dortiger
# Kommentar: K7). SentinelBan ganz aussen: eine gebannte Quelle soll
# SOFORT draussen sein, bevor sie Tokens des Rate-Limiters oder
# Log-Eintraege verbraucht - und 403 ist kein Status, den das
# Rate-Limiting sonst sehen muesste.
app.add_middleware(RequestIDMiddleware)
app.add_middleware(ExternalCommGateMiddleware)
app.add_middleware(SentinelBanMiddleware)


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException):
    """Einheitliches Fehlerformat, request_id auch im Body (nicht nur im
    Header) - hilft beim Support/Debugging ohne Header-Zugriff noetig zu
    haben. Ersetzt nur die Darstellung, nicht FastAPIs Fehlerbehandlung."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "request_id": request_id_var.get()},
        headers=exc.headers,
    )


def _json_safe(value):
    """Nicht-serialisierbare Floats (NaN/Infinity) in einem
    Validierungs-Fehlerbaum ersetzen - rekursiv ueber dicts/lists."""
    if isinstance(value, float) and not math.isfinite(value):
        if math.isnan(value):
            return "NaN"
        return "Infinity" if value > 0 else "-Infinity"
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


@app.exception_handler(RequestValidationError)
async def _request_validation_handler(request: Request, exc: RequestValidationError):
    """FastAPI baut die 422-Ausgabe aus exc.errors() und rendert sie mit
    json.dumps(allow_nan=False). Kommt in einem Float-Feld ein
    NaN/Infinity an, explodiert damit genau die Antwort, die den Fehler
    melden soll - der Request landet als 500 statt als 422 im Client
    (TestClient gibt die Exception sogar direkt zurueck). Gleiche Form
    wie FastAPI-Standard ({"detail": [...]}), nur dass nicht
    darstellbare Floats als Text statt als Zahl stehen."""
    return JSONResponse(
        status_code=422,
        content={"detail": _json_safe(jsonable_encoder(exc.errors()))},
    )


app.include_router(knowledge_routes.router)
app.include_router(crm_routes.router)
app.include_router(professor_routes.router)
app.include_router(ai_routes.router)
app.include_router(affiliate_routes.router)
# Public cookieless tracking-link redirect (GET /go/...) - no /api prefix
# and no auth gate, see backend/affiliate/redirect.py.
app.include_router(affiliate_redirect.router)
app.include_router(credits_routes.router)
app.include_router(marketplace_routes.router)
app.include_router(codes_routes.router)
app.include_router(medialibrary_routes.router)
app.include_router(media_hotspots_routes.router)
app.include_router(clearsearch_routes.router)
app.include_router(community_routes.router)
app.include_router(collaborate_routes.router)
app.include_router(agent_routes.router)
app.include_router(studio_routes.router)
app.include_router(content_manager_routes.router)
app.include_router(dependency_graph_routes.router)
app.include_router(failure_point_routes.router)
app.include_router(corporate_memory_routes.router)
app.include_router(early_warning_routes.router)
app.include_router(design_routes.router)
app.include_router(mail_routes.router)
app.include_router(ml_routes.router)
app.include_router(projects_routes.router)
app.include_router(security_routes.router)
app.include_router(operator_routes.router)
app.include_router(monitor_agent_routes.router)
app.include_router(wissenszweig_routes.router)
app.include_router(skillforge_routes.router)
app.include_router(sitebuilder_routes.router)
app.include_router(logocreator_routes.router)
app.include_router(bookcreator_routes.router)
app.include_router(content_creator_routes.router)
app.include_router(video_ai_routes.router)
app.include_router(aimedia_routes.router)
app.include_router(payments_routes.router)
app.include_router(circuitlab_routes.router)
app.include_router(circuitlab_orchestration_routes.router)
app.include_router(game_engine_routes.router)
app.include_router(gdpr_routes.router)
app.include_router(gps_routes.router)
app.include_router(holo_presence_routes.router)
app.include_router(sentinel_routes.router)
# Honeypot-Pfade bewusst OHNE Gate: so greifen Angreifer auch wirklich
# zu. Antwortet nur, wenn fuer den Pfad eine aktive Falle steht
# (backend/sentinel/canary.py) - sonst unsichtbare 404.
app.include_router(sentinel_canary.honeypot_router)
app.include_router(code_agent_routes.router)
app.include_router(schaltzentrale_routes.router)
app.include_router(profile_routes.router)
app.include_router(vault_routes.router)


# ============================================================================
# Core auth-routes: duenne HTTP-Bindung um das bereits fertige, per
# tests/test_auth.py bewiesene AuthService - keine neue Auth-Logik hier.
# ============================================================================


class LoginRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class RegisterRequest(BaseModel):
    org_name: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)


class ForgotPasswordRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)


class ResetPasswordRequest(BaseModel):
    reset_token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


def _auth() -> AuthService:
    if _auth_service is None:
        raise HTTPException(503, "Auth-Service nicht initialisiert")
    return _auth_service


@app.post("/auth/login")
def login(req: LoginRequest, request: Request):
    # Trusted-proxy-aware, same resolution the rate limiter uses (see
    # module-level _trusted_proxies above) - request.client.host alone
    # would be the Cloudflare Tunnel container's internal IP behind the
    # tunnel, not the real caller.
    ip = resolve_client_ip(request.scope, _trusted_proxies)
    try:
        org_id = UUID(req.org_id)
    except ValueError:
        org = auth_repository.get_organization_by_name(req.org_id.strip())
        if org is None:
            raise HTTPException(401, "Organisation nicht gefunden")
        org_id = org["id"]
    try:
        return _auth().authenticate(org_id, req.username, req.password, ip=ip)
    except RateLimitExceededError as e:
        raise HTTPException(429, str(e), headers={"Retry-After": str(e.retry_after)}) from e
    except AuthenticationError as e:
        report_to_chronos("login_failed", ip, payload=req.username)
        raise HTTPException(401, str(e)) from e


@app.post("/auth/refresh")
def refresh(req: RefreshRequest):
    try:
        return _auth().refresh_access_token(req.refresh_token)
    except AuthenticationError as e:
        raise HTTPException(401, str(e)) from e


@app.post("/auth/logout")
def logout(req: LogoutRequest):
    return {"revoked": _auth().revoke_refresh_token(req.refresh_token)}


@app.get("/auth/sessions")
def sessions(claims=Depends(api_deps.get_current_claims)):
    return {"sessions": _auth().get_active_sessions(UUID(claims["user_id"]))}


@app.post("/auth/register")
def register(req: RegisterRequest, request: Request):
    ip = resolve_client_ip(request.scope, _trusted_proxies)
    try:
        result = _auth().register(
            api_deps.get_registry(), req.org_name, req.username, req.password, ip=ip
        )
        return result
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    except RateLimitExceededError as e:
        raise HTTPException(429, str(e), headers={"Retry-After": str(e.retry_after)}) from e
    except AuthenticationError as e:
        raise HTTPException(401, str(e)) from e


@app.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    try:
        org_id = UUID(req.org_id)
    except ValueError as e:
        raise HTTPException(422, "org_id ist keine gueltige UUID") from e
    # Always the same response shape whether or not the account exists -
    # see AuthService.request_password_reset()'s docstring for why the
    # token itself (not an emailed link) is what's returned here.
    token = _auth().request_password_reset(org_id, req.username)
    return {"reset_token": token}


@app.post("/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    try:
        _auth().reset_password(req.reset_token, req.new_password)
    except AuthenticationError as e:
        raise HTTPException(401, str(e)) from e
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    return {"ok": True}


@app.post("/auth/change-password")
def change_password(req: ChangePasswordRequest, claims=Depends(api_deps.get_current_claims)):
    try:
        _auth().change_password(UUID(claims["user_id"]), req.old_password, req.new_password)
    except AuthenticationError as e:
        raise HTTPException(401, str(e)) from e
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    return {"ok": True}


@app.delete("/auth/account")
def delete_account(claims=Depends(api_deps.get_current_claims)):
    _auth().delete_own_account(UUID(claims["user_id"]))
    return {"deleted": True}


# ============================================================================
# Health/Readiness
# ============================================================================


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    try:
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
    except Exception as e:
        raise HTTPException(503, f"Datenbank nicht erreichbar: {type(e).__name__}: {e}") from e
    if getattr(app.state, "knowledge_service", None) is None:
        raise HTTPException(503, "Knowledge-Service nicht bereit")
    return {"status": "ready"}
