# backend/ai/ai_service.py
#
# Org-scoped orchestration for RoBe AI Runtime - ported from the standalone
# RoBe AI Provider Manager module's backend/ai/manager.py
# (AIProviderManager). Same provider catalog (Gemini/OpenAI/DeepSeek/
# Anthropic/Ollama) and the same IAIProvider interface, three deliberate
# changes:
#
# 1. Org-scoped, not a single global instance. The source read/wrote ONE
#    shared data/ai_config.json file for the whole process - fine for a
#    single-user CLI tool, not for a multi-tenant platform where every
#    org needs its own active provider, model and keys. AIService(org_id)
#    loads that one org's settings on construction, same shape as
#    AuthService/ml_service.py - no shared mutable state between orgs.
#    (Settings are loaded fresh on every construction, and routes build
#    one service per request - so there is no cross-process staleness
#    window in the production path.)
#
# 2. Postgres instead of a local JSON file, and ENCRYPTED. The source
#    wrote API keys to data/ai_config.json in PLAIN TEXT - a real gap the
#    source module never closed. ai_credentials_repository.py reuses the
#    exact same Fernet-blob-per-org pattern already proven in Baustein
#    5's api_credentials_repository.py (see backend/core/crypto.py) -
#    not the SAME table, a new one (see migration 011's header for why).
#    (Fernet is encrypt-then-MAC, so the blob already carries integrity -
#    no extra HMAC layer needed.)
#
# 3. Automatic Ollama -> fallback-provider failover on connection
#    failure, but ONLY with the org's explicit consent
#    (allow_cloud_fallback, D1/E4). Without consent the connection error
#    propagates so the client can degrade gracefully instead of silently
#    sending the org's prompt to a third-country cloud.
#
# Decrypt errors (AICredentialDecryptionError) propagate as an unhandled
# 500 BY DESIGN - they surface during _service()/AIService() construction,
# before any provider logic runs, so _ai_error_to_http never sees them.
# Fail-loud with an alarm beats fail-silent on defaults; see
# ai_credentials_repository.py for why swallowing them loses keys.
from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from typing import Any
from uuid import UUID

import requests

from backend.ai.ai_credentials_repository import AICredentialsRepository
from backend.ai.ai_interfaces import IAIProvider
from backend.ai.providers import PROVIDER_CLASSES as _DEFAULT_PROVIDER_CLASSES
from backend.ai.providers import (
    PROVIDER_INFO,
    AIAuthError,
    AIConnectionError,
    AIProviderError,
    AIUnavailableError,
    build_provider,
)
from backend.core.config import AIConfig
from backend.core.events import EventBus
from backend.core.security_hooks import guard_ai_input, guard_ai_output

__all__ = [
    "PROVIDER_CLASSES",
    "AIService",
    "NotLocalProviderError",
    "validate_ollama_base_url",
]

logger = logging.getLogger(__name__)

PROVIDER_CLASSES: dict[str, type] = dict(_DEFAULT_PROVIDER_CLASSES)

# Which settings field holds a given provider's API key. Ollama
# deliberately has no entry - it authenticates via base_url, not a key.
_API_KEY_FIELD_BY_PROVIDER = {
    "gemini": "gemini_api_key",
    "openai": "openai_api_key",
    "deepseek": "deepseek_api_key",
    "anthropic": "anthropic_api_key",
}

# Hosts that must never become an Ollama base URL (S2): cloud metadata
# endpoints. Literal-IP analysis below additionally rejects link-local
# and other non-loopback private ranges.
_SSRF_BLOCKED_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.169.253",
        "metadata.google.internal",
    }
)


class NotLocalProviderError(ValueError):
    """Active provider is not Ollama - local-only operation refused (→ HTTP 409)."""

    pass


def validate_ollama_base_url(base_url: str) -> str:
    """Validates an Ollama base URL against SSRF (S2/B15).

    Rules: http/https scheme only; no credentials in URL; blocklisted
    metadata hosts rejected; literal IPs allowed only if loopback
    (127/8, ::1) - the default local setup - all other private/
    link-local/reserved ranges rejected. Plain hostnames (e.g. LAN
    names) pass syntactically; DNS rebinding past this check is a
    documented residual risk, not a bypass of the listed vectors.
    Redirects are handled separately: every request against this URL
    runs with allow_redirects=False, so a cooperating server cannot
    bounce the call to an unvalidated target.

    Returns the normalized URL. Raises ValueError (→ HTTP 422).
    """
    raw = (base_url or "").strip()
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError as e:
        raise ValueError(f"Ungültige Ollama-URL: {raw!r:.80}") from e
    if parts.scheme not in ("http", "https"):
        raise ValueError("Ollama-URL muss mit http:// oder https:// beginnen")
    if parts.username or parts.password:
        raise ValueError("Ollama-URL darf keine Zugangsdaten enthalten")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("Ollama-URL braucht einen Hostnamen")
    if host in _SSRF_BLOCKED_HOSTS or host.endswith(".internal"):
        raise ValueError(f"Ollama-URL zeigt auf ein blockiertes internes Ziel: {host}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass  # plain hostname - passes (see docstring)
    else:
        if not ip.is_loopback:
            raise ValueError(
                f"Ollama-URL mit nicht-lokaler IP ist nicht erlaubt: {host} "
                "(erlaubt: localhost/127.0.0.1/::1 für lokales Ollama)"
            )
    return parts.geturl()


def _publish_safe(event: str, payload: dict[str, Any]) -> None:
    """EventBus must never break an answer - but if it is down, ops must
    see it in production logs (warning, not debug)."""
    try:
        EventBus().publish(event, payload)
    except Exception as e:
        logger.warning("Event %s dropped: %s", event, str(e)[:200])


class AIService:
    def __init__(self, org_id: UUID, providers: dict[str, type] | None = None):
        # `providers` override exists only so tests can inject fake
        # IAIProvider implementations without a real network call or a
        # real API key - see tests/test_ai.py. Production callers should
        # never pass this.
        self.org_id = org_id
        self._provider_classes = providers if providers is not None else None
        self._repo = AICredentialsRepository()
        self._settings = self._repo.get(org_id)
        # Built provider instances, keyed by name, valid only for the
        # settings snapshot they were built from (P5: no double
        # client-init per ask, no stale instances after a settings
        # change through this service).
        self._provider_cache: dict[str, tuple[str, IAIProvider]] = {}

    # -- internal ---------------------------------------------------------------

    def _settings_snapshot(self, name: str) -> str:
        if name == "ollama":
            return "|".join(
                [
                    self._settings.get("ollama_base_url") or "",
                    self._settings.get("active_model") or "",
                ]
            )
        key_field = _API_KEY_FIELD_BY_PROVIDER.get(name, "")
        return "|".join(
            [
                self._settings.get(key_field) or "",
                self._settings.get("active_model") or "",
            ]
        )

    def _build_provider(self, name: str) -> IAIProvider:
        snapshot = self._settings_snapshot(name)
        cached = self._provider_cache.get(name)
        if cached and cached[0] == snapshot:
            return cached[1]
        if name == "ollama":
            provider = build_provider(
                name,
                classes=self._provider_classes,
                base_url=self._settings.get("ollama_base_url") or "http://localhost:11434",
                model=self._settings.get("active_model"),
            )
        else:
            # Unknown names are rejected inside build_provider (ValueError).
            key_field = _API_KEY_FIELD_BY_PROVIDER.get(name)
            provider = build_provider(
                name,
                classes=self._provider_classes,
                api_key=self._settings.get(key_field) if key_field else None,
                model=self._settings.get("active_model"),
            )
        self._provider_cache[name] = (snapshot, provider)
        return provider

    @property
    def active_provider_name(self) -> str:
        return self._settings.get("active_provider") or AIConfig.DEFAULT_PROVIDER

    @property
    def fallback_provider_name(self) -> str:
        return self._settings.get("fallback_provider") or AIConfig.DEFAULT_FALLBACK_PROVIDER

    @property
    def cloud_fallback_allowed(self) -> bool:
        """Explicit per-org opt-in for cloud fallback (D1/E4, default off)."""
        return bool(self._settings.get("allow_cloud_fallback", False))

    # -- public API ---------------------------------------------------------------

    def ask(self, prompt: str, model: str | None = None, timeout_seconds: int | None = None) -> str:
        """Sends a prompt to the org's active provider. See ask_detailed()
        for the same call with routing metadata."""
        return self.ask_detailed(prompt, model=model, timeout_seconds=timeout_seconds)["answer"]

    def ask_detailed(
        self, prompt: str, model: str | None = None, timeout_seconds: int | None = None
    ) -> dict[str, Any]:
        """Like ask(), plus routing metadata (M6): which provider
        answered, whether the fallback fired, and why.

        Fallback fires only when ALL of these hold: active is Ollama,
        Ollama is unreachable (connection/timeout, not a content error),
        the org opted into cloud fallback, and a key is on file for the
        fallback provider. The fallback uses its OWN default model (B5) -
        forwarding the caller's Ollama model name to another provider's
        API would only produce an API error. Every other provider's
        errors propagate as exceptions (B1), never as answer strings.

        timeout_seconds reaches every provider (B1), not just Ollama -
        a 600s chapter request keeps its budget even when the fallback
        fires.
        """
        prompt = guard_ai_input(prompt, self.org_id)

        provider_name = self.active_provider_name
        provider = self._build_provider(provider_name)
        active_model = model or self._settings.get("active_model")

        if provider_name != "ollama":
            # timeout only when explicitly set: older/custom providers
            # (and test fakes) may not accept the kwarg at all.
            extra_kwargs = {"timeout": timeout_seconds} if timeout_seconds is not None else {}
            answer = provider.ask(prompt, active_model, **extra_kwargs)
            return {
                "answer": guard_ai_output(answer, self.org_id),
                "provider": provider_name,
                "fallback_used": False,
                "reason": None,
            }

        ollama_kwargs = {"timeout": timeout_seconds} if timeout_seconds is not None else {}
        try:
            answer = provider.ask(prompt, active_model, **ollama_kwargs)
        except (requests.ConnectionError, requests.Timeout, AIConnectionError) as exc:
            fallback_name = self.fallback_provider_name
            key_field = _API_KEY_FIELD_BY_PROVIDER.get(fallback_name)
            has_fallback_key = bool(key_field and (self._settings.get(key_field) or "").strip())
            if fallback_name == provider_name or not has_fallback_key:
                raise
            if not self.cloud_fallback_allowed:
                raise
            fallback = self._build_provider(fallback_name)
            reason = str(exc)[:200]
            _publish_safe(
                "ai.fallback_used",
                {
                    "org_id": str(self.org_id),
                    "from_provider": provider_name,
                    "to_provider": fallback_name,
                    "reason": reason,
                },
            )
            try:
                fallback_kwargs = (
                    {"timeout": timeout_seconds} if timeout_seconds is not None else {}
                )
                fallback_answer = fallback.ask(prompt, None, **fallback_kwargs)
            except AIAuthError:
                # "No key at all" (e.g. key deleted between the check above
                # and this call) - actionable, not an availability state.
                # NOTE: a key the provider REJECTS does not land here: SDK
                # auth errors surface as AIProviderError (→ 503 below).
                # Mapping those to AIAuthError is a separate ticket.
                raise
            except AIProviderError as fallback_exc:
                raise AIUnavailableError(
                    f"Fallback {fallback_name} ist ebenfalls fehlgeschlagen: "
                    f"{str(fallback_exc)[:200]}"
                ) from fallback_exc
            return {
                "answer": guard_ai_output(fallback_answer, self.org_id),
                "provider": fallback_name,
                "fallback_used": True,
                "reason": reason,
            }
        answer = guard_ai_output(answer, self.org_id)
        return {
            "answer": answer,
            "provider": provider_name,
            "fallback_used": False,
            "reason": None,
        }

    def switch_provider(self, name: str) -> None:
        if not self._provider_name_known(name):
            raise ValueError(f"Unbekannter KI-Provider: {name}")
        self._settings = self._repo.update_fields(self.org_id, active_provider=name)
        _publish_safe("provider.switched", {"org_id": str(self.org_id), "provider": name})

    def _provider_name_known(self, name: str) -> bool:
        registry = (
            self._provider_classes if self._provider_classes is not None else PROVIDER_CLASSES
        )
        return name in registry

    def set_model(self, model_name: str) -> None:
        self._settings = self._repo.update_fields(self.org_id, active_model=model_name)
        _publish_safe("model.changed", {"org_id": str(self.org_id), "model": model_name})

    def set_fallback_provider(self, name: str) -> None:
        if not self._provider_name_known(name):
            raise ValueError(f"Unbekannter KI-Provider: {name}")
        self._settings = self._repo.update_fields(self.org_id, fallback_provider=name)
        _publish_safe("fallback_provider.changed", {"org_id": str(self.org_id), "provider": name})

    def set_cloud_fallback_allowed(self, allowed: bool) -> None:
        """Opt-in/out for automatic cloud fallback on Ollama outage (D1/E4)."""
        self._settings = self._repo.update_fields(self.org_id, allow_cloud_fallback=bool(allowed))
        _publish_safe(
            "cloud_fallback_consent.changed",
            {"org_id": str(self.org_id), "allowed": bool(allowed)},
        )

    def set_api_key(self, provider_name: str, key: str) -> None:
        key_field = _API_KEY_FIELD_BY_PROVIDER.get(provider_name)
        if key_field is None:
            if provider_name == "ollama":
                raise ValueError("Ollama benötigt keinen API-Key - siehe set_ollama_base_url()")
            raise ValueError(f"Unbekannter KI-Provider: {provider_name}")
        if not (key or "").strip():
            # Empty is not "no key on file" - it is an explicit clear.
            # Deletion has its own path (delete_credentials); storing ""
            # would leave has_key() False while the blob claims a key
            # was set. Reject instead of guessing.
            raise ValueError(
                f"Leerer API-Key für {provider_name} - zum Löschen credentials löschen"
            )
        # Never log the key itself (B16) - only the provider name travels.
        self._settings = self._repo.update_fields(self.org_id, **{key_field: key})
        _publish_safe("api_key.updated", {"org_id": str(self.org_id), "provider": provider_name})

    def set_ollama_base_url(self, base_url: str) -> None:
        self._settings = self._repo.update_fields(
            self.org_id, ollama_base_url=validate_ollama_base_url(base_url)
        )

    def has_key(self, provider_name: str) -> bool:
        key_field = _API_KEY_FIELD_BY_PROVIDER.get(provider_name)
        if key_field is None:
            # Unknown providers have no key (B12); ollama needs none.
            # has_key("unknown") is False, has_key("ollama") is True.
            # Callers that must distinguish "unknown" from "no key" use
            # knows_provider() (the status route answers 404 for unknown).
            return provider_name == "ollama"

        return bool((self._settings.get(key_field) or "").strip())

    def knows_provider(self, provider_name: str) -> bool:
        """Whether this name is a provider at all (vs. has_key's key check)."""
        return self._provider_name_known(provider_name)

    def list_providers(self) -> list[str]:
        registry = (
            self._provider_classes if self._provider_classes is not None else PROVIDER_CLASSES
        )
        return list(registry.keys())

    def get_provider_info(self, name: str | None = None) -> dict[str, Any]:
        name = name or self.active_provider_name
        info = PROVIDER_INFO.get(name)
        if info is not None:
            return dict(info)
        return {}

    def get_all_providers_info(self) -> dict[str, dict[str, Any]]:
        """Static metadata only - no provider is instantiated here (B9/P1:
        instantiating OllamaProvider pings nothing, but the old code built
        all five clients per call, including a 10s-timeout HTTP round-trip
        when Ollama was down)."""
        if self._provider_classes is not None:
            return {
                name: dict(PROVIDER_INFO.get(name, {"name": name, "requires_api_key": True}))
                for name in self._provider_classes
            }
        return {name: dict(info) for name, info in PROVIDER_INFO.items()}

    def is_local(self) -> bool:
        return self.get_provider_info().get("is_local", False)

    def get_config(self) -> dict[str, Any]:
        """Non-secret settings only - never returns a raw API key. Use
        has_key() to check whether one is on file."""
        return {
            "active_provider": self.active_provider_name,
            "active_model": self._settings.get("active_model"),
            "fallback_provider": self.fallback_provider_name,
            "allow_cloud_fallback": self.cloud_fallback_allowed,
            "ollama_base_url": self._settings.get("ollama_base_url"),
        }

    def delete_credentials(self) -> bool:
        """Deletes the org's whole AI settings blob (keys + selection)."""
        self._settings = {}
        self._provider_cache.clear()
        return self._repo.delete(self.org_id)

    def ollama_reachable(self, timeout: int = 3) -> bool:
        """Short-timeout liveness probe for the health endpoint (O4)."""
        base_url = self._settings.get("ollama_base_url") or "http://localhost:11434"
        try:
            # allow_redirects=False: see OllamaProvider.ask() - the
            # redirect target of an org-controlled URL is never validated.
            response = requests.get(
                f"{base_url}/api/tags", timeout=timeout, verify=True, allow_redirects=False
            )
            response.raise_for_status()
            return True
        except Exception:
            return False

    def health(self) -> dict[str, Any]:
        """Offline-capability signal for clients (O4): can this org work
        right now without any cloud call?"""
        local_ok = self.ollama_reachable()
        fallback_name = self.fallback_provider_name
        key_field = _API_KEY_FIELD_BY_PROVIDER.get(fallback_name)
        fallback_ready = bool(
            key_field
            and (self._settings.get(key_field) or "").strip()
            and self.cloud_fallback_allowed
        )
        return {
            "ollama_reachable": local_ok,
            "active_provider": self.active_provider_name,
            "fallback_provider": fallback_name,
            "fallback_ready": fallback_ready,
            "offline_capable": self.active_provider_name == "ollama" and local_ok,
        }

    def download_local_model(self, model_name: str) -> str:
        if self.active_provider_name != "ollama":
            raise NotLocalProviderError(
                "Modell-Download ist nur im lokalen Modus (Ollama) möglich."
            )
        provider = self._build_provider("ollama")
        download = getattr(provider, "download_model", None)
        if download is None:
            raise NotLocalProviderError("Der aktive Provider unterstützt keinen Modell-Download.")
        return download(model_name)

    def get_local_models(self) -> dict[str, Any]:
        """Live daemon list first; hardcoded list only as labeled fallback (D4)."""
        provider = self._build_provider("ollama")
        get_models = getattr(provider, "get_available_models", None)
        if get_models is None:
            from backend.ai.providers import HARDCODED_LOCAL_MODELS

            return {"models": list(HARDCODED_LOCAL_MODELS), "live": False}
        try:
            return {"models": get_models(), "live": True}
        except AIProviderError:
            from backend.ai.providers import HARDCODED_LOCAL_MODELS

            return {"models": list(HARDCODED_LOCAL_MODELS), "live": False}
