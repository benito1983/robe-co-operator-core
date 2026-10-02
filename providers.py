# backend/ai/providers.py
#
# Concrete AI provider implementations - ported nearly unchanged from the
# standalone RoBe AI Provider Manager module's backend/ai/providers.py.
# German error strings are kept deliberately: they are end-user-facing
# text that would eventually surface in a UI, same convention already
# used for AuthenticationError's messages in backend/core/auth_service.py
# (see robe-analytics.md "Sprach-Entscheidung" - code/comments English,
# product-facing text German).
#
# Two deliberate behavior changes vs. the source:
#
# 1. Errors are EXCEPTIONS, not answer strings (B1). Every ask() failure
#    raises AIProviderError (or a subclass) instead of returning
#    "Fehler bei X: ..." as a normal answer. Callers can no longer mistake
#    an error for a reply, and AIService.ask()'s fallback logic can
#    actually trigger on them. except AIConnectionError is the documented
#    catch site for "unreachable" across all providers; ai_service.py
#    additionally catches raw requests.ConnectionError/Timeout so custom
#    injected providers are covered too.
#
# 2. NO environment-variable key fallback (B2/S3). A provider only ever
#    uses the api_key it was explicitly constructed with (which
#    AIService takes from the org's own encrypted settings). A
#    process-wide GEMINI_API_KEY must never silently pay for - and read
#    the prompts of - an org that configured no key at all.
from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from typing import Any

import requests

from backend.core.config import AIConfig

from .ai_interfaces import IAIProvider

__all__ = [
    "PROVIDER_CLASSES",
    "PROVIDER_INFO",
    "AIAuthError",
    "AIConnectionError",
    "AIProviderError",
    "AIUnavailableError",
    "AnthropicProvider",
    "DeepSeekProvider",
    "GeminiProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "build_provider",
    "validate_model_name",
]

logger = logging.getLogger(__name__)


# ─── error hierarchy (B1) ──────────────────────────────────────────


class AIProviderError(Exception):
    """Base for all provider failures. Never returned as an answer string."""

    pass


class AIConnectionError(AIProviderError):
    """Provider unreachable (network down, timeout, DNS). Retryable."""

    pass


class AIAuthError(AIProviderError):
    """Missing credentials (no key configured, client not initialised).

    NOTE: a key the provider REJECTS (401/permission-denied from the
    SDK) currently arrives as AIProviderError, not here - translating
    SDK auth errors per provider is a separate ticket. Callers must not
    read "AIAuthError" as "invalid key".
    """

    pass


class AIUnavailableError(AIProviderError):
    """Nothing left to try (e.g. local down AND no usable fallback)."""

    pass


def _short(exc: BaseException, api_key: str | None = None, limit: int = 300) -> str:
    """Truncated exception text that can never leak the API key (S10)."""
    text = str(exc)[:limit]
    if api_key and len(api_key) > 8:
        text = text.replace(api_key, "***")
    return text


# Log "no key" only once per process instead of on every construction (S4).
_warned_no_key: set[str] = set()
_warned_lock = threading.Lock()


def _warn_no_key_once(provider: str) -> None:
    with _warned_lock:
        if provider not in _warned_no_key:
            _warned_no_key.add(provider)
            logger.warning("Kein %s API-Key hinterlegt.", provider)


# ─── shared static metadata (B9: no instantiation needed) ──────────

PROVIDER_INFO: dict[str, dict[str, Any]] = {
    "gemini": {
        "name": "Gemini",
        "website": "https://ai.google.dev",
        "requires_api_key": True,
        "is_local": False,
    },
    "openai": {
        "name": "OpenAI",
        "website": "https://openai.com",
        "requires_api_key": True,
        "is_local": False,
    },
    "deepseek": {
        "name": "DeepSeek",
        "website": "https://deepseek.com",
        "requires_api_key": True,
        "is_local": False,
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "website": "https://anthropic.com",
        "requires_api_key": True,
        "is_local": False,
    },
    "ollama": {
        "name": "Ollama (lokal)",
        "website": "https://ollama.com",
        "requires_api_key": False,
        "is_local": True,
    },
}

# Hardcoded fallback when the local daemon cannot be reached (D4).
# Explicitly stale-by-design: callers must surface which list they show
# (see AIService.get_local_models() "live" flag).
HARDCODED_LOCAL_MODELS = ["qwen2.5-coder:7b", "llama3.2:3b", "deepseek-r1:7b", "gemma3:4b"]

# Model names for `ollama pull`: no shell is involved (list-form
# subprocess), but a leading "-" would still be parsed as a flag by
# ollama itself (S1). "@" stays allowed so pinned pulls (model@sha256:…)
# keep working.
_MODEL_NAME_PATTERN = re.compile(r"[a-zA-Z0-9_./:@-]{1,128}\Z")


def validate_model_name(model_name: str) -> str:
    """Validates an Ollama model name. Returns the stripped name.

    Raises ValueError (→ HTTP 422) on argument-injection attempts.
    """
    name = (model_name or "").strip()
    if not name or name.startswith("-") or not _MODEL_NAME_PATTERN.fullmatch(name):
        raise ValueError(f"Ungültiger Modellname: {model_name!r:.60}")
    return name


# ─── GEMINI ──────────────────────────────────────────────────


class GeminiProvider(IAIProvider):
    DEFAULT_TIMEOUT_SECONDS = 60

    def __init__(self, api_key: str | None = None, model: str = "gemini-3.6-flash"):
        self.api_key = (api_key or "").strip() or None
        self.model = model
        self.client = self._build_client(self.DEFAULT_TIMEOUT_SECONDS)

    def _build_client(self, timeout_seconds: int):
        """Builds a genai client with the given per-request timeout.

        Client construction is network-free, so rebuilding per distinct
        timeout is cheap - this is what honors a caller's timeout_seconds
        on Gemini (B1), where the SDK only knows client-level timeouts.
        """
        if not self.api_key:
            _warn_no_key_once("Gemini")
            return None
        try:
            from google import genai

            try:
                from google.genai import types

                return genai.Client(
                    api_key=self.api_key,
                    http_options=types.HttpOptions(timeout=int(timeout_seconds * 1000)),
                )
            except Exception:
                return genai.Client(api_key=self.api_key)
        except ImportError:
            logger.warning("google-genai nicht installiert")
            return None

    def _client_for_timeout(self, timeout: int | None):
        if timeout and timeout != self.DEFAULT_TIMEOUT_SECONDS and self.api_key:
            return self._build_client(timeout) or self.client
        return self.client

    def ask(self, prompt: str, model: str | None = None, timeout: int | None = None) -> str:
        if not self.client:
            raise AIAuthError("Fehler: Kein Gemini API-Key hinterlegt.")
        model = model or self.model
        client = self._client_for_timeout(timeout)
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            return response.text or ""
        except Exception as e:
            raise AIProviderError(f"Fehler bei Gemini: {_short(e, self.api_key)}") from e

    def set_model(self, model_name: str) -> None:
        self.model = model_name

    def get_available_models(self) -> list[str]:
        return ["gemini-3.6-flash", "gemini-3.7-flash", "gemini-3.1-pro-preview"]

    def set_api_key(self, key: str) -> None:
        self.api_key = key
        try:
            from google import genai

            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            logger.error("API-Key-Setzung fehlgeschlagen: %s", _short(e))

    def get_provider_info(self) -> dict[str, Any]:
        return dict(PROVIDER_INFO["gemini"])


# ─── OPENAI ──────────────────────────────────────────────────


class OpenAIProvider(IAIProvider):
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini"):
        self.api_key = (api_key or "").strip() or None
        self.model = model
        self.client = None
        if self.api_key:
            try:
                from openai import OpenAI

                self.client = OpenAI(api_key=self.api_key, timeout=60.0)
            except ImportError:
                logger.warning("openai nicht installiert")
        else:
            _warn_no_key_once("OpenAI")

    def ask(self, prompt: str, model: str | None = None, timeout: int | None = None) -> str:
        if not self.client:
            raise AIAuthError("Fehler: Kein OpenAI API-Key hinterlegt.")
        model = model or self.model
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                timeout=timeout or 60.0,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            raise AIProviderError(f"Fehler bei OpenAI: {_short(e, self.api_key)}") from e

    def set_model(self, model_name: str) -> None:
        self.model = model_name

    def get_available_models(self) -> list[str]:
        return ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]

    def set_api_key(self, key: str) -> None:
        self.api_key = key
        try:
            from openai import OpenAI

            self.client = OpenAI(api_key=self.api_key, timeout=60.0)
        except Exception as e:
            logger.error("API-Key-Setzung fehlgeschlagen: %s", _short(e))

    def get_provider_info(self) -> dict[str, Any]:
        return dict(PROVIDER_INFO["openai"])


# ─── DEEPSEEK ───────────────────────────────────────────────


class DeepSeekProvider(IAIProvider):
    def __init__(self, api_key: str | None = None, model: str = "deepseek-chat"):
        self.api_key = (api_key or "").strip() or None
        self.model = model
        if not self.api_key:
            _warn_no_key_once("DeepSeek")

    def ask(self, prompt: str, model: str | None = None, timeout: int | None = None) -> str:
        if not self.api_key:
            raise AIAuthError("Fehler: Kein DeepSeek API-Key hinterlegt.")
        model = model or self.model
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        try:
            response = requests.post(
                url, json=payload, headers=headers, timeout=timeout or 60, verify=True
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except (requests.ConnectionError, requests.Timeout) as e:
            raise AIConnectionError(f"DeepSeek nicht erreichbar: {_short(e)}") from e
        except Exception as e:
            raise AIProviderError(f"Fehler bei DeepSeek: {_short(e, self.api_key)}") from e

    def set_model(self, model_name: str) -> None:
        self.model = model_name

    def get_available_models(self) -> list[str]:
        return ["deepseek-chat", "deepseek-coder"]

    def set_api_key(self, key: str) -> None:
        self.api_key = key

    def get_provider_info(self) -> dict[str, Any]:
        return dict(PROVIDER_INFO["deepseek"])


# ─── ANTHROPIC ──────────────────────────────────────────────


class AnthropicProvider(IAIProvider):
    def __init__(self, api_key: str | None = None, model: str = "claude-3-haiku-20240307"):
        self.api_key = (api_key or "").strip() or None
        self.model = model
        if not self.api_key:
            _warn_no_key_once("Anthropic")

    def ask(self, prompt: str, model: str | None = None, timeout: int | None = None) -> str:
        if not self.api_key:
            raise AIAuthError("Fehler: Kein Anthropic API-Key hinterlegt.")
        model = model or self.model
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000,
        }
        try:
            response = requests.post(
                url, json=payload, headers=headers, timeout=timeout or 60, verify=True
            )
            response.raise_for_status()
            return response.json()["content"][0]["text"]
        except (requests.ConnectionError, requests.Timeout) as e:
            raise AIConnectionError(f"Anthropic nicht erreichbar: {_short(e)}") from e
        except Exception as e:
            raise AIProviderError(f"Fehler bei Anthropic: {_short(e, self.api_key)}") from e

    def set_model(self, model_name: str) -> None:
        self.model = model_name

    def get_available_models(self) -> list[str]:
        return ["claude-3-haiku-20240307", "claude-3-5-sonnet-20240620", "claude-3-opus-20240229"]

    def set_api_key(self, key: str) -> None:
        self.api_key = key

    def get_provider_info(self) -> dict[str, Any]:
        return dict(PROVIDER_INFO["anthropic"])


# ─── OLLAMA (LOKAL) ────────────────────────────────────────

# Cache for /api/tags (P2): one HTTP round-trip per base_url per minute,
# not per call.
_TAGS_TTL_SECONDS = 60.0
_tags_cache: dict[str, tuple[float, list[str]]] = {}
_tags_lock = threading.Lock()


class OllamaProvider(IAIProvider):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:7b"):
        self.base_url = base_url
        self.model = model

    def ask(self, prompt: str, model: str | None = None, timeout: int | None = 120) -> str:
        model = model or self.model
        url = f"{self.base_url}/api/generate"
        # think=False: skips extended reasoning-token generation on
        # hybrid-reasoning models (Qwen3, DeepSeek-R1, ...) that default
        # to it. Confirmed via a real timed request (2026-09-15) that
        # this is NOT the dominant cost for a large model on this
        # platform's actual hardware (an integrated GPU with ~2GB VRAM,
        # so an 18GB model like qwen3-coder runs CPU-bound regardless -
        # load_duration and prompt_eval_duration dwarfed eval_duration
        # in that test) - kept anyway since it's free and does help on
        # capable hardware or smaller reasoning models. Ignored by
        # non-reasoning models (Ollama's API tolerates the unknown field).
        # keep_alive: how long Ollama keeps this model loaded after this
        # request (default "1h", see AIConfig.OLLAMA_KEEP_ALIVE's own
        # comment) - without it Ollama's own default (5 min) unloads the
        # model between normal-paced interactive requests, forcing a
        # full reload (the dominant cost for a large local model) on the
        # next one.
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "keep_alive": AIConfig.OLLAMA_KEEP_ALIVE,
        }
        try:
            # allow_redirects=False: base_url is org-controlled input - a
            # cooperating server answering 302 to the metadata endpoint
            # must not turn this call into an SSRF (the validator only
            # sees the initial host, never the redirect target).
            response = requests.post(
                url, json=payload, timeout=timeout or 120, verify=True, allow_redirects=False
            )
            if 300 <= response.status_code < 400:
                # Explicit instead of a downstream JSONDecodeError riddle:
                # with redirects disabled a 3xx is always worth naming.
                raise AIConnectionError(
                    f"Unerwarteter Redirect von Ollama: {response.headers.get('Location', '?')}"
                )
            response.raise_for_status()
            return response.json().get("response", "")
        except (requests.ConnectionError, requests.Timeout) as e:
            # Wrapped like every other provider (AIConnectionError is the
            # documented catch site). The original stays linked as
            # __cause__; callers that must distinguish transport details
            # can still catch requests.* directly - ai_service.py does
            # both for custom-provider compatibility.
            raise AIConnectionError(f"Ollama nicht erreichbar: {_short(e)}") from e
        except AIProviderError:
            # Already classified above (e.g. explicit redirect) - must not
            # be re-wrapped by the generic handler below.
            raise
        except Exception as e:
            raise AIProviderError(f"Fehler bei Ollama: {_short(e)}") from e

    def set_model(self, model_name: str) -> None:
        self.model = model_name

    def get_available_models(self) -> list[str]:
        """Live list from the daemon. Raises (B8) instead of silently
        returning a stale hardcoded list - callers that want a fallback
        must ask for it explicitly (see AIService.get_local_models)."""
        with _tags_lock:
            cached = _tags_cache.get(self.base_url)
            if cached and time.monotonic() - cached[0] < _TAGS_TTL_SECONDS:
                return list(cached[1])
        try:
            # allow_redirects=False, same reasoning as in ask(): the host
            # in base_url is validated, a redirect target is not.
            response = requests.get(
                f"{self.base_url}/api/tags", timeout=10, verify=True, allow_redirects=False
            )
            if 300 <= response.status_code < 400:
                raise AIConnectionError(
                    f"Unerwarteter Redirect von Ollama: {response.headers.get('Location', '?')}"
                )
            response.raise_for_status()
            models = [m["name"] for m in response.json().get("models", [])]
        except (requests.ConnectionError, requests.Timeout) as e:
            raise AIConnectionError(f"Ollama nicht erreichbar: {_short(e)}") from e
        except AIProviderError:
            # Already classified above (explicit redirect) - no re-wrap.
            raise
        except Exception as e:
            raise AIProviderError(f"Ollama-Modellliste fehlgeschlagen: {_short(e)}") from e
        with _tags_lock:
            _tags_cache[self.base_url] = (time.monotonic(), models)
        return models

    def set_api_key(self, key: str) -> None:
        pass

    def get_provider_info(self) -> dict[str, Any]:
        return dict(PROVIDER_INFO["ollama"])

    def download_model(self, model_name: str) -> str:
        """Shells out to `ollama pull` - only meaningful when this backend
        process runs on the same machine as the Ollama instance. True for
        Benito's current local-Postgres/local-dev setup (see
        robe-analytics.md "DB-Hosting-Entscheidung"); revisit once this
        platform is a genuinely separate hosted multi-tenant deployment
        where the server and an org's Ollama instance are different
        machines."""
        name = validate_model_name(model_name)
        try:
            # No shell, fixed argv[0:2]; argv[2] passes validate_model_name
            # (no leading "-", strict charset) - S603/S607 do not apply.
            result = subprocess.run(
                ["ollama", "pull", name],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            return "❌ Ollama ist nicht installiert. Bitte installiere es von https://ollama.com"
        except subprocess.TimeoutExpired as e:
            raise AIUnavailableError(
                f"Modell-Download hat das 10-Minuten-Limit überschritten: {name}"
            ) from e
        if result.returncode == 0:
            return f"✅ Modell {name} erfolgreich heruntergeladen!"
        # Truncated: full pull logs can be megabytes (B18/Q14).
        return f"❌ Fehler beim Download: {(result.stderr or result.stdout or '').strip()[:2000]}"


# ─── factory (B10/A3) ──────────────────────────────────────────────

PROVIDER_CLASSES: dict[str, type] = {
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
    "deepseek": DeepSeekProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
}


def build_provider(
    name: str,
    classes: dict[str, type] | None = None,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> IAIProvider:
    """Single construction point for all providers (B10/A3).

    Constructor contract for custom providers: cloud-style classes take
    (api_key=..., model=...), local-style classes (like Ollama) take
    (base_url=..., model=...). Anything else must be adapted here once,
    not in every caller.
    """
    registry = classes if classes is not None else PROVIDER_CLASSES
    provider_class = registry.get(name)
    if provider_class is None:
        raise ValueError(f"Unbekannter KI-Provider: {name}")
    if name == "ollama":
        kwargs: dict[str, Any] = {"base_url": base_url or "http://localhost:11434"}
    else:
        kwargs = {"api_key": api_key}
    if model is not None:
        kwargs["model"] = model
    return provider_class(**kwargs)
