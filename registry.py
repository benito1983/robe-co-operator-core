# backend/skillforge/registry.py
#
# Skill Forge: makes the platform's existing capability system (module
# registry + permissions, backend/core/registry.py & capabilities.py &
# permissions.py) usable BY an AI/agent, not just by a human clicking
# through the app. A "skill" wraps one existing action (a repository
# method, an orchestrator call) behind a name, a description, and a
# JSON-Schema parameter spec an AI can read to decide when and how to
# call it (OpenAI function-calling-compatible shape) - the same
# module_key/permission_key gate backend/core/api_deps.py's
# require_module_and_permission() already enforces for the HTTP route
# is reused here (see routes.py), not a parallel, weaker check.
#
# Same self-registration pattern as backend/core/registry.py's
# ModuleRegistry: each backend/<domain>/skills.py exposes a
# register_skills(registry) function, discover_and_register_skills()
# finds and calls all of them. A module that has no skills to offer
# simply omits skills.py - no error, same as omitting register().
from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class SkillDefinition:
    key: str  # stable id, e.g. "wissenszweig.search"
    name: str  # display name for a UI/agent listing
    description: str  # what it does - this is what an AI reads to decide WHEN to use it
    module_key: str  # which backend/<module> gates this (capability check)
    permission_key: str  # which permission gates this
    parameters_schema: dict  # JSON Schema for the handler's kwargs
    # handler(org_id, user_id, **kwargs) -> JSON-serializable result.
    # Never called directly by routes.py without the module+permission
    # gate having already passed - see invoke_skill()'s docstring.
    handler: Callable[..., Any]


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: dict[str, SkillDefinition] = {}

    def register(self, skill: SkillDefinition) -> None:
        if skill.key in self._skills:
            raise ValueError(f"Skill '{skill.key}' is already registered")
        self._skills[skill.key] = skill

    def get(self, key: str) -> SkillDefinition | None:
        return self._skills.get(key)

    def all(self) -> Iterator[SkillDefinition]:
        return iter(self._skills.values())

    def __len__(self) -> int:
        return len(self._skills)


def discover_and_register_skills(registry: SkillRegistry, package_name: str = "backend") -> None:
    """Scans `package_name` for direct subpackages and calls their
    skills.py's register_skills(registry), if present - mirrors
    backend/core/registry.py's discover_and_register() exactly, one
    level deeper (module -> module.skills)."""
    package = importlib.import_module(package_name)
    for module_info in pkgutil.iter_modules(package.__path__, prefix=f"{package_name}."):
        if not module_info.ispkg:
            continue
        try:
            skills_module = importlib.import_module(f"{module_info.name}.skills")
        except ModuleNotFoundError:
            continue
        register_fn = getattr(skills_module, "register_skills", None)
        if register_fn is not None:
            register_fn(registry)


def invoke_skill(
    skill: SkillDefinition,
    org_id: UUID,
    user_id: UUID,
    arguments: dict[str, Any],
) -> Any:
    """Thin, deliberate indirection (not just `skill.handler(...)`
    inline in routes.py) so every call path into a skill handler is
    forced through one place - if a future audit/rate-limit/event hook
    is needed for skill invocations, it goes here once, not into every
    module's skills.py."""
    return skill.handler(org_id, user_id, **arguments)
