# backend/skillforge/routes.py
#
# Two generic endpoints instead of one per skill: /skills lists what an
# org/user is actually allowed to call right now (filtered the same way
# require_module_and_permission() would gate each one individually -
# see _has_capability()), /invoke dispatches to whichever skill's key is
# given. This is the point of Skill Forge - an AI/agent (or a future
# chat UI) discovers capabilities at runtime instead of every new skill
# needing its own hardcoded route.
from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field

from backend.core import audit
from backend.core.api_deps import get_registry, require_module_and_permission
from backend.core.capabilities import active_modules_for_org
from backend.core.permissions import has_permission
from backend.core.schemas import BaseRequestModel
from backend.skillforge.registry import SkillRegistry, invoke_skill

router = APIRouter(prefix="/api/skillforge", tags=["skillforge"])

_gate = require_module_and_permission("skillforge", "can_use_skillforge")

# Set once at app startup (main.py lifespan), same singleton pattern as
# backend/knowledge/routes.py's _service.
_skill_registry: SkillRegistry | None = None


def init(skill_registry: SkillRegistry) -> None:
    global _skill_registry
    _skill_registry = skill_registry


def _skills() -> SkillRegistry:
    if _skill_registry is None:
        raise HTTPException(503, "Skill Forge nicht initialisiert")
    return _skill_registry


def _org_id(claims: dict) -> UUID:
    return UUID(claims["org_id"])


def _actor(claims: dict) -> UUID:
    return UUID(claims["user_id"])


def _has_capability(org_id: UUID, user_id: UUID, module_key: str, permission_key: str) -> bool:
    """The exact same two-gate check require_module_and_permission()
    does for a fixed route (module active for org AND user has the
    permission), reused here because a skill's own module_key/
    permission_key is only known at runtime (it's data, not a route
    decorator argument)."""
    active_keys = {m.key for m in active_modules_for_org(get_registry(), org_id)}
    return module_key in active_keys and has_permission(user_id, permission_key)


class InvokeRequest(BaseRequestModel):
    skill_key: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


@router.get("/skills")
def list_skills(claims=Depends(_gate)):
    org_id, user_id = _org_id(claims), _actor(claims)
    return {
        "skills": [
            {
                "key": s.key,
                "name": s.name,
                "description": s.description,
                "parameters": s.parameters_schema,
            }
            for s in _skills().all()
            if _has_capability(org_id, user_id, s.module_key, s.permission_key)
        ]
    }


@router.post("/invoke")
def invoke(req: InvokeRequest, claims=Depends(_gate)):
    org_id, user_id = _org_id(claims), _actor(claims)
    skill = _skills().get(req.skill_key)
    if skill is None:
        raise HTTPException(404, f"Skill nicht gefunden: {req.skill_key!r}")
    if not _has_capability(org_id, user_id, skill.module_key, skill.permission_key):
        raise HTTPException(
            403,
            f"Fehlende Berechtigung fuer Skill '{req.skill_key}' "
            f"(Modul '{skill.module_key}', Berechtigung '{skill.permission_key}')",
        )
    try:
        result = invoke_skill(skill, org_id, user_id, req.arguments)
    except TypeError as e:
        raise HTTPException(422, f"Ungueltige Argumente fuer Skill '{req.skill_key}': {e}") from e
    except ValueError as e:
        raise HTTPException(422, str(e)) from e

    # Audit-log the skill invocation (best-effort, don't fail the invoke)
    try:
        from backend.core.repository import connection

        with connection() as conn, conn.cursor() as cur:
            audit.log_action(
                cur,
                org_id,
                user_id,
                "skillforge",
                "skill_invocation",
                user_id,
                "invoked",
                {"skill_key": req.skill_key, "arguments": list(req.arguments.keys())},
            )
            conn.commit()
    except Exception:
        pass  # Audit failure must not break skill invocation

    return {"result": result}
