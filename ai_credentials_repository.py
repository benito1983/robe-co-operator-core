# backend/ai/ai_credentials_repository.py
#
# Org-scoped storage for RoBe AI Runtime settings: which provider/model an
# org has selected, its fallback provider, and each paid provider's API
# key - one Fernet-encrypted blob per org (see backend/core/crypto.py),
# same pattern as Baustein 5's ApiCredentialsRepository
# (backend/affiliate/api_credentials_repository.py), reused deliberately -
# NOT the same table. See migration 011 for why AI Runtime gets its own
# table instead of adding fields onto api_credentials.
#
# Non-secret selection state (active_provider/active_model/
# fallback_provider) lives in the same blob as the actual API keys, not a
# separate table - same "always read/written together, no query ever
# filters by one field" reasoning migration 007 already used for
# Affiliate's credentials.
from __future__ import annotations

from typing import Any
from uuid import UUID

from backend.core.crypto import decrypt_json_strict, encrypt_json
from backend.core.repository import OrgScopedRepository, connection

AI_SETTINGS_FIELDS = (
    "active_provider",
    "active_model",
    "fallback_provider",
    "allow_cloud_fallback",
    "openai_api_key",
    "anthropic_api_key",
    "gemini_api_key",
    "deepseek_api_key",
    "ollama_base_url",
)


class AICredentialDecryptionError(Exception):
    """Stored blob exists but cannot be decrypted (e.g. key rotation
    without re-encryption, corrupt row).

    Deliberately NOT swallowed to {} (unlike an earlier revision of this
    method): fail-closed like Affiliate's CredentialDecryptionError. A
    silent {} would show "configure your key" while a blob exists, and
    the next update_fields would overwrite - and destroy - the old keys
    without anyone noticing. The only fault-tolerant case is "no row".
    """

    pass


class AICredentialsRepository(OrgScopedRepository):
    table = "ai_provider_credentials"

    def get(self, org_id: UUID) -> dict[str, Any]:
        """Decrypted settings, or {} if no row exists.

        Raises AICredentialDecryptionError if a row exists but fails to
        decrypt - distinct from "never configured". Callers (AIService)
        let this propagate: every AI route fails loudly (500 + alarm)
        instead of silently running on defaults.
        """
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT encrypted_data FROM ai_provider_credentials WHERE org_id = %s",
                (str(org_id),),
            )
            row = cur.fetchone()
            if row is None:
                return {}
            try:
                return decrypt_json_strict(row[0])
            except Exception as exc:
                raise AICredentialDecryptionError(
                    "AI-Einstellungen vorhanden, aber nicht entschlüsselbar "
                    "(Key-Rotation ohne Re-Verschlüsselung oder korrupte Zeile?)"
                ) from exc

    def set_all(self, org_id: UUID, settings: dict[str, Any]) -> None:
        """Replaces the org's ENTIRE settings blob - see update_fields()
        for the safer merge-based alternative."""
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO ai_provider_credentials (org_id, encrypted_data, updated_at)
                    VALUES (%s, %s, now())
                    ON CONFLICT (org_id) DO UPDATE SET
                        encrypted_data = EXCLUDED.encrypted_data,
                        updated_at = now()
                    """,
                (str(org_id), encrypt_json(settings)),
            )

    def update_fields(self, org_id: UUID, **fields: Any) -> dict[str, Any]:
        """Decrypt-merge-encrypt convenience, same shape as
        ApiCredentialsRepository.update_fields(). Rejects unknown fields.
        Returns the resulting full settings dict.

        B14: row-level lock + pre-insert so parallel first-writers cannot
        lose each other's merge (same TOCTOU the affiliate module fixed).
        """
        unknown = set(fields) - set(AI_SETTINGS_FIELDS)
        if unknown:
            raise ValueError(f"Unknown AI setting field(s): {sorted(unknown)}")

        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ai_provider_credentials (org_id, encrypted_data, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (org_id) DO NOTHING
                """,
                (str(org_id), encrypt_json({})),
            )
            cur.execute(
                "SELECT encrypted_data FROM ai_provider_credentials WHERE org_id = %s FOR UPDATE",
                (str(org_id),),
            )
            row = cur.fetchone()
            # A corrupt blob raises here - BEFORE the merge - so a broken
            # row can never be silently overwritten with a partial update.
            try:
                current = decrypt_json_strict(row[0]) if row is not None else {}
            except Exception as exc:
                raise AICredentialDecryptionError(
                    "AI-Einstellungen vorhanden, aber nicht entschlüsselbar - "
                    "Update verweigert, um keine Keys zu verlieren"
                ) from exc
            current.update(fields)
            encrypted = encrypt_json(current)
            cur.execute(
                """
                INSERT INTO ai_provider_credentials (org_id, encrypted_data, updated_at)
                VALUES (%s, %s, now())
                ON CONFLICT (org_id) DO UPDATE SET
                    encrypted_data = EXCLUDED.encrypted_data,
                    updated_at = now()
                """,
                (str(org_id), encrypted),
            )
        return current

    def delete(self, org_id: UUID) -> bool:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM ai_provider_credentials WHERE org_id = %s",
                (str(org_id),),
            )
            return cur.rowcount > 0
