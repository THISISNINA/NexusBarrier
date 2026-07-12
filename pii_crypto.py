"""pii_crypto — field-level Fernet encryption for PII at rest; sentinel-prefixed ("pii:v1:"), NULL-safe, idempotent tokens that coexist with legacy cleartext, using an import-stable key from NEXUSBARRIER_PII_KEY (comma-separated list enables MultiFernet rotation; deterministic dev fallback when unset)."""

import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

log = logging.getLogger(__name__)

# Marks a value this module produced; bumped only if the on-disk token format changes (not on rotation).
ENC_PREFIX = "pii:v1:"

_ENV_KEY = "NEXUSBARRIER_PII_KEY"

# Deterministic (not random) dev fallback so every process derives the same readable key; NOT secret, so production MUST set NEXUSBARRIER_PII_KEY.
_DEV_SEED = "nexusbarrier-development-pii-key-do-not-use-in-production"


def _is_production() -> bool:
    """See app._is_production — duplicated per this codebase's no-cross-module-
    coupling convention (same rationale as _add_column_if_missing)."""
    return (
        os.environ.get("NEXUSBARRIER_ENV", "development").strip().lower() == "production"
        or bool(os.environ.get("RENDER"))
    )


def _derive_fernet_key(material: str) -> bytes:
    """Turn arbitrary text into a valid 32-byte urlsafe-base64 Fernet key.
    Used only for the development fallback; production keys are supplied
    pre-formatted via the environment."""
    digest = hashlib.sha256(material.encode("utf-8")).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)


def _resolve_keys() -> MultiFernet:
    """Build the MultiFernet used for all encrypt/decrypt calls.

    Production: NEXUSBARRIER_PII_KEY = one Fernet key, or several
    comma-separated (first encrypts, all decrypt — enables rotation).

    Development: no env var → a deterministic key derived from _DEV_SEED, with
    a warning. Stable across processes so the demo's data stays readable; not
    secret, so it must never guard real customer data."""
    raw = os.environ.get(_ENV_KEY, "").strip()
    if raw:
        keys = [k.strip() for k in raw.split(",") if k.strip()]
        try:
            return MultiFernet([Fernet(k.encode("utf-8")) for k in keys])
        except (ValueError, TypeError) as exc:
            # A malformed key is a hard config error: fail loudly rather than silently use the public dev key.
            raise RuntimeError(
                f"{_ENV_KEY} is set but is not a valid Fernet key (or "
                f"comma-separated list of them): {exc}"
            ) from exc

    if _is_production():
        # The dev key is derived from a public seed in source — using it in
        # production would mean customer PII is "encrypted" with a key anyone
        # can reconstruct. Refuse rather than provide false protection.
        raise RuntimeError(
            f"{_ENV_KEY} must be set in production. Refusing to fall back to the "
            "public development PII key (it provides no real protection for PII at rest)."
        )
    log.warning(
        "%s is not set — falling back to a DETERMINISTIC development PII key. "
        "This key is derived from a public seed in source and provides NO real "
        "protection. Set %s to a Fernet key (Fernet.generate_key()) in any "
        "non-development environment.",
        _ENV_KEY, _ENV_KEY,
    )
    return MultiFernet([Fernet(_derive_fernet_key(_DEV_SEED))])


# Resolved lazily on first use (not at import, so a dotenv-loaded .env is honoured) then cached process-wide.
_FERNET: Optional[MultiFernet] = None


def _get_fernet() -> MultiFernet:
    global _FERNET
    if _FERNET is None:
        _FERNET = _resolve_keys()
    return _FERNET


def is_encrypted(value: object) -> bool:
    """True if `value` is one of our ciphertext tokens (carries ENC_PREFIX)."""
    return isinstance(value, str) and value.startswith(ENC_PREFIX)


def encrypt_pii(plaintext: Optional[str]) -> Optional[str]:
    """Encrypt a single PII field for storage.

    NULL-safe and idempotent: None/empty pass through unchanged (so a NULL
    column stays NULL and the '—' template fallbacks keep working), and an
    already-encrypted value is returned as-is rather than double-wrapped."""
    if plaintext is None or plaintext == "":
        return plaintext
    if is_encrypted(plaintext):
        return plaintext  # idempotent — never wrap twice (UPSERT re-read safety)
    token = _get_fernet().encrypt(str(plaintext).encode("utf-8")).decode("ascii")
    return ENC_PREFIX + token


def decrypt_pii(value: Optional[str]) -> Optional[str]:
    """Decrypt a stored PII field for an authorized read.

    Transparent to legacy data: a value WITHOUT ENC_PREFIX is assumed to be
    pre-encryption cleartext (or already-decrypted) and returned unchanged, so
    this can be dropped onto any read site regardless of whether that row was
    written before or after encryption was enabled. NULL-safe."""
    if not is_encrypted(value):
        return value  # None, or legacy/plaintext — nothing to do
    try:
        return _get_fernet().decrypt(value[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken:
        # Wrong key or corrupted token: fail safe on a read path — log and surface a marker, don't crash the render.
        log.error("Failed to decrypt a PII field (InvalidToken) — key mismatch or corruption.")
        return "[ENCRYPTED]"


# Fields encrypted on customer_profiles; centralised so write and read sites stay in lock-step.
PROFILE_PII_FIELDS = ("customer_name", "nationality", "date_of_birth")


def decrypt_profile_fields(profile: Optional[dict]) -> Optional[dict]:
    """Decrypt every encrypted PII column on a customer_profiles row dict
    in place, then return it. The single call every service method that
    surfaces a profile to a logged-in user routes through, so decryption
    lives in one place instead of being re-typed per column per method."""
    if not profile:
        return profile
    for field in PROFILE_PII_FIELDS:
        if field in profile:
            profile[field] = decrypt_pii(profile[field])
    return profile
