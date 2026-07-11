"""
pii_crypto — field-level encryption for sensitive customer PII at rest.

Task 3 (PII-at-rest): highly sensitive customer metadata — `customer_name`,
`nationality`, `date_of_birth` (on customer_profiles) and
`counterparty_wallet_address` (on transactions) — must not sit in the SQLite
database file as cleartext. This module wraps `cryptography.fernet` (AES-128-CBC
+ HMAC-SHA256 authenticated encryption; "AES-256-class" symmetric protection)
behind two tiny, side-effect-free helpers:

    encrypt_pii(plaintext) -> ciphertext token   (called on every write path)
    decrypt_pii(token)     -> plaintext           (called only when an
                                                    authorized service reads a
                                                    profile / screens a name)

Design decisions that make retrofitting encryption onto an app full of
hand-written SQL safe and incremental:

1. Sentinel-prefixed tokens (`ENC_PREFIX`). Every ciphertext we emit is
   `"pii:v1:" + <fernet token>`. `decrypt_pii` treats anything WITHOUT that
   prefix as legacy cleartext and returns it untouched. This means:
     • encrypted rows and pre-encryption (legacy) rows coexist in one table;
     • `decrypt_pii` is idempotent and NULL-safe, so it can be layered onto a
       read site without knowing whether that particular row was encrypted;
     • `encrypt_pii` is idempotent — re-encrypting an already-encrypted value
       is a no-op, so an UPSERT that re-reads then re-writes can't double-wrap.

2. A STABLE key, resolved once at import. Field encryption is worthless if the
   key changes between processes: a Gunicorn worker that can't decrypt what a
   sibling worker wrote is a data-loss bug, not a security feature. The key is
   read from `NEXUSBARRIER_PII_KEY` (see `_resolve_keys`); absent that, a
   deterministic development key is derived so a laptop demo keeps working —
   with a loud warning, because that fallback key is NOT secret.

Key rotation: `NEXUSBARRIER_PII_KEY` may hold a comma-separated list. The first
entry encrypts; all entries can decrypt (MultiFernet), so you can introduce a
new primary key and retire an old one without a flag-day re-encryption.
"""

import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

log = logging.getLogger(__name__)

# Marks a value this module produced. Bumped only if the on-disk token format
# itself changes (not on key rotation — that's handled by MultiFernet).
ENC_PREFIX = "pii:v1:"

_ENV_KEY = "NEXUSBARRIER_PII_KEY"

# Deterministic development fallback. Derived, not random, so every process on
# the same machine derives the SAME key and can therefore read each other's
# ciphertext across restarts and Gunicorn workers. This is explicitly NOT a
# secret — it ships in source — which is exactly why production MUST set
# NEXUSBARRIER_PII_KEY. See _resolve_keys.
_DEV_SEED = "nexusbarrier-development-pii-key-do-not-use-in-production"


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
            # A malformed key is a hard configuration error: failing loudly is
            # safer than silently falling back to the public dev key and
            # writing "encrypted" data anyone can read.
            raise RuntimeError(
                f"{_ENV_KEY} is set but is not a valid Fernet key (or "
                f"comma-separated list of them): {exc}"
            ) from exc

    log.warning(
        "%s is not set — falling back to a DETERMINISTIC development PII key. "
        "This key is derived from a public seed in source and provides NO real "
        "protection. Set %s to a Fernet key (Fernet.generate_key()) in any "
        "non-development environment.",
        _ENV_KEY, _ENV_KEY,
    )
    return MultiFernet([Fernet(_derive_fernet_key(_DEV_SEED))])


# Resolved LAZILY on first use, then cached for the life of the process — one
# stable key set shared by every worker. Lazy (not at import) so a `.env`
# loaded via python-dotenv in an entry point's __main__ is honoured even though
# this module is imported at the top of that file, before load_dotenv() runs.
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
        # Wrong key (e.g. a rotated-out key with no overlap) or corrupted
        # token. Fail safe for a read path: log and surface a redaction marker
        # rather than crashing the whole page render on one bad row.
        log.error("Failed to decrypt a PII field (InvalidToken) — key mismatch or corruption.")
        return "[ENCRYPTED]"


# Fields we encrypt on customer_profiles. Centralised so write and read sites
# stay in lock-step — add a column here and both sides pick it up.
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
