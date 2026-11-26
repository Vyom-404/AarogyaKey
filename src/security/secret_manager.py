"""Validated, purpose-separated keys derived from the runtime secret."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SALT = b"secret-wards/hkdf-salt/v1"
_ROOT_INFO = b"secret-wards/root-key/v1"
_PURPOSES = frozenset({"patient-pseudonym/v2", "date-shift/v2", "intermediate-aead/v1"})


def validate_secret(secret: str, minimum_bytes: int = 16) -> bytes:
    """Return secret bytes after enforcing the established minimum length."""
    if not isinstance(secret, str):
        raise ValueError("RAKSHA_SECRET is invalid") from None
    try:
        encoded = secret.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("RAKSHA_SECRET is invalid") from None
    if not secret.strip() or len(encoded) < minimum_bytes:
        raise ValueError("RAKSHA_SECRET is invalid") from None
    return encoded


class SecretManager:
    """Keep the root key in memory and derive separate keys by purpose."""

    __slots__ = ("__root",)

    def __init__(self, secret: str) -> None:
        material = validate_secret(secret)
        self.__root = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=_SALT, info=_ROOT_INFO
        ).derive(material)

    def key_for(self, purpose: str) -> bytes:
        if purpose not in _PURPOSES:
            raise ValueError("key_purpose_invalid")
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=_SALT,
            info=b"secret-wards/purpose/" + purpose.encode("ascii"),
        ).derive(self.__root)

    def __repr__(self) -> str:
        return "SecretManager(<redacted>)"


def derive_key(secret: str, purpose: str) -> bytes:
    """Derive one purpose-specific key without exposing the root key."""
    return SecretManager(secret).key_for(purpose)
