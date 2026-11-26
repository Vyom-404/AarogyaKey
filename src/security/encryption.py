"""Versioned AES-GCM envelope for any sensitive intermediate persistence."""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.security.secret_manager import derive_key

_MAGIC = b"RAKSHA\x01"
_NONCE_SIZE = 12
_TAG_SIZE = 16


def encrypt(plaintext: bytes, secret: str, associated_data: bytes = b"") -> bytes:
    """Encrypt bytes with AES-256-GCM and a fresh nonce."""
    if not isinstance(plaintext, bytes) or not isinstance(associated_data, bytes):
        raise ValueError("encryption_input_invalid") from None
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ciphertext = AESGCM(derive_key(secret, "intermediate-aead/v1")).encrypt(
        nonce, plaintext, associated_data
    )
    return _MAGIC + nonce + ciphertext


def decrypt(envelope: bytes, secret: str, associated_data: bytes = b"") -> bytes:
    """Authenticate and decrypt an envelope; never expose provider errors."""
    if not isinstance(envelope, bytes) or not isinstance(associated_data, bytes):
        raise ValueError("encrypted_data_invalid") from None
    if len(envelope) < len(_MAGIC) + _NONCE_SIZE + _TAG_SIZE or not envelope.startswith(_MAGIC):
        raise ValueError("encrypted_data_invalid") from None
    nonce_start = len(_MAGIC)
    nonce = envelope[nonce_start:nonce_start + _NONCE_SIZE]
    ciphertext = envelope[nonce_start + _NONCE_SIZE:]
    try:
        return AESGCM(derive_key(secret, "intermediate-aead/v1")).decrypt(
            nonce, ciphertext, associated_data
        )
    except (InvalidTag, ValueError):
        raise ValueError("encrypted_data_invalid") from None
