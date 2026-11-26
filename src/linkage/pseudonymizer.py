"""HMAC-based, domain-separated deterministic patient pseudonyms."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json


class Pseudonymizer:
    DOMAIN = b"secret-wards/patient-pseudonym/v1\0"

    def __init__(self, secret: str, minimum_bytes: int = 16) -> None:
        if not isinstance(secret, str):
            raise ValueError("RAKSHA_SECRET is invalid")
        key = secret.encode("utf-8")
        if len(key) < minimum_bytes or not secret.strip():
            raise ValueError("RAKSHA_SECRET is invalid")
        self._key = key

    def pseudonym(self, stable_cluster_anchor: tuple[str, ...]) -> str:
        if not stable_cluster_anchor or any(not item for item in stable_cluster_anchor):
            raise ValueError("patient_identity_unresolved")
        payload = self.DOMAIN + json.dumps(
            stable_cluster_anchor, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        digest = hmac.new(self._key, payload, hashlib.sha256).digest()
        token = base64.b32encode(digest[:16]).decode("ascii").rstrip("=")
        return "PSN-" + token
