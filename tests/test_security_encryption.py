from __future__ import annotations

import unittest

from src.security.encryption import decrypt, encrypt

SECRET = "unit test security secret 2026"


class AuthenticatedEncryptionTests(unittest.TestCase):
    def test_aes_gcm_round_trip_and_associated_data(self) -> None:
        raw = b"synthetic intermediate mapping"
        envelope = encrypt(raw, SECRET, b"dataset-v1")
        self.assertTrue(envelope.startswith(b"RAKSHA\x01"))
        self.assertNotIn(raw, envelope)
        self.assertEqual(decrypt(envelope, SECRET, b"dataset-v1"), raw)
        with self.assertRaisesRegex(ValueError, "encrypted_data_invalid"):
            decrypt(envelope, SECRET, b"other-context")

    def test_tampered_ciphertext_and_wrong_secret_fail_authentication(self) -> None:
        envelope = bytearray(encrypt(b"synthetic PII", SECRET))
        envelope[-1] ^= 1
        for candidate, secret in ((bytes(envelope), SECRET), (encrypt(b"x", SECRET), "different secret value 2026")):
            with self.subTest(candidate_size=len(candidate)):
                with self.assertRaisesRegex(ValueError, "encrypted_data_invalid"):
                    decrypt(candidate, secret)

    def test_malformed_envelope_has_fixed_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "encrypted_data_invalid"):
            decrypt(b"not-an-envelope", SECRET)
