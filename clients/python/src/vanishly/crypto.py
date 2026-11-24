"""Crypto format v1 of Vanishly, the same as public/js/vanishly-crypto.js.

  key        32 random bytes, only ever in the URL fragment (#...).
  pk         without passphrase: empty; with one PBKDF2-SHA256(passphrase, salt, iterations, 32).
  encKey     HKDF-SHA256(ikm = key || pk, salt, info "vanishly v1 enc"), AES-256.
  verifier   HKDF-SHA256(ikm = pk, salt, info "vanishly v1 auth", 32); the server
             stores only SHA-256(verifier).
  ciphertext AES-256-GCM(encKey, iv 12 bytes, aad "vanishly v1") with the 16-byte tag.

All binary values are base64url without padding.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
PBKDF2_ITERATIONS = 600000
AAD = b"vanishly v1"
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class DecryptError(Exception):
    """The key, the passphrase or the ciphertext is wrong."""


def to_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(text: str) -> bytes:
    if not isinstance(text, str) or not _B64URL.match(text) or len(text) % 4 == 1:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def unlock_key(passphrase: str, salt: str, iterations: int) -> bytes:
    """Stretches a passphrase once (pk); salt is the base64url value of the secret."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), from_b64url(salt), iterations, 32)


def verifier_for(pk: bytes, salt: str) -> str:
    """The verifier the reveal API checks for a passphrase-protected secret."""
    return to_b64url(_hkdf(pk, from_b64url(salt), b"vanishly v1 auth"))


def encrypt_secret(plaintext: str, passphrase: str = "", *, iterations: int = PBKDF2_ITERATIONS,
                   _key: bytes | None = None, _salt: bytes | None = None, _iv: bytes | None = None):
    """Encrypts a secret. Returns (key, payload): the key goes into the URL
    fragment, the payload to POST /api/v1/secrets. The _key/_salt/_iv
    arguments are only for test vectors."""
    key = _key or os.urandom(32)
    salt = _salt or os.urandom(16)
    iv = _iv or os.urandom(12)
    if len(key) != 32 or len(salt) != 16 or len(iv) != 12:
        raise ValueError("key, salt or iv has the wrong length")
    pk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, 32) if passphrase else b""
    enc_key = _hkdf(key + pk, salt, b"vanishly v1 enc")
    ct = AESGCM(enc_key).encrypt(iv, plaintext.encode("utf-8"), AAD)
    payload = {
        "v": VERSION,
        "ciphertext": to_b64url(ct),
        "iv": to_b64url(iv),
        "salt": to_b64url(salt),
        "iterations": iterations,
    }
    if pk:
        payload["verifier"] = to_b64url(_hkdf(pk, salt, b"vanishly v1 auth"))
    return to_b64url(key), payload


def decrypt_secret(payload: dict, key: str, pk: bytes = b"") -> str:
    """Decrypts what the reveal API returned; pk from unlock_key for a passphrase."""
    try:
        raw_key = from_b64url(key)
        if len(raw_key) != 32:
            raise ValueError("the key must be 32 bytes")
        salt = from_b64url(payload["salt"])
        enc_key = _hkdf(raw_key + pk, salt, b"vanishly v1 enc")
        pt = AESGCM(enc_key).decrypt(from_b64url(payload["iv"]), from_b64url(payload["ciphertext"]), AAD)
        return pt.decode("utf-8")
    except Exception as exc:  # InvalidTag, bad base64, bad UTF-8
        raise DecryptError("cannot decrypt: wrong key or passphrase, or damaged data") from exc
