"""Vanishly client: end-to-end encrypted one-time secrets (crypto format v1)
and the whole Vanishly API (/api/v1)."""

__version__ = "4.0.0"

from .client import ApiError, Client, parse_link  # noqa: E402
from .crypto import DecryptError, decrypt_secret, encrypt_secret, unlock_key, verifier_for  # noqa: E402

__all__ = [
    "ApiError", "Client", "DecryptError", "parse_link",
    "decrypt_secret", "encrypt_secret", "unlock_key", "verifier_for",
]
