from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_key(path: str | None) -> bytes | None:
    if not path:
        return None
    key_path = Path(path)
    mode = key_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ValueError("evidence key file permissions must be 0600 or stricter")
    raw = key_path.read_bytes().strip()
    try:
        decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except (ValueError, binascii.Error):
        decoded = b""
    if len(decoded) == 32:
        return decoded
    if len(raw) == 64:
        try:
            decoded = bytes.fromhex(raw.decode("ascii"))
        except ValueError:
            decoded = b""
    if len(decoded) != 32:
        raise ValueError("evidence key file must contain one base64url or hex encoded 32-byte key")
    return decoded


def generate_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
