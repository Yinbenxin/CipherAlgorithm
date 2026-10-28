"""AES in GCM / CBC / CTR modes.

The key length selects the variant: 16 bytes for AES-128, 24 for AES-192,
32 for AES-256. Never reuse a GCM nonce or CTR counter block with the same key.
CBC and CTR are not authenticated; prefer GCM unless you need interoperability.
"""

from . import _native
from ._util import BytesLike, as_bytes

__all__ = [
    "GCM_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "IV_SIZE",
    "gcm_encrypt",
    "gcm_decrypt",
    "cbc_encrypt",
    "cbc_decrypt",
    "ctr_encrypt",
    "ctr_decrypt",
]

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
IV_SIZE = 16


def gcm_encrypt(key: BytesLike, nonce: BytesLike, plaintext: BytesLike, aad: BytesLike = b"") -> bytes:
    """Encrypt with AES-GCM. Returns ``ciphertext || 16-byte tag``.

    ``nonce`` must be 12 bytes and unique per message for a given key.
    """
    return _native.aes_gcm_encrypt(
        as_bytes(key, "key"), as_bytes(nonce, "nonce"), as_bytes(plaintext, "plaintext"), as_bytes(aad, "aad")
    )


def gcm_decrypt(key: BytesLike, nonce: BytesLike, ciphertext: BytesLike, aad: BytesLike = b"") -> bytes:
    """Decrypt and verify ``ciphertext || tag``. Raises ``CipherError`` if verification fails."""
    return _native.aes_gcm_decrypt(
        as_bytes(key, "key"), as_bytes(nonce, "nonce"), as_bytes(ciphertext, "ciphertext"), as_bytes(aad, "aad")
    )


def cbc_encrypt(key: BytesLike, iv: BytesLike, plaintext: BytesLike) -> bytes:
    """Encrypt with AES-CBC and PKCS#7 padding. ``iv`` must be 16 unpredictable bytes."""
    return _native.aes_cbc_encrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(plaintext, "plaintext"))


def cbc_decrypt(key: BytesLike, iv: BytesLike, ciphertext: BytesLike) -> bytes:
    """Decrypt AES-CBC and strip PKCS#7 padding. Raises ``CipherError`` on bad length or padding."""
    return _native.aes_cbc_decrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(ciphertext, "ciphertext"))


def ctr_encrypt(key: BytesLike, iv: BytesLike, plaintext: BytesLike) -> bytes:
    """Encrypt with AES-CTR. ``iv`` is the 16-byte initial counter block (128-bit big-endian counter)."""
    return _native.aes_ctr_encrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(plaintext, "plaintext"))


def ctr_decrypt(key: BytesLike, iv: BytesLike, ciphertext: BytesLike) -> bytes:
    """Decrypt AES-CTR. Identical to :func:`ctr_encrypt`."""
    return _native.aes_ctr_decrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(ciphertext, "ciphertext"))
