"""SM4 (GB/T 32907-2016) in GCM / CBC / CTR modes.

Keys are 16 bytes. Never reuse a GCM nonce or CTR counter block with the same key.
CBC and CTR are not authenticated; prefer GCM unless you need interoperability.
SM4-GCM follows RFC 8998.
"""

from . import _native
from ._util import BytesLike, as_bytes

__all__ = [
    "KEY_SIZE",
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

KEY_SIZE = 16
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
IV_SIZE = 16


def gcm_encrypt(key: BytesLike, nonce: BytesLike, plaintext: BytesLike, aad: BytesLike = b"") -> bytes:
    """Encrypt with SM4-GCM. Returns ``ciphertext || 16-byte tag``.

    ``nonce`` must be 12 bytes and unique per message for a given key.
    """
    return _native.sm4_gcm_encrypt(
        as_bytes(key, "key"), as_bytes(nonce, "nonce"), as_bytes(plaintext, "plaintext"), as_bytes(aad, "aad")
    )


def gcm_decrypt(key: BytesLike, nonce: BytesLike, ciphertext: BytesLike, aad: BytesLike = b"") -> bytes:
    """Decrypt and verify ``ciphertext || tag``. Raises ``CipherError`` if verification fails."""
    return _native.sm4_gcm_decrypt(
        as_bytes(key, "key"), as_bytes(nonce, "nonce"), as_bytes(ciphertext, "ciphertext"), as_bytes(aad, "aad")
    )


def cbc_encrypt(key: BytesLike, iv: BytesLike, plaintext: BytesLike) -> bytes:
    """Encrypt with SM4-CBC and PKCS#7 padding. ``iv`` must be 16 unpredictable bytes."""
    return _native.sm4_cbc_encrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(plaintext, "plaintext"))


def cbc_decrypt(key: BytesLike, iv: BytesLike, ciphertext: BytesLike) -> bytes:
    """Decrypt SM4-CBC and strip PKCS#7 padding. Raises ``CipherError`` on bad length or padding."""
    return _native.sm4_cbc_decrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(ciphertext, "ciphertext"))


def ctr_encrypt(key: BytesLike, iv: BytesLike, plaintext: BytesLike) -> bytes:
    """Encrypt with SM4-CTR. ``iv`` is the 16-byte initial counter block (128-bit big-endian counter)."""
    return _native.sm4_ctr_encrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(plaintext, "plaintext"))


def ctr_decrypt(key: BytesLike, iv: BytesLike, ciphertext: BytesLike) -> bytes:
    """Decrypt SM4-CTR. Identical to :func:`ctr_encrypt`."""
    return _native.sm4_ctr_decrypt(as_bytes(key, "key"), as_bytes(iv, "iv"), as_bytes(ciphertext, "ciphertext"))
