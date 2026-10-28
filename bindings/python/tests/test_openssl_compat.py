"""Cross-check against OpenSSL via the `cryptography` package."""

import os

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import UnsupportedAlgorithm  # noqa: E402
from cryptography.hazmat.primitives import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from cipher_algorithm import aes, sm4  # noqa: E402

CIPHERS = [
    pytest.param(aes, 16, id="aes128"),
    pytest.param(aes, 24, id="aes192"),
    pytest.param(aes, 32, id="aes256"),
    pytest.param(sm4, 16, id="sm4"),
]


def _ref_encrypt(algo, mode, data):
    enc = Cipher(algo, mode).encryptor()
    return enc.update(data) + enc.finalize()


@pytest.mark.parametrize("mod,key_len", CIPHERS)
@pytest.mark.parametrize("size", [0, 5, 16, 33, 4096])
def test_matches_openssl(mod, key_len, size):
    key, pt = os.urandom(key_len), os.urandom(size)
    nonce, iv, aad = os.urandom(12), os.urandom(16), os.urandom(7)
    algo = algorithms.AES(key) if mod is aes else algorithms.SM4(key)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(pt) + padder.finalize()
    assert mod.cbc_encrypt(key, iv, pt) == _ref_encrypt(algo, modes.CBC(iv), padded)
    assert mod.ctr_encrypt(key, iv, pt) == _ref_encrypt(algo, modes.CTR(iv), pt)

    try:
        enc = Cipher(algo, modes.GCM(nonce)).encryptor()
    except UnsupportedAlgorithm:
        pytest.skip("OpenSSL build lacks this GCM variant")
    enc.authenticate_additional_data(aad)
    ref = enc.update(pt) + enc.finalize() + enc.tag
    assert mod.gcm_encrypt(key, nonce, pt, aad) == ref
