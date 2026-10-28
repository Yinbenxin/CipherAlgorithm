import os

import pytest

from cipher_algorithm import CipherError, aes, sm4

# --- Known-answer tests -----------------------------------------------------


def test_aes_gcm_vector():
    # McGrew & Viega, GCM test case 4.
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    pt = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    ct = bytes.fromhex(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        "5bc94fbc3221a5db94fae95ae7121a47"
    )
    assert aes.gcm_encrypt(key, nonce, pt, aad) == ct
    assert aes.gcm_decrypt(key, nonce, ct, aad) == pt


def test_aes_ctr_vector():
    # NIST SP 800-38A F.5.1, first block.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert aes.ctr_encrypt(key, iv, pt).hex() == "874d6191b620e3261bef6864990db6ce"


def test_sm4_gcm_vector():
    # RFC 8998 Appendix A.1.
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    nonce = bytes.fromhex("00001234567800000000abcd")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    pt = bytes.fromhex(
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"
        "eeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
    )
    ct = bytes.fromhex(
        "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735"
        "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d"
        "83de3541e4c2b58177e065a9bf7b62ec"
    )
    assert sm4.gcm_encrypt(key, nonce, pt, aad) == ct
    assert sm4.gcm_decrypt(key, nonce, ct, aad) == pt


def test_sm4_block_vector():
    # GB/T 32907-2016 Appendix A.1; CBC with a zero IV exposes the raw block output.
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    assert sm4.cbc_encrypt(key, bytes(16), key)[:16].hex() == "681edf34d206965e86b3e94f536e4246"


# --- Round trips and error handling ------------------------------------------

CIPHERS = [
    pytest.param(aes, 16, id="aes128"),
    pytest.param(aes, 24, id="aes192"),
    pytest.param(aes, 32, id="aes256"),
    pytest.param(sm4, 16, id="sm4"),
]


@pytest.mark.parametrize("mod,key_len", CIPHERS)
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000])
def test_round_trip(mod, key_len, size):
    key, pt = os.urandom(key_len), os.urandom(size)
    nonce, iv = os.urandom(12), os.urandom(16)

    ct = mod.gcm_encrypt(key, nonce, pt, b"aad")
    assert len(ct) == size + mod.GCM_TAG_SIZE
    assert mod.gcm_decrypt(key, nonce, ct, b"aad") == pt

    ct = mod.cbc_encrypt(key, iv, pt)
    assert len(ct) == (size // 16 + 1) * 16
    assert mod.cbc_decrypt(key, iv, ct) == pt

    ct = mod.ctr_encrypt(key, iv, pt)
    assert len(ct) == size
    assert mod.ctr_decrypt(key, iv, ct) == pt


@pytest.mark.parametrize("mod,key_len", CIPHERS)
def test_gcm_rejects_tampering(mod, key_len):
    key, nonce = os.urandom(key_len), os.urandom(12)
    ct = mod.gcm_encrypt(key, nonce, b"attack at dawn", b"header")

    tampered = bytearray(ct)
    tampered[0] ^= 1
    with pytest.raises(CipherError, match="authentication failed"):
        mod.gcm_decrypt(key, nonce, tampered, b"header")
    with pytest.raises(CipherError, match="authentication failed"):
        mod.gcm_decrypt(key, nonce, ct, b"other header")
    with pytest.raises(CipherError):
        mod.gcm_decrypt(key, nonce, ct[:10], b"header")


@pytest.mark.parametrize("mod", [aes, sm4])
def test_invalid_lengths(mod):
    with pytest.raises(CipherError, match="key length"):
        mod.gcm_encrypt(bytes(15), bytes(12), b"")
    with pytest.raises(CipherError, match="nonce"):
        mod.gcm_encrypt(bytes(16), bytes(16), b"")
    with pytest.raises(CipherError, match="nonce"):
        mod.cbc_encrypt(bytes(16), bytes(12), b"")
    with pytest.raises(CipherError, match="nonce"):
        mod.ctr_encrypt(bytes(16), bytes(8), b"")
    with pytest.raises(CipherError, match="invalid ciphertext"):
        mod.cbc_decrypt(bytes(16), bytes(16), bytes(17))


def test_sm4_rejects_aes256_key():
    with pytest.raises(CipherError, match="key length"):
        sm4.cbc_encrypt(bytes(32), bytes(16), b"")


def test_cipher_error_is_value_error():
    assert issubclass(CipherError, ValueError)


def test_accepts_bytes_like():
    key, nonce = bytearray(16), memoryview(bytes(12))
    assert aes.gcm_encrypt(key, nonce, bytearray(b"hi")) == aes.gcm_encrypt(bytes(16), bytes(12), b"hi")


@pytest.mark.parametrize("bad", [16, "0" * 16, None])
def test_rejects_non_bytes(bad):
    with pytest.raises(TypeError, match="key must be bytes"):
        aes.ctr_encrypt(bad, bytes(16), b"")
