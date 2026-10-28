//! Known-answer tests from published standards.

use cipher_sym::{aes, sm4, Error};
use hex_literal::hex;

// NIST SP 800-38A, shared plaintext for F.2 (CBC) and F.5 (CTR).
const SP800_38A_PT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);
const SP800_38A_IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
const SP800_38A_CTR: [u8; 16] = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
const AES128_KEY: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const AES192_KEY: [u8; 24] = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
const AES256_KEY: [u8; 32] =
    hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

/// CBC output carries one extra PKCS#7 block, so compare the prefix and round-trip.
fn check_cbc(key: &[u8], expected: &[u8]) {
    let ct = aes::cbc_encrypt(key, &SP800_38A_IV, &SP800_38A_PT).unwrap();
    assert_eq!(ct.len(), SP800_38A_PT.len() + 16);
    assert_eq!(&ct[..64], expected);
    assert_eq!(
        aes::cbc_decrypt(key, &SP800_38A_IV, &ct).unwrap(),
        SP800_38A_PT
    );
}

#[test]
fn aes_cbc_sp800_38a() {
    // F.2.1
    check_cbc(
        &AES128_KEY,
        &hex!(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        ),
    );
    // F.2.3
    check_cbc(
        &AES192_KEY,
        &hex!(
            "4f021db243bc633d7178183a9fa071e8"
            "b4d9ada9ad7dedf4e5e738763f69145a"
            "571b242012fb7ae07fa9baac3df102e0"
            "08b0e27988598881d920a9e64f5615cd"
        ),
    );
    // F.2.5
    check_cbc(
        &AES256_KEY,
        &hex!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        ),
    );
}

fn check_ctr(key: &[u8], expected: &[u8]) {
    assert_eq!(
        aes::ctr_encrypt(key, &SP800_38A_CTR, &SP800_38A_PT).unwrap(),
        expected
    );
    assert_eq!(
        aes::ctr_decrypt(key, &SP800_38A_CTR, expected).unwrap(),
        SP800_38A_PT
    );
}

#[test]
fn aes_ctr_sp800_38a() {
    // F.5.1
    check_ctr(
        &AES128_KEY,
        &hex!(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        ),
    );
    // F.5.3
    check_ctr(
        &AES192_KEY,
        &hex!(
            "1abc932417521ca24f2b0459fe7e6e0b"
            "090339ec0aa6faefd5ccc2c6f4ce8e94"
            "1e36b26bd1ebc670d1bd1d665620abf7"
            "4f78a7f6d29809585a97daec58c6b050"
        ),
    );
    // F.5.5
    check_ctr(
        &AES256_KEY,
        &hex!(
            "601ec313775789a5b7a7f504bbf3d228"
            "f443e3ca4d62b59aca84e990cacaf5c5"
            "2b0930daa23de94ce87017ba2d84988d"
            "dfc9c58db67aada613c2dd08457941a6"
        ),
    );
}

// McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 4 and 16.
const GCM_PT: [u8; 60] = hex!(
    "d9313225f88406e5a55909c5aff5269a"
    "86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525"
    "b16aedf5aa0de657ba637b39"
);
const GCM_NONCE: [u8; 12] = hex!("cafebabefacedbaddecaf888");
const GCM_AAD: [u8; 20] = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");

fn check_gcm(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8], expected: &[u8]) {
    assert_eq!(aes::gcm_encrypt(key, nonce, pt, aad).unwrap(), expected);
    assert_eq!(aes::gcm_decrypt(key, nonce, expected, aad).unwrap(), pt);
}

#[test]
fn aes_gcm_mcgrew_viega() {
    // Test case 1: empty plaintext.
    check_gcm(
        &[0; 16],
        &[0; 12],
        b"",
        b"",
        &hex!("58e2fccefa7e3061367f1d57a4e7455a"),
    );
    // Test case 2.
    check_gcm(
        &[0; 16],
        &[0; 12],
        &[0; 16],
        b"",
        &hex!("0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf"),
    );
    // Test case 4: AES-128 with AAD.
    check_gcm(
        &hex!("feffe9928665731c6d6a8f9467308308"),
        &GCM_NONCE,
        &GCM_PT,
        &GCM_AAD,
        &hex!(
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
            "5bc94fbc3221a5db94fae95ae7121a47"
        ),
    );
    // Test case 16: AES-256 with AAD.
    check_gcm(
        &hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
        &GCM_NONCE,
        &GCM_PT,
        &GCM_AAD,
        &hex!(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662"
            "76fc6ece0f4e1768cddf8853bb2d551b"
        ),
    );
}

const SM4_KEY: [u8; 16] = hex!("0123456789abcdeffedcba9876543210");

#[test]
fn sm4_gbt_32907_block() {
    // GB/T 32907-2016 Appendix A.1: E(K, K) with K as both key and plaintext.
    // CBC with an all-zero IV makes the first ciphertext block a raw block encryption.
    let ct = sm4::cbc_encrypt(&SM4_KEY, &[0; 16], &SM4_KEY).unwrap();
    assert_eq!(&ct[..16], &hex!("681edf34d206965e86b3e94f536e4246"));
    assert_eq!(sm4::cbc_decrypt(&SM4_KEY, &[0; 16], &ct).unwrap(), SM4_KEY);
}

#[test]
fn sm4_gcm_rfc8998() {
    // RFC 8998 Appendix A.1.
    let nonce = hex!("00001234567800000000abcd");
    let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex!(
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"
        "ccccccccccccccccdddddddddddddddd"
        "eeeeeeeeeeeeeeeeffffffffffffffff"
        "eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
    );
    let expected = hex!(
        "17f399f08c67d5ee19d0dc9969c4bb7d"
        "5fd46fd3756489069157b282bb200735"
        "d82710ca5c22f0ccfa7cbf93d496ac15"
        "a56834cbcf98c397b4024a2691233b8d"
        "83de3541e4c2b58177e065a9bf7b62ec"
    );
    assert_eq!(
        sm4::gcm_encrypt(&SM4_KEY, &nonce, &pt, &aad).unwrap(),
        expected
    );
    assert_eq!(
        sm4::gcm_decrypt(&SM4_KEY, &nonce, &expected, &aad).unwrap(),
        pt
    );
}

#[test]
fn gcm_rejects_tampering() {
    let key = [7u8; 16];
    let nonce = [1u8; 12];
    for (enc, dec) in [
        (
            aes::gcm_encrypt as fn(&[u8], &[u8], &[u8], &[u8]) -> _,
            aes::gcm_decrypt as fn(&[u8], &[u8], &[u8], &[u8]) -> _,
        ),
        (sm4::gcm_encrypt, sm4::gcm_decrypt),
    ] {
        let ct = enc(&key, &nonce, b"hello", b"aad").unwrap();
        assert_eq!(ct.len(), 5 + 16);

        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(
            dec(&key, &nonce, &bad, b"aad"),
            Err(Error::AuthenticationFailed)
        );
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            dec(&key, &nonce, &bad, b"aad"),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            dec(&key, &nonce, &ct, b"other"),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            dec(&key, &[2u8; 12], &ct, b"aad"),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            dec(&key, &nonce, &ct[..15], b"aad"),
            Err(Error::InvalidCiphertext)
        );
    }
}

#[test]
fn rejects_bad_lengths() {
    let iv = [0u8; 16];
    assert!(matches!(
        aes::cbc_encrypt(&[0; 15], &iv, b""),
        Err(Error::InvalidKeyLength { actual: 15, .. })
    ));
    assert!(matches!(
        aes::gcm_encrypt(&[0; 33], &[0; 12], b"", b""),
        Err(Error::InvalidKeyLength { actual: 33, .. })
    ));
    assert!(matches!(
        sm4::ctr_encrypt(&[0; 32], &iv, b""),
        Err(Error::InvalidKeyLength { actual: 32, .. })
    ));
    assert!(matches!(
        aes::cbc_encrypt(&[0; 16], &[0; 12], b""),
        Err(Error::InvalidNonceLength { actual: 12, .. })
    ));
    assert!(matches!(
        aes::ctr_encrypt(&[0; 16], &[0; 8], b""),
        Err(Error::InvalidNonceLength { actual: 8, .. })
    ));
    assert!(matches!(
        sm4::gcm_encrypt(&[0; 16], &[0; 16], b"", b""),
        Err(Error::InvalidNonceLength { actual: 16, .. })
    ));
}

#[test]
fn cbc_rejects_malformed_ciphertext() {
    let key = [3u8; 16];
    let iv = [4u8; 16];
    assert_eq!(
        aes::cbc_decrypt(&key, &iv, b""),
        Err(Error::InvalidCiphertext)
    );
    assert_eq!(
        sm4::cbc_decrypt(&key, &iv, &[0; 17]),
        Err(Error::InvalidCiphertext)
    );

    // Empty plaintext still yields one full padding block.
    let ct = aes::cbc_encrypt(&key, &iv, b"").unwrap();
    assert_eq!(ct.len(), 16);
    assert_eq!(aes::cbc_decrypt(&key, &iv, &ct).unwrap(), b"");

    // Wrong key almost always produces invalid padding.
    let ct = sm4::cbc_encrypt(&key, &iv, b"0123456789abcdef").unwrap();
    assert_eq!(
        sm4::cbc_decrypt(&[9u8; 16], &iv, &ct),
        Err(Error::InvalidCiphertext)
    );
}

#[test]
fn ctr_counter_wraps_at_2_128() {
    // Matches OpenSSL: the full 128-bit block is the counter and wraps to zero.
    let key = [5u8; 16];
    let data = [0u8; 48];
    let ks = aes::ctr_encrypt(&key, &[0xff; 16], &data).unwrap();
    let after_wrap = aes::ctr_encrypt(&key, &[0; 16], &data[..32]).unwrap();
    assert_eq!(&ks[16..], &after_wrap[..]);
}
