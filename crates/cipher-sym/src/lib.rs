//! Symmetric ciphers: AES and SM4 in GCM / CBC / CTR modes.
//!
//! Both ciphers expose the same functions:
//!
//! - `gcm_encrypt` / `gcm_decrypt`: 12-byte nonce, output is `ciphertext || 16-byte tag`.
//! - `cbc_encrypt` / `cbc_decrypt`: 16-byte IV, PKCS#7 padding. Not authenticated.
//! - `ctr_encrypt` / `ctr_decrypt`: 16-byte initial counter block, 128-bit
//!   big-endian counter (NIST SP 800-38A). Not authenticated.
//!
//! A GCM nonce or CTR counter block must never be reused with the same key.

mod mode;

pub use cipher_core::{Error, Result};

/// Length in bytes of a GCM nonce.
pub const GCM_NONCE_SIZE: usize = mode::GCM_NONCE_SIZE;
/// Length in bytes of the GCM authentication tag appended to the ciphertext.
pub const GCM_TAG_SIZE: usize = mode::GCM_TAG_SIZE;
/// Length in bytes of a CBC IV / CTR counter block.
pub const IV_SIZE: usize = mode::BLOCK_SIZE;

/// AES-128 / AES-192 / AES-256, selected by key length (16 / 24 / 32 bytes).
pub mod aes {
    use super::mode;
    use aes::{Aes128, Aes192, Aes256};
    use cipher_core::{Error, Result};

    /// Dispatches to the AES variant matching the key length.
    macro_rules! dispatch {
        ($f:ident, $key:expr, $($arg:expr),*) => {
            match $key.len() {
                16 => mode::$f::<Aes128>($key, $($arg),*),
                24 => mode::$f::<Aes192>($key, $($arg),*),
                32 => mode::$f::<Aes256>($key, $($arg),*),
                n => Err(Error::InvalidKeyLength { expected: "16, 24 or 32", actual: n }),
            }
        };
    }

    pub fn gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        dispatch!(gcm_encrypt, key, nonce, plaintext, aad)
    }

    pub fn gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        dispatch!(gcm_decrypt, key, nonce, ciphertext, aad)
    }

    pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        dispatch!(cbc_encrypt, key, iv, plaintext)
    }

    pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        dispatch!(cbc_decrypt, key, iv, ciphertext)
    }

    pub fn ctr_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        dispatch!(ctr_apply, key, iv, plaintext)
    }

    pub fn ctr_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        dispatch!(ctr_apply, key, iv, ciphertext)
    }
}

/// SM4 (GB/T 32907-2016), 16-byte key.
pub mod sm4 {
    use super::mode;
    use cipher_core::{Error, Result};
    use sm4::Sm4;

    /// Length in bytes of an SM4 key.
    pub const KEY_SIZE: usize = 16;

    fn check_key(key: &[u8]) -> Result<()> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: "16",
                actual: key.len(),
            });
        }
        Ok(())
    }

    pub fn gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        check_key(key)?;
        mode::gcm_encrypt::<Sm4>(key, nonce, plaintext, aad)
    }

    pub fn gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        check_key(key)?;
        mode::gcm_decrypt::<Sm4>(key, nonce, ciphertext, aad)
    }

    pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        check_key(key)?;
        mode::cbc_encrypt::<Sm4>(key, iv, plaintext)
    }

    pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        check_key(key)?;
        mode::cbc_decrypt::<Sm4>(key, iv, ciphertext)
    }

    pub fn ctr_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        check_key(key)?;
        mode::ctr_apply::<Sm4>(key, iv, plaintext)
    }

    pub fn ctr_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        check_key(key)?;
        mode::ctr_apply::<Sm4>(key, iv, ciphertext)
    }
}
