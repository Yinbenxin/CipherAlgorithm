//! Mode implementations generic over any 128-bit block cipher.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::AesGcm;
use cbc::cipher::array::Array;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::consts::{U12, U16};
use cbc::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher};
use cipher_core::{Error, Result};

pub(crate) const BLOCK_SIZE: usize = 16;
pub(crate) const GCM_NONCE_SIZE: usize = 12;
pub(crate) const GCM_TAG_SIZE: usize = 16;

fn check_iv(iv: &[u8]) -> Result<()> {
    if iv.len() != BLOCK_SIZE {
        return Err(Error::InvalidNonceLength {
            expected: "16",
            actual: iv.len(),
        });
    }
    Ok(())
}

/// GCM with a 96-bit nonce; output is `ciphertext || 16-byte tag`.
pub(crate) fn gcm_encrypt<C>(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
{
    let nonce = gcm_nonce(nonce)?;
    AesGcm::<C, U12>::new_from_slice(key)
        .map_err(|_| unreachable_key_len(key))?
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // Only reachable when the input exceeds the GCM length limit.
        .map_err(|_| Error::InvalidCiphertext)
}

pub(crate) fn gcm_decrypt<C>(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
{
    let nonce = gcm_nonce(nonce)?;
    if ciphertext.len() < GCM_TAG_SIZE {
        return Err(Error::InvalidCiphertext);
    }
    AesGcm::<C, U12>::new_from_slice(key)
        .map_err(|_| unreachable_key_len(key))?
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)
}

fn gcm_nonce(nonce: &[u8]) -> Result<Array<u8, U12>> {
    Array::try_from(nonce).map_err(|_| Error::InvalidNonceLength {
        expected: "12",
        actual: nonce.len(),
    })
}

/// CBC with PKCS#7 padding.
pub(crate) fn cbc_encrypt<C>(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
{
    check_iv(iv)?;
    let enc =
        cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_| unreachable_key_len(key))?;
    Ok(enc.encrypt_padded_vec::<Pkcs7>(plaintext))
}

pub(crate) fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherDecrypt + KeyInit,
{
    check_iv(iv)?;
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidCiphertext);
    }
    let dec =
        cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| unreachable_key_len(key))?;
    // Length and padding failures share one error so callers can't build a
    // finer-grained padding oracle on top of it. CBC is still unauthenticated.
    dec.decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| Error::InvalidCiphertext)
}

/// CTR with a 128-bit big-endian counter; `iv` is the initial counter block.
pub(crate) fn ctr_apply<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
{
    check_iv(iv)?;
    let mut ctr =
        ctr::Ctr128BE::<C>::new_from_slices(key, iv).map_err(|_| unreachable_key_len(key))?;
    let mut out = data.to_vec();
    // The counter wraps modulo 2^128 (as in OpenSSL), so the keystream cannot
    // run out for any buffer that fits in memory.
    ctr.apply_keystream(&mut out);
    Ok(out)
}

// Key lengths are validated by the public wrappers before calling into here.
fn unreachable_key_len(key: &[u8]) -> Error {
    Error::InvalidKeyLength {
        expected: "valid",
        actual: key.len(),
    }
}
