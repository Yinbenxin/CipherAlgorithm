//! Shared types for all CipherAlgorithm crates.

use std::fmt;

/// Errors returned by CipherAlgorithm primitives.
///
/// Messages never contain key material or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Key length is not supported by the algorithm.
    InvalidKeyLength {
        expected: &'static str,
        actual: usize,
    },
    /// Nonce / IV length is not supported by the mode.
    InvalidNonceLength {
        expected: &'static str,
        actual: usize,
    },
    /// Ciphertext is malformed (wrong length or bad padding).
    InvalidCiphertext,
    /// Authenticated decryption failed: the tag does not match.
    AuthenticationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid key length: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidNonceLength { expected, actual } => {
                write!(
                    f,
                    "invalid nonce/IV length: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidCiphertext => f.write_str("invalid ciphertext"),
            Error::AuthenticationFailed => f.write_str("authentication failed"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
