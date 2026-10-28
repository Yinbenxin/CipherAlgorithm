//! Native extension module `cipher_algorithm._native`.
//!
//! Only accepts `bytes`; the Python wrappers in `python/cipher_algorithm/`
//! normalize other bytes-like inputs and provide defaults and docs.

use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

create_exception!(
    _native,
    CipherError,
    PyValueError,
    "Raised when an encryption or decryption operation fails."
);

fn to_py_err(e: cipher_core::Error) -> PyErr {
    CipherError::new_err(e.to_string())
}

/// Defines a `#[pyfunction]` that runs `cipher_sym::$module::$func` with the GIL released.
macro_rules! py_cipher_fn {
    ($name:ident => $module:ident::$func:ident($($arg:ident),*)) => {
        #[pyfunction]
        fn $name<'py>(py: Python<'py>, $($arg: &[u8]),*) -> PyResult<Bound<'py, PyBytes>> {
            let out = py
                .detach(|| cipher_sym::$module::$func($($arg),*))
                .map_err(to_py_err)?;
            Ok(PyBytes::new(py, &out))
        }
    };
}

py_cipher_fn!(aes_gcm_encrypt => aes::gcm_encrypt(key, nonce, data, aad));
py_cipher_fn!(aes_gcm_decrypt => aes::gcm_decrypt(key, nonce, data, aad));
py_cipher_fn!(aes_cbc_encrypt => aes::cbc_encrypt(key, iv, data));
py_cipher_fn!(aes_cbc_decrypt => aes::cbc_decrypt(key, iv, data));
py_cipher_fn!(aes_ctr_encrypt => aes::ctr_encrypt(key, iv, data));
py_cipher_fn!(aes_ctr_decrypt => aes::ctr_decrypt(key, iv, data));

py_cipher_fn!(sm4_gcm_encrypt => sm4::gcm_encrypt(key, nonce, data, aad));
py_cipher_fn!(sm4_gcm_decrypt => sm4::gcm_decrypt(key, nonce, data, aad));
py_cipher_fn!(sm4_cbc_encrypt => sm4::cbc_encrypt(key, iv, data));
py_cipher_fn!(sm4_cbc_decrypt => sm4::cbc_decrypt(key, iv, data));
py_cipher_fn!(sm4_ctr_encrypt => sm4::ctr_encrypt(key, iv, data));
py_cipher_fn!(sm4_ctr_decrypt => sm4::ctr_decrypt(key, iv, data));

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("CipherError", m.py().get_type::<CipherError>())?;
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ctr_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_ctr_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_ctr_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_ctr_decrypt, m)?)?;
    Ok(())
}
