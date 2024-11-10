//! This crate uses Rust FFI bindings of the OpenSSL library to
//! provide an API for decrypting AES-128 in ECB mode.

use break_repeating_key_xor_6::base64_to_binary_buf;
use openssl::symm::{decrypt, Cipher};
use std::error::Error;

/// Takes in data which was encrypted with AES-128 in ECB mode, then base64 encoded,
/// and uses the key to decrypt it and return the plaintext
pub fn decrypt_aes_ecb(encrypted_base64: &str, key: &[u8]) -> Result<String, Box<dyn Error>> {
    // Decode base64 input
    let encrypted_data = base64_to_binary_buf(encrypted_base64)?;

    let cipher = Cipher::aes_128_ecb();

    // Decrypt the data
    let decrypted_data = decrypt(
        cipher,
        key,
        None, // ECB does not use an IV so we pass None here
        &encrypted_data,
    )?;

    Ok(String::from_utf8(decrypted_data)?)
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use super::*;

    #[test]
    fn test_decrypt_aes_128_ecb() {
        let mut encrypted_file = File::open("encrypted_data.txt").unwrap();
        let mut encryped_string = String::new();
        encrypted_file.read_to_string(&mut encryped_string).unwrap();
        encryped_string.retain(|c| !c.is_whitespace());
        let key = "YELLOW SUBMARINE".as_bytes();

        let result = decrypt_aes_ecb(&encryped_string, key);
        assert!(result.is_ok());

        let mut expected_file = File::open("expected.txt").unwrap();
        let mut expected_string = String::new();
        expected_file.read_to_string(&mut expected_string).unwrap();

        assert_eq!(result.unwrap(), expected_string);
    }
}
