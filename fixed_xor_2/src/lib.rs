//! Solution to Challenge 2
//!
//! This crate calculated the XOR of two fixed length buffers in hexadecimal format

use crypto_utilities::{hex_to_binary_buffer, is_valid_hex};
use std::iter::zip;

/// Returns the XOR of two equal sized hexadecimal buffers
pub fn hexadecimal_xor(hex_str1: &str, hex_str2: &str) -> Result<Vec<u8>, String> {
    if !is_valid_hex(hex_str1) || !is_valid_hex(hex_str2) {
        return Err(String::from("Received hex buffers with invalid characters"));
    }

    if hex_str1.len() != hex_str2.len() {
        return Err(format!(
            "Received different length buffers, {} vs {}",
            hex_str1.len(),
            hex_str2.len()
        ));
    }

    let hex_buf1 = match hex_to_binary_buffer(hex_str1) {
        Ok(buf) => buf,
        Err(err) => return Err(err),
    };

    let hex_buf2 = match hex_to_binary_buffer(hex_str2) {
        Ok(buf) => buf,
        Err(err) => return Err(err),
    };

    let mut result = Vec::new();

    for (operand1, operand2) in zip(hex_buf1, hex_buf2) {
        result.push(operand1 ^ operand2);
    }

    Ok(result)
}

/// Takes buffer of binary data and converts it to a hexadecimal string
pub fn buffer_to_hex_string(buf: &[u8]) -> Result<String, String> {
    let mut result = String::new();

    for &byte in buf {
        let (msb, lsb) = ((byte >> 4) as u32, (byte & 0xf) as u32);

        for portion in [msb, lsb] {
            match char::from_digit(portion, 16) {
                Some(hex_digit) => result.push(hex_digit),
                None => return Err(String::from("Failed to encode buffer as hex string")),
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_hex() {
        let test_data: [(&str, &str); 3] = [("57cd", "92ag"), ("p297", "62ca"), ("8dcr", "l591")];

        for (hex_str1, hex_str2) in test_data {
            assert!(hexadecimal_xor(hex_str1, hex_str2).is_err());
        }
    }

    #[test]
    fn different_length() {
        let result = hexadecimal_xor("67c72", "8361cd");
        assert!(result.is_err());
    }

    #[test]
    fn empty_hex_xor() {
        let result = hexadecimal_xor("", "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::new());
    }

    #[test]
    fn hexadecimal_xor_normal() {
        let result = hexadecimal_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
        );
        assert!(result.is_ok());

        let result_buf = buffer_to_hex_string(&result.unwrap());
        assert!(result_buf.is_ok());

        assert_eq!(
            result_buf.unwrap(),
            String::from("746865206b696420646f6e277420706c6179"),
        );
    }

    #[test]
    fn hex_strings_to_buf_and_back() {
        let test_data = ["1234567890abcdef", "fedcba0987654321", "000030fedcba"];

        for hex in test_data {
            let buf = hex_to_binary_buffer(hex);
            assert!(buf.is_ok());

            let decoded_hex = buffer_to_hex_string(&buf.unwrap());
            assert!(decoded_hex.is_ok());

            assert_eq!(hex, decoded_hex.unwrap());
        }
    }
}
