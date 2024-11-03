//! Solution to Challenge 1
//!
//! This crate converts hex to base64

use crypto_utilities::{hex_to_binary_buffer, is_valid_hex};

/// Converts a u8 to the UTF-8 character its value represents in base64 encoding
///
/// The base64 bits must occupy the 6 least significant bits of the u8 parameter
pub fn base64_u8_to_utf8_char(base64: u8) -> Result<char, String> {
    let decode_error: &str = "Error while decoding u32 to UTF-8 character.";

    if base64 < 26 {
        let uppercase = char::from_u32('A' as u32 + base64 as u32).expect(decode_error);
        Ok(uppercase)
    } else if base64 < 52 {
        let lowercase = char::from_u32('a' as u32 + (base64 - 26) as u32).expect(decode_error);
        Ok(lowercase)
    } else if base64 < 62 {
        let number = char::from_u32('0' as u32 + (base64 - 52) as u32).expect(decode_error);
        Ok(number)
    } else if base64 == 62 {
        Ok('+')
    } else if base64 == 63 {
        Ok('/')
    } else {
        Err(format!(
            "Got invalid u8 which does not map to base64 value: {}",
            base64
        ))
    }
}

/// Converts base64 binary buffer to UTF-8 string
pub fn base64_buf_to_utf8_string(buf: &[u8]) -> String {
    let decode_error = "Error while decoding base64 character.";
    let mut result = String::new();

    if buf.is_empty() {
        return result;
    }

    /*
     * Record leftover bits which should be dealt with in the next iteration
     */
    let mut leftovers: u8 = 0;

    /*
     * In base64, 4 sets of 6 bits correspond to 3 UTF-8 characters
     *
     * This loop processes the binary base64 buffer in batches of 4 characters,
     * and uses bitwise operations to map these to 3 UTF-8 characters
     */
    for (idx, byte) in buf.iter().enumerate() {
        if idx % 3 == 0 {
            let c = base64_u8_to_utf8_char(byte >> 2).expect(decode_error);
            result.push(c);
            leftovers = (byte & 0x3) << 4;
        } else if idx % 3 == 1 {
            let c = base64_u8_to_utf8_char(leftovers | (byte >> 4)).expect(decode_error);
            result.push(c);
            leftovers = (byte & 0xf) << 2;
        } else {
            let c = base64_u8_to_utf8_char(leftovers | (byte >> 6)).expect(decode_error);
            result.push(c);
            result.push(base64_u8_to_utf8_char(byte & 0x3f).expect(decode_error));
        }
    }

    /* Add any leftover parts of the last processed byte */
    if buf.len() % 3 != 0 {
        let c = base64_u8_to_utf8_char(leftovers).expect(decode_error);
        result.push(c);
    }

    /* Add padding on the end */
    while result.len() % 4 != 0 {
        result.push('=');
    }

    result
}

/// Converts a &str representing hex data to a base64 buffer
///
/// Returns None if hex_str is not well-formed hexadecimal
pub fn hex_to_base64_buf(hex_str: &str) -> Result<Vec<u8>, String> {
    if !is_valid_hex(hex_str) {
        return Err(format!(
            "Could not parse invalid hexadecimal string: {}",
            hex_str
        ));
    }

    hex_to_binary_buffer(hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_base64_valid_hex_no_padding() {
        let base64_buf = hex_to_base64_buf("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert!(base64_buf.is_ok());

        let base64_string = base64_buf_to_utf8_string(&base64_buf.unwrap());
        assert_eq!(
            base64_string,
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        );
    }

    #[test]
    fn hex_to_base64_invalid_hex() {
        let result = hex_to_base64_buf("invalid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_base64_empty_input() {
        let result = hex_to_base64_buf("");
        assert_eq!(result, Ok(Vec::new()));

        let string = base64_buf_to_utf8_string(&result.unwrap());
        assert_eq!(string, "");
    }

    #[test]
    fn hex_to_base64_valid_hex_padding() {
        let test_data = [
            ("48656c6c6f2c20776f726c6421", "SGVsbG8sIHdvcmxkIQ=="),
            (
                "416e6f746865722070616464696e672074657374",
                "QW5vdGhlciBwYWRkaW5nIHRlc3Q=",
            ),
            ("abc", "qww="),
        ];

        for (hex, base64) in test_data {
            let result = hex_to_base64_buf(hex);
            assert!(result.is_ok());

            let string = base64_buf_to_utf8_string(&result.unwrap());
            assert_eq!(string, base64);
        }
    }

    #[test]
    fn base64_value_out_of_range() {
        for val in 64..u8::MAX {
            assert!(base64_u8_to_utf8_char(val).is_err());
        }
    }

    #[test]
    fn base64_values_to_printable_chars() {
        let test_data: [(u8, char); 8] = [
            (0, 'A'),
            (25, 'Z'),
            (26, 'a'),
            (51, 'z'),
            (52, '0'),
            (61, '9'),
            (62, '+'),
            (63, '/'),
        ];

        for (base64_val, char) in test_data {
            assert_eq!(base64_u8_to_utf8_char(base64_val), Ok(char));
        }
    }
}
