//! This crate breaks the base64, XOR encoded data in encoded_data.txt

use std::iter::zip;

/// This function computes the Hamming distance between two &strs
pub fn get_hamming_distance(str1: &str, str2: &str) -> Result<i32, String> {
    // The Hamming distance can only be calculated between two equal length strings
    if str1.len() != str2.len() {
        return Err(String::from(
            "Cannot compute Hamming distance between two different length strings.\n",
        ));
    }

    let mut hamming = 0;

    // Loop through each pair of bytes
    for (byte1, byte2) in zip(str1.bytes(), str2.bytes()) {
        // The XOR of the bytes returns a byte with a bit set for each bit that differs
        let mut xor = byte1 ^ byte2;

        // Increment hamming distance for each bit set in xor
        while xor != 0 {
            hamming += 1;
            xor &= xor - 1;
        }
    }

    Ok(hamming)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        let result = get_hamming_distance("this is a test", "wokka wokka!!!");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 37);
    }

    #[test]
    fn empty_hamming_distance() {
        let result = get_hamming_distance("", "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn unequal_length_hamming_distance() {
        let result = get_hamming_distance("this is a test for uneven strings", "wokka wokka!!!");
        assert!(result.is_err());
    }
}
