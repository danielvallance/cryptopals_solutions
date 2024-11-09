//! This crate breaks the base64, XOR encoded data in encoded_data.txt

use std::{
    cmp::{max, min},
    collections::{BinaryHeap, HashMap},
    fs::File,
    io::Read,
    iter::zip,
    str,
};

use repeating_key_xor_5::multi_key_xor_encode;
use single_xor_cipher_3::{
    get_character_percentages, get_chi_squared, get_file_character_percentages,
    single_xor_cipher_crack,
};

/// This function computes the Hamming distance between two u8 buffers
pub fn get_hamming_distance(buf1: &[u8], buf2: &[u8]) -> Result<i32, String> {
    /*  The Hamming distance can only be calculated between two equal length buffers */
    if buf1.len() != buf2.len() {
        return Err(String::from(
            "Cannot compute Hamming distance between two different length buffers.\n",
        ));
    }

    let mut hamming = 0;

    /* Loop through each pair of bytes */
    for (byte1, byte2) in zip(buf1, buf2) {
        /* The XOR of the bytes returns a byte with a bit set for each bit that differs */
        let mut xor = byte1 ^ byte2;

        /* Increment Hamming distance for each bit set in xor */
        while xor != 0 {
            hamming += 1;
            xor &= xor - 1;
        }
    }

    Ok(hamming)
}

/// This function gets the likely key sizes based
/// off the average Hamming distance between consecutive
/// blocks of "keysize" bytes in the encoded message
pub fn get_likely_key_sizes(
    encoded_msg: &[u8],
    min_key_size: usize,
    max_key_size: usize,
    no_of_sizes: usize,
) -> Vec<u8> {
    /* If no likely keysizes were requested, return */
    if no_of_sizes == 0 {
        return Vec::new();
    }

    /*
     * Binary heap of key sizes, and associated average Hamming
     * distances between consecutive blocks of key size bytes
     *
     * The first element of the tuple will be the Hamming
     * distance as that is what determines the ordering
     * in (i32,u8)'s default implementation of Ord
     */
    let mut keysizes = BinaryHeap::<(i32, u8)>::new();

    /* Iterate through the range of key sizes given */
    for key_size in max(1, min_key_size)..=min(max_key_size, encoded_msg.len() / 2) {
        /*
         * Find the total Hamming distances between consecutive blocks
         * of key_size bytes (this should be an indicator of how likely it
         * is that the given key_size is correct)
         */
        let mut start = 0;
        let mut middle = key_size;
        let mut end = 2 * key_size;
        let mut total_hamming = 0;
        while end <= encoded_msg.len() {
            total_hamming +=
                get_hamming_distance(&encoded_msg[start..middle], &encoded_msg[middle..end])
                    .unwrap();
            start += key_size;
            middle += key_size;
            end += key_size;
        }

        /* Obtain the average Hamming distance between consecutive blocks */
        let average_hamming = total_hamming / (encoded_msg.len() / key_size) as i32;

        /*
         * Insert the normalised Hamming distance and keysize pair into the
         * binary heap, sorted by Hamming distance (in ascending order)
         *
         * The average Hamming distance was multiplied by 1000 before normalising
         * for greater granularity
         */
        keysizes.push((average_hamming * 1000 / key_size as i32, key_size as u8));

        /* Pop the pair with the largest Hamming distance if necessary */
        if keysizes.len() > no_of_sizes {
            keysizes.pop();
        }
    }

    /* Return the most likely key sizes */
    keysizes.into_iter().map(|(_, key_size)| key_size).collect()
}

/// Given the encoded message and key size, returns the key
/// which when XORed with the encoded message, results in the decoded
/// text with the most similar character frequencies to the reference
/// frequencies passed
pub fn get_sized_key(
    encoded_msg: &[u8],
    key_size: usize,
    reference_percentages: &HashMap<char, f32>,
) -> Result<Vec<u8>, String> {
    let mut key = Vec::new();

    /*
     * Since we are doing multi-byte XORing, we can use
     * crack the key a byte at a time, by collecting all
     * the bytes which that byte of the key will apply to,
     * then acting as if it was a single byte XOR cipher
     * */
    for key_byte_no in 0..key_size {
        let mut current_encoded_bytes = Vec::new();
        for (idx, byte) in encoded_msg.iter().enumerate() {
            if idx % key_size == key_byte_no {
                current_encoded_bytes.push(*byte);
            }
        }

        key.push(single_xor_cipher_crack(&current_encoded_bytes, reference_percentages)?.0);
        current_encoded_bytes.clear();
    }

    Ok(key)
}

/// Converts a base64 character into its base64 numeric value
pub fn char_to_base64_value(c: char) -> Result<Option<u8>, String> {
    match c {
        'A'..='Z' => Ok(Some((c as u32 - 'A' as u32) as u8)),
        'a'..='z' => Ok(Some((c as u32 - 'a' as u32 + 26) as u8)),
        '0'..='9' => Ok(Some((c as u32 - '0' as u32 + 52) as u8)),
        '+' => Ok(Some(62)),
        '/' => Ok(Some(63)),
        '=' => Ok(None),
        _ => Err(String::from("Non base64 character passed")),
    }
}

/// Decodes a base64 string into the corresponding binary buffer
pub fn base64_to_binary_buf(base64: &str) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();

    /* Perform the marshaling 24 bits at a time, as base64 operates on groups of 24 bits */
    let mut temp: [u8; 3] = [0; 3];

    for (idx, base64_char) in base64.chars().enumerate() {
        if let Some(base64_value) = char_to_base64_value(base64_char)? {
            match idx % 4 {
                0 => temp[0] = base64_value << 2,
                1 => {
                    temp[0] |= base64_value >> 4;
                    temp[1] = base64_value << 4;
                }
                2 => {
                    temp[1] |= base64_value >> 2;
                    temp[2] = base64_value << 6;
                }
                _ => {
                    temp[2] |= base64_value;
                    /* Push bytes into buffer once 24 bits have been processed */
                    for byte in temp {
                        buffer.push(byte);
                    }
                    /* Reinitialise to zero for next iteration */
                    temp = [0; 3];
                }
            }
        } else {
            /* If padding is encountered, push remaining bytes which contain data */
            match idx % 4 {
                0 => (),
                1 => buffer.push(temp[0]),
                2 => {
                    buffer.push(temp[0]);
                    buffer.push(temp[1]);
                }
                _ => {
                    for byte in temp {
                        buffer.push(byte);
                    }
                }
            }
            break;
        }
    }

    Ok(buffer)
}

/// Crack the base64 encoded, XOR encoded data by
/// using Hamming distance to obtain guesses for the key size,
/// then crack the key a byte at a time, acting as if it was a series
/// of single byte XOR ciphers
pub fn crack_base64_repeating_key_xor(
    encoded_msg_file: &str,
    reference_file: &str,
    min_key_size: usize,
    max_key_size: usize,
    no_of_sizes: usize,
) -> Result<String, String> {
    /* Get the encoded message into a String */
    let mut file = match File::open(encoded_msg_file) {
        Ok(file) => file,
        Err(e) => return Err(e.to_string()),
    };
    let mut file_text = String::new();
    if let Err(e) = file.read_to_string(&mut file_text) {
        return Err(e.to_string());
    };

    /* Newlines are not base64, so remove them */
    file_text.retain(|c| !c.is_whitespace());

    /* Marshal the base64 string into a binary buffer */
    let buffer = base64_to_binary_buf(&file_text)?;

    /* Use the Hamming distances to get the likely key sizes */
    let likely_key_sizes = get_likely_key_sizes(&buffer, min_key_size, max_key_size, no_of_sizes);

    /* Keep track of which key sizes resulted in the most plausible character frequencies in the decoded message */
    let mut best_chi_squared = None;
    let mut best_decoded = None;

    /* Get character frequencies of reference file */
    let reference_percentages = match get_file_character_percentages(reference_file) {
        Ok(reference_percentages) => reference_percentages,
        Err(e) => return Err(e.to_string()),
    };

    /* For each key size, get the most likely key */
    for key_size in likely_key_sizes {
        /* If a key could not be obtained, move onto the next key size */
        let key = match get_sized_key(&buffer, key_size as usize, &reference_percentages) {
            Ok(key) => key,
            Err(_) => continue,
        };

        /* Decode the message using the key */
        let decoded = multi_key_xor_encode(&buffer, &key);

        /* If the result is not a valid UTF-8 string, continue to the next key size */
        let decoded_str = match str::from_utf8(&decoded) {
            Ok(decoded_str) => decoded_str,
            Err(_) => continue,
        };

        /* Get metric on how plausible the character frequencies in the decoded message are */
        let decoded_percentages = get_character_percentages(decoded_str);
        let chi_squared = get_chi_squared(&reference_percentages, decoded_percentages);

        /* If this key results in more plausible character frequencies, record it */
        if best_chi_squared.is_none() || chi_squared < best_chi_squared.unwrap() {
            best_chi_squared = Some(chi_squared);
            best_decoded = Some(String::from(decoded_str));
        }
    }

    /* If a decoded message was obtained, return it */
    match best_decoded {
        Some(ret) => Ok(ret),
        _ => Err(String::from("Could not decode the given base64 file.")),
    }
}

#[cfg(test)]
mod tests {
    use hex_to_base64_1::{base64_buf_to_utf8_string, base64_u8_to_utf8_char};

    use super::*;

    #[test]
    fn test_hamming_distance() {
        let result = get_hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 37);
    }

    #[test]
    fn empty_hamming_distance() {
        let result = get_hamming_distance("".as_bytes(), "".as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn unequal_length_hamming_distance() {
        let result = get_hamming_distance(
            "this is a test for uneven strings".as_bytes(),
            "wokka wokka!!!".as_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn base64_invalid_chars() {
        let out_of_range_values = ['*', ',', '.', ':', '@', '[', '`', '{', '<', '>'];
        for out_of_range_value in out_of_range_values {
            assert!(char_to_base64_value(out_of_range_value).is_err());
        }
    }

    #[test]
    fn base64_convert_chars_and_back() {
        for i in 0..64 {
            let utf8_char = base64_u8_to_utf8_char(i);
            assert!(utf8_char.is_ok());

            let base64_value = char_to_base64_value(utf8_char.unwrap());
            assert!(base64_value.is_ok());
            let base64_value = base64_value.unwrap();
            assert!(base64_value.is_some());
            assert_eq!(i, base64_value.unwrap());
        }
    }

    #[test]
    fn base64_equals_sign_is_none() {
        let result = char_to_base64_value('=');
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn base64_to_buf_and_back() {
        let test_data = ["", "SGVsbG8gd29ybGQh"];

        for base64_string in test_data {
            let buffer = base64_to_binary_buf(base64_string);
            assert!(buffer.is_ok());
            let buffer = buffer.unwrap();
            let result = base64_buf_to_utf8_string(&buffer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), base64_string);
        }
    }

    #[test]
    fn decode_test() {
        let mut expected_file = File::open("expected.txt").unwrap();
        let mut expected_text = String::new();
        expected_file.read_to_string(&mut expected_text).unwrap();

        let result =
            crack_base64_repeating_key_xor("encoded_data.txt", "sample-text.txt", 2, 40, 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_text);
    }
}
