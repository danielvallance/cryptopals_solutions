//! This crate takes a file of hex strings, one of
//! which has been XOR-encoded, and finds the most likely
//! key and decoded message based off character frequency analysis

use single_xor_cipher_3::{get_file_character_percentages, single_xor_cipher_crack};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

/// This function iterates over the encoded hex strings in the given file,
/// attempts to find the single byte XOR key for each line, and finds the
/// decoded message with the most similar character frequencies to the reference
/// file, and returns it
pub fn get_decoded_msg(filename: &str, reference_file: &str) -> Result<(u8, String, f32), String> {
    /* Get file of encoded hex strings */
    let encoded_hex_file = match File::open(filename) {
        Ok(file) => file,
        Err(e) => return Err(e.to_string()),
    };

    let buf_reader = BufReader::new(encoded_hex_file);

    /* Keep track of key, message and chi which have most similar character frequencies to the sample text */
    let mut smallest_chi = None;
    let mut decoded_message = None;
    let mut best_key = None;

    /* Get character frequencies from reference file */
    let reference_percentages = match get_file_character_percentages(reference_file) {
        Ok(reference_percentages) => reference_percentages,
        Err(e) => return Err(e.to_string()),
    };

    /* Iterate through encoded hex strings, and try and decode them */
    for line in buf_reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => return Err(e.to_string()),
        };
        /* Attempt to find the single byte XOR key for this hex string */
        let cipher_crack_result = single_xor_cipher_crack(line.trim(), &reference_percentages);
        let (candidate_key, candidate_decoded_msg, candidate_chi) = match cipher_crack_result {
            Ok((key, decoded_msg, chi)) => (key, decoded_msg, chi),
            Err(_) => continue,
            /* If decoding was not successful, continue */
        };

        /* If this is the solution with the most similar character frequencies to the reference text, record it */
        if smallest_chi.is_none() || candidate_chi < smallest_chi.unwrap() {
            smallest_chi = Some(candidate_chi);
            decoded_message = Some(candidate_decoded_msg);
            best_key = Some(candidate_key);
        }
    }

    /* If a valid result was found return it */
    if let Some(smallest_chi) = smallest_chi {
        Ok((best_key.unwrap(), decoded_message.unwrap(), smallest_chi))
    } else {
        Err(String::from(
            "Did not find any key which resulted in a valid decoded UTF-8 string",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_decoded_msg_test() {
        let result = get_decoded_msg("hex_strings.txt", "sample-text.txt");
        assert!(result.is_ok());

        let (key, decoded_msg, chi) = result.unwrap();
        assert_eq!(key, 53);
        assert_eq!(decoded_msg, "Now that the party is jumping\n");
        assert_eq!(chi as i32, 258);
    }
}
