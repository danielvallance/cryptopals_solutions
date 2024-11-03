//! This crate provides an API to crack an XOR cipher with a single character key
//!
//! Each u8 is tested, and is judged as a valid solution based off character frequency of the English language

use core::str;
use crypto_utilities::{hex_to_binary_buffer, is_valid_hex};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader},
    str::Utf8Error,
};

/// Takes hex data which has been encoded by a single byte XOR,
/// and uses brute force and character frequency analysis to
/// get the most likely solution
///
/// On success, it will return the key and the decoded message string
pub fn single_xor_cipher_crack(encoded_msg: &str) -> Result<(u8, String), String> {
    if !is_valid_hex(encoded_msg) {
        return Err(format!(
            "Encoded hex message is not valid hex: {}",
            encoded_msg
        ));
    }

    /* Store hex data in buffer */
    let encoded_bytes = hex_to_binary_buffer(encoded_msg)?;

    /* Keep track of key and message which have most similar character frequencies to the sample text */
    let mut smallest_chi = None;
    let mut decoded_message = None;
    let mut best_key = None;

    /* Get character frequencies of text file containing lots of text */
    let reference_percentages = match get_file_character_percentages("sample-text.txt") {
        Ok(reference_percentages) => reference_percentages,
        Err(e) => return Err(e.to_string()),
    };

    /* Try each single byte key */
    for key in 0..255 {
        /* If decoding each byte with XOR does not result in a valid UTF-8 string, skip that iteration */
        let decode_attempt = match apply_xor_cipher(key, &encoded_bytes) {
            Ok(decode_attempt) => decode_attempt,
            Err(_) => continue,
        };

        let decoded_percentages = get_character_percentages(&decode_attempt);

        let new_chi = get_chi_squared(&reference_percentages, decoded_percentages);

        /*
         * If this key results in a decoded message with more similar character frequencies
         * to the reference text, update the provisional return values
         */
        if smallest_chi.is_none() || new_chi < smallest_chi.unwrap() {
            smallest_chi = Some(new_chi);
            decoded_message = Some(decode_attempt);
            best_key = Some(key);
        }
    }

    if smallest_chi.is_none() {
        Err(String::from(
            "Did not find any key which resulted in a valid decoded UTF-8 string",
        ))
    } else {
        Ok((best_key.unwrap(), decoded_message.unwrap()))
    }
}

/// Returns a String resulting from XORing the key with every byte in the encoded message
///
/// If the resulting bytes are not a valid UTF-8 sequence, an error is returned
pub fn apply_xor_cipher(key: u8, encoded_msg: &[u8]) -> Result<String, Utf8Error> {
    /* Get the decoded bytes by XORing every byte in the encoded message with the key */
    let decoded_bytes: Vec<u8> = encoded_msg
        .iter()
        .map(|encoded_byte| encoded_byte ^ key)
        .collect();

    /* Try and decode the bytes to a String, and return the String if successful */
    match str::from_utf8(&decoded_bytes) {
        Ok(decoded_str) => Ok(String::from(decoded_str)),
        Err(utf8_error) => Err(utf8_error),
    }
}

/// Given a &str, returns the frequency at which each character
/// appears in the text as a percentage
pub fn get_character_percentages(text: &str) -> HashMap<char, f32> {
    let total_chars = text.chars().count();

    /* Return the character frequencies as a percentage */
    get_character_frequencies(text)
        .into_iter()
        .map(|(c, count)| (c, count as f32 / (total_chars as f32 / 100.0)))
        .collect()
}

/// Given a &str, returns the number of times
/// each character appears in the text
pub fn get_character_frequencies(text: &str) -> HashMap<char, u32> {
    let mut counts: HashMap<char, u32> = HashMap::new();

    /* Get number of times each character occurs in the text */
    for c in text.chars() {
        counts.entry(c).and_modify(|count| *count += 1).or_insert(1);
    }
    counts
}

/// Get the text from the given file and return a hashmap containing the character frequency percentages
pub fn get_file_character_percentages(filename: &str) -> io::Result<HashMap<char, f32>> {
    let file = File::open(filename)?;

    /* Allocate a large buffer to memory map the file and speed up reading */
    let mut reader = BufReader::with_capacity(300 * 1024, file);

    /* Keeps a running count of how many times each character has appeared in the file */
    let mut counts = HashMap::new();
    let mut total_chars = 0;

    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        /* Get the character frequencies in each line, and update counts */
        for (c, frequency) in get_character_frequencies(&line) {
            counts
                .entry(c)
                .and_modify(|count| *count += frequency)
                .or_insert(frequency);
            total_chars += frequency;
        }

        /* Remember the newline character too */
        counts
            .entry('\n')
            .and_modify(|count| *count += 1)
            .or_insert(1);
        total_chars += 1;
    }

    let frequencies = counts
        .into_iter()
        .map(|(c, count)| (c, count as f32 / (total_chars / 100) as f32))
        .collect();

    Ok(frequencies)
}

/// Calculate the chi-squared metric on two character
/// frequency sets to determine how 'similar' they are
pub fn get_chi_squared(reference: &HashMap<char, f32>, mut msg: HashMap<char, f32>) -> f32 {
    let mut chi_squared = 0.0;

    /* First iterate over the reference frequencies, and get the chi squared values for all of those characters */
    for (char, frequency) in reference {
        let difference = msg.get(char).unwrap_or(&0.0) - frequency;
        chi_squared += (difference * difference) / frequency;

        /* Once a character has been processed, remove it from the message map */
        msg.remove(char);
    }

    /* Now process the rest of the characters */
    for (char, frequency) in msg {
        let difference = reference.get(&char).unwrap_or(&0.0) - frequency;
        chi_squared += (difference * difference) / frequency;
    }

    chi_squared
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crack_cipher() {
        let test_data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let result = single_xor_cipher_crack(test_data);
        assert!(result.is_ok());

        let (key, message) = result.unwrap();
        assert_eq!(key, 88);
        assert_eq!(message, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn apply_xor_cipher_empty() {
        let result = apply_xor_cipher(0, &Vec::new());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn apply_xor_cipher_invalid_utf8() {
        let test_data: [(&[u8], u8); 2] = [(&[255, 1], 24), (&[0, 41, 143, 9, 9], 12)];

        for (msg, key) in test_data {
            let result = apply_xor_cipher(key, msg);
            assert!(result.is_err());
        }
    }

    #[test]
    fn apply_xor_cipher_valid_uf8() {
        let test_data: [(&str, u8, &str); 2] = [
            ("asdf", 24, "yk|~"),
            ("hello i am daniel", 12, "di``c,e,ma,hmbei`"),
        ];

        for (msg, key, decoded) in test_data {
            let result = apply_xor_cipher(key, msg.as_bytes());
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), String::from(decoded));
        }
    }

    #[test]
    fn get_character_frequencies_empty() {
        let result = get_character_frequencies("");
        assert_eq!(result, HashMap::new());
    }

    #[test]
    fn get_character_frequencies_simple() {
        let result = get_character_frequencies("aaaabbcc");
        let mut expected = HashMap::new();
        expected.insert('a', 4);
        expected.insert('b', 2);
        expected.insert('c', 2);

        assert_eq!(result, expected);
    }

    #[test]
    fn get_character_percentages_empty() {
        let result = get_character_percentages("");
        assert_eq!(result, HashMap::new());
    }

    #[test]
    fn get_character_percentages_simple() {
        let result = get_character_percentages("aaaabbcc");
        let mut expected = HashMap::new();
        expected.insert('a', 50.0);
        expected.insert('b', 25.0);
        expected.insert('c', 25.0);

        assert_eq!(result, expected);
    }
}
