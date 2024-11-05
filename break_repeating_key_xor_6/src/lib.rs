//! This crate breaks the base64, XOR encoded data in encoded_data.txt

use std::{
    cmp::{max, min, Reverse},
    collections::BinaryHeap,
    iter::zip,
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
/// off the Hamming distance between the first two
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
     * Binary heap of key sizes, and associated Hamming
     * distances of first two blocks of key size bytes
     *
     * The first element of the tuple will be the Hamming
     * distance as that is what determines the ordering
     * in (i32,u8)'s default implementation of Ord
     */
    let mut keysizes = BinaryHeap::<Reverse<(i32, u8)>>::new();

    /* Iterate through the range of key sizes given */
    for key_size in max(1, min_key_size)..=min(max_key_size, encoded_msg.len() / 2) {
        /*
         * Find the Hamming distance of the first and seconds blocks
         * of key_size bytes (this should be an indicator of how likely it
         * is that the given key_size is correct)
         */
        let hamming = get_hamming_distance(
            &encoded_msg[0..key_size],
            &encoded_msg[key_size..2 * key_size],
        )
        .unwrap();

        /*
         * Insert the normalise Hamming distance and keysize pair into the
         * binary heap, sorted by Hamming distance (in ascending order)
         */
        keysizes.push(Reverse((hamming / key_size as i32, key_size as u8)));

        /* Pop the pair with the largest Hamming distance if necessary */
        if keysizes.len() > no_of_sizes {
            keysizes.pop();
        }
    }

    /* Return the most likely key sizes */
    keysizes
        .into_iter()
        .map(|Reverse((_, key_size))| key_size)
        .collect()
}

#[cfg(test)]
mod tests {
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
}
