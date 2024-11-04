//! This crate provides an API for performing multi-key XOR encoding

use core::str;

/// Return a vector containing the result of XOR encoding
/// the message with the multi byte key
pub fn multi_key_xor_encode(msg: &str, key: &str) -> Vec<u8> {
    let mut key_bytes = key.bytes().cycle();

    msg.bytes()
        .map(|msg_byte| msg_byte ^ key_bytes.next().unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_key_xor_encode_test() {
        let result = multi_key_xor_encode(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE",
        );

        let decoded = str::from_utf8(&result);
        assert!(decoded.is_ok());

        let expected_buf = crypto_utilities::hex_to_binary_buffer("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
        assert_eq!(expected_buf, result);
    }
}
