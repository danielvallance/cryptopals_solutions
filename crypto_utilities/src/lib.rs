//! This crate contains utilities which are common to many solutions in this workspace

/// Determines if a &str is valid hexadecimal
pub fn is_valid_hex(buf: &str) -> bool {
    for c in buf.chars() {
        if !c.is_ascii_hexdigit() {
            return false;
        }
    }

    true
}

/// Turns hex string into binary buffer containing the hex data
pub fn hex_to_binary_buffer(hex: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();

    if hex.is_empty() {
        return Ok(result);
    }

    let mut cur_byte = 0;

    /*
     * Loop through the hexadecimal values and store
     * each 4 bit hex digit in part of a u8
     */
    for (idx, c) in hex.chars().enumerate() {
        let hex_mask = match c.to_digit(16) {
            Some(val) => val as u8,
            None => {
                return Err(format!(
                    "Could not parse '{}' which does not represent a value in hexadecimal",
                    c
                ))
            }
        };

        /* Store the 4 bit hex data in part of a u8 */
        if idx % 2 == 0 {
            cur_byte = hex_mask << 4;
        } else {
            cur_byte |= hex_mask;

            /* Push a u8 which contains 8 bits of prcessed data to the vector to be returned */
            result.push(cur_byte);

            /* Reinitialise to zero for the next iteration */
            cur_byte = 0;
        }
    }

    /* Push a byte containing any leftover hex data */
    if hex.len() % 2 == 1 {
        result.push(cur_byte);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hex() {
        assert!(is_valid_hex("9087654321abcdefABCDEF"));
    }

    #[test]
    fn invalid_hex_grave() {
        assert!(!is_valid_hex("9087654321abcdefABCDEF`"));
    }

    #[test]
    fn invalid_hex_ampersand() {
        assert!(!is_valid_hex("9087654321abcdefABCDEF@"));
    }

    #[test]
    fn invalid_hex_slash() {
        assert!(!is_valid_hex("9087654321abcdefABCDEF/"));
    }

    #[test]
    fn invalid_hex_colon() {
        assert!(!is_valid_hex("9087654321abcdefABCDEF:"));
    }

    #[test]
    fn invalid_hex_uppercase_g() {
        assert!(!is_valid_hex("9087654321abcdefABCDEFG"));
    }

    #[test]
    fn invalid_hex_lowercase_g() {
        assert!(!is_valid_hex("9087654321abcdefABCDEFg"));
    }

    #[test]
    fn empty_hex_string_to_buffer() {
        let buffer = hex_to_binary_buffer("");
        assert_eq!(buffer, Ok(Vec::new()))
    }

    #[test]
    fn normal_hex_string_to_binary_buffer() {
        let test_data: [(&str, Vec<u8>); 2] =
            [("4cd2", vec![76, 210]), ("8f61c", vec![143, 97, 192])];

        for (hex, buf) in test_data {
            let result = hex_to_binary_buffer(hex);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), buf);
        }
    }

    #[test]
    fn invalid_hex_to_binary_buffer() {
        let result = hex_to_binary_buffer("invalid_hex");
        assert!(result.is_err());
    }
}
