//! Solution to Challenge 1
//!
//! This crate converts hex to base64

/// Determines if a &str is valid hexadecimal
pub fn is_valid_hex(buf: &str) -> bool {
    for c in buf.chars() {
        if !c.is_ascii_hexdigit() {
            return false;
        }
    }

    true
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
}
