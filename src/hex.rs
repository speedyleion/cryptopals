// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Hex decoder to bytes

use once_cell::sync::Lazy;
use std::collections::HashMap;

static LOOKUP_TABLE: Lazy<HashMap<char, u8>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert('0', 0u8);
    m.insert('1', 1);
    m.insert('2', 2);
    m.insert('3', 3);
    m.insert('4', 4);
    m.insert('5', 5);
    m.insert('6', 6);
    m.insert('7', 7);
    m.insert('8', 8);
    m.insert('9', 9);
    m.insert('a', 10);
    m.insert('b', 11);
    m.insert('c', 12);
    m.insert('d', 13);
    m.insert('e', 14);
    m.insert('f', 15);
    m
});

#[derive(Debug, Default, Eq, PartialEq, PartialOrd)]
pub struct Hex {
    bytes: Vec<u8>,
}

impl<T: AsRef<str>> From<T> for Hex {
    fn from(string: T) -> Self {
        let string = string.as_ref();
        let mut bytes = vec![];
        if string.is_empty() {
            return Self { bytes };
        }

        // NEED to ensure an even number of characters
        let upper = string.chars().step_by(2);
        let lower = string[1..].chars().step_by(2);

        for (high, low) in upper.zip(lower) {
            let high_nyble = LOOKUP_TABLE.get(&high).unwrap();
            let low_nyble = LOOKUP_TABLE.get(&low).unwrap();
            let value = (high_nyble << 4) | low_nyble;
            bytes.push(value);
        }
        Self { bytes }
    }
}

impl<'a> From<&'a Hex> for &'a [u8] {
    fn from(hex: &'a Hex) -> Self {
        &hex.bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[test]
    fn hex_from_empty_string() {
        assert_eq!(Hex::from(""), Hex { bytes: vec![] });
    }

    #[parameterized(
    zero_one = { "01", &[1] },
    zero_two = { "02", &[2] },
    long_hex = { "abcdef1234567890", &[171, 205, 239, 18, 52, 86, 120, 144] },
    )]
    fn hex_from(input: &str, expected: &[u8]) {
        assert_eq!(
            Hex::from(input),
            Hex {
                bytes: Vec::from(expected)
            }
        );
    }
}
