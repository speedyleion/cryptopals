// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Hex decoder to bytes

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ops::BitXor;

static INDEX_TO_CHAR: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
static CHAR_TO_BYTE: Lazy<HashMap<char, u8>> = Lazy::new(|| {
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

#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd)]
pub struct Hex {
    bytes: Vec<u8>,
}

impl From<&str> for Hex {
    fn from(string: &str) -> Self {
        let mut bytes = vec![];
        if string.is_empty() {
            return Self { bytes };
        }

        // NEED to ensure an even number of characters
        let upper = string.chars().step_by(2);
        let lower = string[1..].chars().step_by(2);

        for (high, low) in upper.zip(lower) {
            let high_nyble = CHAR_TO_BYTE.get(&high).unwrap();
            let low_nyble = CHAR_TO_BYTE.get(&low).unwrap();
            let value = (high_nyble << 4) | low_nyble;
            bytes.push(value);
        }
        Self { bytes }
    }
}

impl From<&[u8]> for Hex {
    fn from(bytes: &[u8]) -> Self {
        Hex {
            bytes: Vec::from(bytes),
        }
    }
}

impl<'a> From<&'a Hex> for &'a [u8] {
    fn from(hex: &'a Hex) -> Self {
        &hex.bytes
    }
}

impl From<&Hex> for String {
    fn from(hex: &Hex) -> Self {
        let mut string = String::new();
        for byte in hex.bytes.iter() {
            let high = byte >> 4;
            let low = byte & 0xF;
            string.push(INDEX_TO_CHAR[high as usize]);
            string.push(INDEX_TO_CHAR[low as usize]);
        }
        string
    }
}

impl BitXor for Hex {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        assert_eq!(self.bytes.len(), rhs.bytes.len());
        let bytes = self
            .bytes
            .iter()
            .zip(rhs.bytes.iter())
            .map(|(x, y)| *x ^ *y)
            .collect();
        Self { bytes }
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

    #[test]
    fn xor_hex_strings() {
        let first = "1c0111001f010100061a024b53535009181c";
        let second = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";
        let xor = Hex::from(first) ^ Hex::from(second);
        assert_eq!(String::from(&xor), expected.to_string())
    }
}
