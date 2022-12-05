// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//! Perform base64 encoding bytes. Detail on base64 encoding is
//! available at https://en.wikipedia.org/wiki/Base64

/// Provides the look up of a 6 bit value to the representative base64 value
const LOOKUP_TABLE: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

const PAD: char = '=';

/// Mask that only allows the lower 6 bits of a u8
const SEXTET_MASK: u8 = 0b00111111u8;

/// A base 64 representation of some bytes
#[derive(Debug, Default, Eq, PartialEq, PartialOrd)]
pub struct Base64 {
    contents: String,
}

fn sextet_1(byte: u8) -> char {
    let index = byte >> 2;
    LOOKUP_TABLE[index as usize]
}

fn sextet_2(byte_1: u8, byte_2: u8) -> char {
    let mut index = (byte_1 << 4) & SEXTET_MASK;
    index |= byte_2 >> 4;
    LOOKUP_TABLE[index as usize]
}

fn sextet_3(byte_1: u8, byte_2: u8) -> char {
    let mut index = (byte_1 << 2) & SEXTET_MASK;
    index |= byte_2 >> 6;
    LOOKUP_TABLE[index as usize]
}

fn sextet_4(byte: u8) -> char {
    let index = byte & SEXTET_MASK;
    LOOKUP_TABLE[index as usize]
}

impl From<&[u8]> for Base64 {
    fn from(bytes: &[u8]) -> Self {
        let octets = bytes.chunks_exact(3);
        let mut contents = String::new();
        let remainder = octets.remainder();

        for chunk in octets {
            contents.push(sextet_1(chunk[0]));
            contents.push(sextet_2(chunk[0], chunk[1]));
            contents.push(sextet_3(chunk[1], chunk[2]));
            contents.push(sextet_4(chunk[2]));
        }

        match remainder.len() {
            0 => {}
            1 => {
                let byte = remainder[0];
                contents.push(sextet_1(byte));
                contents.push(sextet_2(byte, 0));
                contents.push(PAD);
                contents.push(PAD);
            }
            2 => {
                contents.push(sextet_1(remainder[0]));
                contents.push(sextet_2(remainder[0], remainder[1]));
                contents.push(sextet_3(remainder[1], 0));
                contents.push(PAD);
            }
            _ => panic!("Should only every have 2 items in remainder"),
        }

        Self { contents }
    }
}

impl From<&str> for Base64 {
    fn from(src: &str) -> Self {
        Self::from(src.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex::Hex;
    use yare::parameterized;

    #[test]
    fn from_empty_string() {
        assert_eq!(
            Base64::from(""),
            Base64 {
                contents: String::from("")
            }
        );
    }

    // https://www.base64encode.org/ was used to create the input
    #[parameterized(
    d = { "d", "ZA==" },
    a = { "a", "YQ==" },
    ma = { "Ma", "TWE=" },
    jk = { "jk", "ams=" },
    )]
    fn from(input: &str, base_64: &str) {
        assert_eq!(
            Base64::from(input),
            Base64 {
                contents: String::from(base_64)
            }
        );
    }

    // Taken from wikipedia description at https://en.wikipedia.org/wiki/Base64#Output_padding
    #[parameterized(
    light_work_ = { "light work.", "bGlnaHQgd29yay4=" },
    light_work = { "light work", "bGlnaHQgd29yaw==" },
    light_wor = { "light wor", "bGlnaHQgd29y" },
    light_wo = { "light wo", "bGlnaHQgd28=" },
    light_w = { "light w", "bGlnaHQgdw==" },
    )]
    fn from_light_work(input: &str, base_64: &str) {
        assert_eq!(
            Base64::from(input),
            Base64 {
                contents: String::from(base_64)
            }
        );
    }

    // The test from https://cryptopals.com/sets/1/challenges/1
    #[test]
    fn crypto_pals_set1_challenge_1() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let hex = Hex::from(input);
        let hex_bytes: &[u8] = (&hex).into();
        assert_eq!(
            Base64::from(hex_bytes),
            Base64 {
                contents: String::from(expected)
            }
        );
    }
}
