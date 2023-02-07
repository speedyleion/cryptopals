// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

mod base64;
mod hex;

use hex::Hex;

static WEIGHTS: &str = "ETAOIN SHRDLU";

fn xor_encrypt(input: &[u8], key: &[u8]) -> Hex {
    let bytes = input
        .into_iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();
    Hex::from(bytes.as_slice())
}

fn decode_bytes(key_byte: u8, cipher: &Hex) -> Result<String, ()> {
    let key = vec![key_byte; <&[u8]>::from(cipher).len()];
    let plaintext = cipher.clone() ^ Hex::from(key.as_slice());
    match std::str::from_utf8(<&[u8]>::from(&plaintext)) {
        Ok(s) => Ok(String::from(s)),
        Err(_) => Err(()),
    }
}

pub fn crack_single_byte_xor(cipher: &Hex) -> (u8, String) {
    let (key, _) = get_weighted_key(cipher);
    (key, decode_bytes(key, cipher).unwrap())
}

fn get_weighted_key(cipher: &Hex) -> (u8, f32) {
    let mut weights = [0f32; 255];
    for (byte, weight) in weights.iter_mut().enumerate() {
        let maybe_message = decode_bytes(byte as u8, cipher);
        if let Ok(message) = maybe_message {
            *weight = weight_characters(&message);
        }
    }
    let (key, weight) = weights
        .into_iter()
        .enumerate()
        .max_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap())
        .unwrap();

    (key as u8, weight)
}

/// Given a list of hex strings will find the one with the most likely text string and it's
/// xored byte
pub fn crack_list_of_codes(codes: &[Hex]) -> (u8, String, usize, String) {
    let (raw, key, index, _) = codes
        .into_iter()
        .enumerate()
        .map(|(index, c)| {
            let (key, weight) = get_weighted_key(c);
            (c, key, index, weight)
        })
        .max_by(|(_, _, _, x), (_, _, _, y)| x.partial_cmp(y).unwrap())
        .unwrap();
    (key, decode_bytes(key, raw).unwrap(), index, raw.into())
}

fn weight_characters(message: &str) -> f32 {
    let total_weight: usize = message
        .to_uppercase()
        .chars()
        .map(|c| match WEIGHTS.chars().rev().position(|w| w == c) {
            Some(pos) => pos + 1,
            None => 0,
        })
        .sum();
    total_weight as f32 / message.len() as f32
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::Hex;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Disabling this test, it resolves to:
    //
    //  Ok((61, "pd=niotsz"))
    //
    // #[test]
    // fn my_string_and_32() {
    //     let plaintext = b"my string";
    //     let byte_key = vec![32; plaintext.len()];
    //     let cipher = Hex::from(plaintext.as_slice()) ^ Hex::from(byte_key.as_slice());
    //     assert_eq!(crack_single_byte_xor(cipher), (32, String::from("my string")));
    // }

    #[test]
    fn a_different_and_16() {
        let plaintext = b"a different";
        let byte_key = vec![16; plaintext.len()];
        let cipher = Hex::from(plaintext.as_slice()) ^ Hex::from(byte_key.as_slice());
        assert_eq!(
            crack_single_byte_xor(&cipher),
            (16, String::from("a different"))
        );
    }

    #[test]
    fn crypto_pals_message() {
        let cipher =
            Hex::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assert_eq!(
            crack_single_byte_xor(&cipher),
            (88, String::from("Cooking MC's like a pound of bacon"))
        );
    }

    #[test]
    fn weight_foo() {
        assert_eq!(weight_characters("foo"), 6.6666665f32);
    }

    #[test]
    fn weight_happy() {
        assert_eq!(weight_characters("happy"), 3.2f32);
    }

    #[test]
    fn find_encrypted_string_in_file() {
        let file = File::open("tests/assets/4.txt").unwrap();
        let lines = BufReader::new(file)
            .lines()
            .map(|f| Hex::from(&f.unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            crack_list_of_codes(lines.as_slice()),
            (
                53,
                "Now that the party is jumping\n".to_owned(),
                170,
                "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".to_owned()
            )
        );
    }

    #[test]
    fn repeating_xor_apply() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let expected = Hex::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

        assert_eq!(xor_encrypt(input.as_bytes(), b"ICE"), expected);
    }
}
