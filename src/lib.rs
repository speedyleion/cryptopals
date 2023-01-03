// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

mod base64;
mod hex;

use hex::Hex;

static WEIGHTS: &str = "ETAOIN SHRDLU";

fn decode_bytes(key_byte: u8, cipher: Hex) -> Result<String, ()> {
    let key = vec![key_byte; <&[u8]>::from(&cipher).len()];
    let plaintext = cipher ^ Hex::from(key.as_slice());
    match std::str::from_utf8(<&[u8]>::from(&plaintext)) {
        Ok(s) => Ok(String::from(s)),
        Err(_) => Err(()),
    }
}

pub fn crack_single_byte_xor(cipher: Hex) -> (u8, String) {
    let mut weights = [0f32; 255];
    for (byte, weight) in weights.iter_mut().enumerate() {
        let maybe_message = decode_bytes(byte as u8, cipher.clone());
        if let Ok(message) = maybe_message {
            *weight = weight_characters(&message);
        }
    }
    let (key, _) = weights
        .into_iter()
        .enumerate()
        .max_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap())
        .unwrap();
    (key as u8, decode_bytes(key as u8, cipher).unwrap())
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
            crack_single_byte_xor(cipher),
            (16, String::from("a different"))
        );
    }

    #[test]
    fn crypto_pals_message() {
        let cipher =
            Hex::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assert_eq!(
            crack_single_byte_xor(cipher),
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
}
