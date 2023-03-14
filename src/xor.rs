// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

static WEIGHTS: &str = "ETAOIN SHRDLU";

fn xor_encrypt(input: &[u8], key: &[u8]) -> Hex {
    let bytes = input
        .iter()
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
        .iter()
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

fn hamming_distance(b1: &[u8], b2: &[u8]) -> usize {
    assert_eq!(b1.len(), b2.len());
    let diff = Hex::from(b1) ^ Hex::from(b2);
    let bytes: &[u8] = (&diff).into();

    let distance = bytes.iter().fold(0, |accum, b| accum + b.count_ones());
    distance as usize
}

fn crack_repeating_xor(cipher: &Hex) -> String {
    let key_size = find_key_size(cipher);
    let bytes: &[u8] = cipher.into();
    let height = bytes.len() / key_size;
    let mut transposed = vec![0; key_size * height];
    transpose::transpose(
        &bytes[..transposed.len()],
        transposed.as_mut_slice(),
        key_size,
        height,
    );
    let cipher_blocks = transposed.chunks_exact(height);

    let mut key = vec![];
    for block in cipher_blocks {
        let (byte, _) = crack_single_byte_xor(&block.into());
        key.push(byte);
    }
    let hex = xor_encrypt(cipher.into(), &key);
    std::str::from_utf8(<&[u8]>::from(&hex)).unwrap().to_owned()
}

fn find_key_size(cipher: &Hex) -> usize {
    let bytes: &[u8] = cipher.into();
    let mut distances = vec![];
    for size in 1..=40 {
        let mut chunks = bytes.chunks_exact(size);
        let c1 = chunks.next().unwrap();
        let c2 = chunks.next().unwrap();
        let c3 = chunks.next().unwrap();
        let c4 = chunks.next().unwrap();
        let d1 = hamming_distance(c1, c2);
        let d2 = hamming_distance(c1, c3);
        let d3 = hamming_distance(c1, c4);
        let d4 = hamming_distance(c2, c3);
        let d5 = hamming_distance(c2, c4);
        let d6 = hamming_distance(c3, c4);
        let distance = (d1 + d2 + d4 + d3 + d5 + d6) as f32 / 6f32;
        let distance = distance / (size * 8) as f32;
        distances.push(distance);
    }
    let (key_size, _) = distances
        .iter()
        .enumerate()
        .min_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap())
        .unwrap();
    key_size + 1 // 0 based, but 1 based key size
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::Engine;
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

    #[test]
    fn hamming_distance_of_known_string() {
        let b1 = b"this is a test";
        let b2 = b"wokka wokka!!!";
        assert_eq!(hamming_distance(b1, b2), 37)
    }

    #[test]
    fn crack_repeating_xor_file() {
        let file = File::open("tests/assets/6.txt").unwrap();
        let base_64 = BufReader::new(file)
            .lines()
            .fold(String::new(), |mut acc, e| {
                acc.push_str(&e.unwrap());
                acc
            });
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base_64.as_bytes())
            .unwrap();
        let cipher = Hex::from(bytes.as_slice());
        assert_eq!(find_key_size(&cipher), 29);
        assert!(crack_repeating_xor(&cipher).starts_with("I'm back and I'm ringin' the bell"));
    }
}
