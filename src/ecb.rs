//          Copyright Nick G 2023.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};
use aes::Aes128;
use base64::Engine;
use itertools::Itertools;
use std::borrow::Borrow;

pub fn encrypt(key: impl AsRef<[u8]>, raw: impl AsRef<[u8]>) -> Vec<u8> {
    let raw = raw.as_ref();
    let encryptor = Aes128::new_from_slice(key.as_ref()).unwrap();
    let mut output = vec![0; raw.len()];
    let in_blocks = raw
        .chunks_exact(Aes128::block_size())
        .map(Block::<Aes128>::from_slice);
    let out_blocks = output
        .chunks_exact_mut(Aes128::block_size())
        .map(Block::<Aes128>::from_mut_slice);
    in_blocks
        .zip(out_blocks)
        .for_each(|(in_block, out_block)| encryptor.encrypt_block_b2b(in_block, out_block));
    output
}

fn ecb_decrypt(key: impl AsRef<[u8]>, encrypted: impl AsRef<[u8]>) -> Vec<u8> {
    let encrypted = encrypted.as_ref();
    let decryptor = Aes128::new_from_slice(key.as_ref()).unwrap();
    let mut output = vec![0; encrypted.len()];
    let in_blocks = encrypted
        .chunks_exact(Aes128::block_size())
        .map(Block::<Aes128>::from_slice);
    let out_blocks = output
        .chunks_exact_mut(Aes128::block_size())
        .map(Block::<Aes128>::from_mut_slice);
    in_blocks
        .zip(out_blocks)
        .for_each(|(in_block, out_block)| decryptor.decrypt_block_b2b(in_block, out_block));
    output
}

fn detect_ecb(lines: impl IntoIterator<Item = impl Borrow<str>>) -> Option<usize> {
    for (index, line) in lines.into_iter().enumerate() {
        let line = line.borrow();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(line)
            .unwrap();
        let chunks = bytes.chunks_exact(Aes128::block_size());
        if chunks.into_iter().duplicates().next().is_some() {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::Engine;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn yellow_sub() {
        let file = File::open("tests/assets/7.txt").unwrap();
        let base_64 = BufReader::new(file)
            .lines()
            .fold(String::new(), |mut acc, e| {
                acc.push_str(&e.unwrap());
                acc
            });
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base_64.as_bytes())
            .unwrap();
        let decrypted = ecb_decrypt("YELLOW SUBMARINE", &bytes);
        let plaintext = String::from_utf8(decrypted).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"))
    }

    #[test]
    fn re_encrypt() {
        let file = File::open("tests/assets/7.txt").unwrap();
        let base_64 = BufReader::new(file)
            .lines()
            .fold(String::new(), |mut acc, e| {
                acc.push_str(&e.unwrap());
                acc
            });
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base_64.as_bytes())
            .unwrap();
        let decrypted = ecb_decrypt("YELLOW SUBMARINE", &bytes);
        // let plaintext = String::from_utf8(decrypted).unwrap();
        // assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
        let encrypted = encrypt("YELLOW SUBMARINE", &decrypted);
        assert_eq!(encrypted, bytes);
    }

    #[test]
    fn find_ecb() {
        let file = File::open("tests/assets/8.txt").unwrap();
        let lines = BufReader::new(file).lines().map(|x| x.unwrap());
        assert_eq!(detect_ecb(lines), Some(132));
    }
}
