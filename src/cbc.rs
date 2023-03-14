//          Copyright Nick G 2023.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)


use aes::{Aes128, Block};
use aes::cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};

trait Xor {
    fn xor(&mut self, other: &Self);
}

impl Xor for Block {
    fn xor(&mut self, other: &Self) {
        self.as_mut_slice().iter_mut()
            .zip(other.as_slice().iter())
            .for_each(|(a, b)| *a = *a ^ *b);
    }
}

pub fn encrypt(key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>, raw: impl AsRef<[u8]>) -> Vec<u8> {
    let raw = raw.as_ref();
    let encryptor = Aes128::new_from_slice(key.as_ref()).unwrap();
    let mut output = vec![0; raw.len()];
    let in_blocks = raw
        .chunks_exact(Aes128::block_size())
        .map(Block::from_slice);
    let out_blocks = output
        .chunks_exact_mut(Aes128::block_size())
        .map(Block::from_mut_slice);

    let mut iv_block = Block::clone_from_slice(iv.as_ref());
    for (in_block, out_block) in in_blocks.zip(out_blocks) {
        iv_block.xor(in_block);
        encryptor.encrypt_block_b2b(&iv_block, out_block);
        iv_block = *out_block;
    }
    output

}

fn cbc_decrypt(key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>, encrypted: impl AsRef<[u8]>) -> Vec<u8> {
    let encrypted = encrypted.as_ref();
    let decryptor = Aes128::new_from_slice(key.as_ref()).unwrap();
    let mut output = vec![0; encrypted.len()];
    let in_blocks = encrypted
        .chunks_exact(Aes128::block_size())
        .map(Block::from_slice);
    let out_blocks = output
        .chunks_exact_mut(Aes128::block_size())
        .map(Block::from_mut_slice);

    let mut iv_block = Block::clone_from_slice(iv.as_ref());
    for (in_block, out_block) in in_blocks.zip(out_blocks) {
        decryptor.decrypt_block_b2b(in_block, out_block);
        out_block.xor(&iv_block);
        iv_block = *in_block;
    }
    output

}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use base64::Engine;
    use super::*;

    #[test]
    fn yellow_sub() {
        let file = File::open("tests/assets/10.txt").unwrap();
        let base_64 = BufReader::new(file)
            .lines()
            .fold(String::new(), |mut acc, e| {
                acc.push_str(&e.unwrap());
                acc
            });
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base_64.as_bytes())
            .unwrap();
        let decrypted = cbc_decrypt("YELLOW SUBMARINE", &[0u8; 16], &bytes);
        let plaintext = String::from_utf8(decrypted).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"))
    }

    #[test]
    fn re_encrypt() {
        let file = File::open("tests/assets/10.txt").unwrap();
        let base_64 = BufReader::new(file)
            .lines()
            .fold(String::new(), |mut acc, e| {
                acc.push_str(&e.unwrap());
                acc
            });
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base_64.as_bytes())
            .unwrap();
        let decrypted = cbc_decrypt("YELLOW SUBMARINE", &[0u8; 16], &bytes);
        let encrypted = encrypt("YELLOW SUBMARINE", &[0u8; 16], &decrypted);
        assert_eq!(encrypted, bytes);
    }
}
