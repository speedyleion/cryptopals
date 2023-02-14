//          Copyright Nick G 2023.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

use aes::Aes128;
use aes::cipher::{Block, BlockDecrypt, BlockSizeUser, KeyInit};

fn ecb_decrypt(key: impl AsRef<[u8]>, encrypted: impl AsRef<[u8]>) -> Vec<u8> {
    let encrypted = encrypted.as_ref();
    let decryptor = Aes128::new_from_slice(key.as_ref()).unwrap();
    let mut output = vec![0; encrypted.len()];
    let in_blocks = encrypted.chunks_exact(Aes128::block_size()).map(|c| Block::<Aes128>::from_slice(c));
    let out_blocks = output.chunks_exact_mut(Aes128::block_size()).map(|c| Block::<Aes128>::from_mut_slice(c));
    in_blocks.zip(out_blocks).for_each(|(in_block, out_block)| decryptor.decrypt_block_b2b(in_block, out_block));
    output
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use base64::Engine;

    #[test]
    fn yellow_sub() {
        let file = File::open("tests/assets/7.txt").unwrap();
        let base_64 = BufReader::new(file).lines().fold(String::new(), |mut acc, e| {acc.push_str(&e.unwrap()); acc});
        let bytes = base64::engine::general_purpose::STANDARD.decode(base_64.as_bytes()).unwrap();
        let decrypted = ecb_decrypt("YELLOW SUBMARINE", &bytes);
        let plaintext = String::from_utf8(decrypted).unwrap();
        assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"))
    }

}
