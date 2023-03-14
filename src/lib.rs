// Copyright 2022 Nick G.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

extern crate core;

mod ecb;
mod hex;
mod pkcs;
mod cbc;
use once_cell::sync::Lazy;
use rand::Rng;

const BLOCK_SIZE: usize = 16;

fn random_prefix_and_suffix(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let prefix_size = rng.gen_range(5..=10);
    let suffix_size = rng.gen_range(5..=10);

    let mut output = (0..prefix_size).map(|_| rand::Rng::gen::<u8>(&mut rng)).collect::<Vec<_>>();
    output.extend(input.as_ref());
    output.extend((0..suffix_size).map(|_| rand::Rng::gen::<u8>(&mut rng)));
    output
}

#[derive(Debug, PartialEq, Eq)]
enum EncryptionMode {
    ECB,
    CBC,
}

fn opaque_cbc_or_ecb_encryptor(input: impl AsRef<[u8]>) -> (Vec<u8>, EncryptionMode) {
    static KEY: Lazy<[u8; BLOCK_SIZE]> = Lazy::new(|| {
        let mut rng = rand::thread_rng();
        Rng::gen::<[u8; BLOCK_SIZE]>(&mut rng)
    });
    let mut rng = rand::thread_rng();
    let input = pkcs::pad(random_prefix_and_suffix(input), BLOCK_SIZE as u8);
    if Rng::gen_bool(&mut rng, 0.5) {
        (ecb::encrypt(KEY.as_ref(), input), EncryptionMode::ECB)
    } else {
        let iv = rand::Rng::gen::<[u8; BLOCK_SIZE]>(&mut rng);
        (cbc::encrypt(KEY.as_ref(), iv.as_ref(), input), EncryptionMode::CBC)
    }
}

fn detect_cbc_or_ecb(input: impl AsRef<[u8]>) -> EncryptionMode {
    let input = input.as_ref();
    let blocks = input.chunks_exact(BLOCK_SIZE).into_iter().take(4);
    let unique_blocks = blocks.collect::<std::collections::HashSet<_>>();
    if unique_blocks.len() <= 2 {
        EncryptionMode::ECB
    } else {
        EncryptionMode::CBC
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_opaque_cbc_or_ecb_encryptor() {
        let input = [b'A'; 200];
        let (output, mode) = opaque_cbc_or_ecb_encryptor(input);
        assert_eq!(detect_cbc_or_ecb(output), mode);
    }
}