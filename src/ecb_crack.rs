use std::collections::{HashMap, VecDeque};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use crate::{BLOCK_SIZE, ecb, pkcs, random_prefix_and_suffix};

fn fixed_ecb_encryptor(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut rng = ChaChaRng::seed_from_u64(0);
    let key = Rng::gen::<[u8; BLOCK_SIZE]>(&mut rng);
    let input = pkcs::pad(random_prefix_and_suffix(input), BLOCK_SIZE as u8);
    ecb::encrypt(key.as_ref(), input)
}

fn compute_byte_map(block_prefix: &[u8]) -> HashMap<u8, u8> {
    let mut byte_map = HashMap::new();
    for i in 0..=255 {
        let mut input = block_prefix.to_vec();
        input.push(i);
        let output = fixed_ecb_encryptor(&input);
        byte_map.insert(output[BLOCK_SIZE - 1], i);
    }
    byte_map
}
fn crack_ecb(plaintext: impl AsRef<[u8]>) -> Vec<u8> {
    let plaintext = plaintext.as_ref();

    let mut block = vec![b'A'; BLOCK_SIZE];
    let mut output = vec![];

    for byte  in plaintext {
        let byte_map = compute_byte_map(&block[..BLOCK_SIZE - 1]);
        block[BLOCK_SIZE - 1] = *byte;
        let first_block = fixed_ecb_encryptor(&block);
        let decoded_byte = byte_map[&first_block[BLOCK_SIZE - 1]];
        output.push(decoded_byte);
        block.remove(0);
        block.push(decoded_byte);
    }
    output
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::Engine;

    #[test]
    fn successfull_crack_of_ecb() {

        let input = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(input)
            .unwrap();
        let cracked = crack_ecb(&plaintext);
        assert_eq!(String::from_utf8(cracked).unwrap(), "what")
    }
}
