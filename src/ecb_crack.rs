use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use crate::{BLOCK_SIZE, ecb, pkcs, random_prefix_and_suffix};

fn fixed_ecb_encryptor(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut rng = ChaChaRng::seed_from_u64(0);
    let key = Rng::gen::<[u8; BLOCK_SIZE]>(&mut rng);
    let input = pkcs::pad(random_prefix_and_suffix(input), BLOCK_SIZE as u8);
    ecb::encrypt(key.as_ref(), input)
}

fn crack_ecb(encrypted: impl AsRef<[u8]>) -> Vec<u8> {
    vec![]

}

#[cfg(test)]
mod test {
    use super::*;
    use base64::Engine;

    #[test]
    fn successfull_crack_of_ecb() {

        let input = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(input)
            .unwrap();
        let encrypted = fixed_ecb_encryptor(bytes);

        let cracked = crack_ecb(&encrypted);
        assert_eq!(String::from_utf8(cracked).unwrap(), "what")
    }
}
