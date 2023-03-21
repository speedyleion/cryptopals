use rand::{Rng, SeedableRng};
use crate::{BLOCK_SIZE, ecb, EncryptionMode, pkcs, random_prefix_and_suffix};

fn fixed_ecb_encryptor(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut rng = rand::from_seed();
    let key = Rng::gen::<[u8; BLOCK_SIZE]>(&mut rng);
    let input = pkcs::pad(random_prefix_and_suffix(input), BLOCK_SIZE as u8);
        ecb::encrypt(key.as_ref(), input)
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::Engine;

    #[test]
    fn detect_ecb() {
        let input = r#"
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK"#;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(textwrap::dedent(input).trim())
            .unwrap();
        let encrypted = fixed_ecb_encryptor(bytes);
    }
}
