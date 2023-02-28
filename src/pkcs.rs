//          Copyright Nick G 2023.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

pub fn pad(bytes: impl AsRef<[u8]>, pad_size: u8) -> Vec<u8> {
    let bytes = bytes.as_ref();
    let over_pad = bytes.len() % pad_size as usize;
    let pad_bytes = pad_size - over_pad as u8;

    let mut padded = bytes.to_vec();
    padded.extend(vec![pad_bytes; pad_bytes as usize]);
    padded
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn one_byte_pad() {
        assert_eq!(pad(b"123", 4), b"123\x01");
    }

    #[test]
    fn two_byte_pad_no_overflow() {
        assert_eq!(pad(b"55", 2), b"55\x02\x02");
    }

    #[test]
    fn yellow_submarine_20() {
        assert_eq!(pad(b"YELLOW SUBMARINE", 20), b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }
}
