pub fn as_min_be_bytes(x: u64) -> impl DoubleEndedIterator<Item = u8> {
    let be_bytes = x.to_be_bytes();
    let length_in_bytes = min_len_in_bytes(x);
    be_bytes
        .into_iter()
        .skip(be_bytes.len() - length_in_bytes as usize)
}

pub fn min_len_in_bytes(value: u64) -> u8 {
    if value == 0 {
        return 1; // at least 1 byte is needed to represent 0000_0000
    }

    let leading_zeros = value
        .to_be_bytes()
        .iter()
        .take_while(|&&value| value == 0)
        .count() as u8; // never panics as u64 has only 8 bytes
    8 - leading_zeros
}

#[cfg(test)]
mod test {
    use super::min_len_in_bytes;

    #[test]
    fn nof_non_zero_bytes() {
        assert_eq!(1u8, min_len_in_bytes(0));
        assert_eq!(1u8, min_len_in_bytes(7));
        assert_eq!(2u8, min_len_in_bytes(256));
        assert_eq!(8u8, min_len_in_bytes(u64::MAX));
    }
}
