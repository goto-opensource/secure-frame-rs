#![allow(clippy::unusual_byte_groupings)]
use bitfield::bitfield;

use crate::error::{Result, SframeError};

use super::{
    frame_counter::{get_nof_non_zero_bytes, into_be_bytes},
    keyid::ExtendedKeyId,
    Deserialization, ExtendedHeader, FrameCount, HeaderFields, Serialization,
};

bitfield! {
    /// Modelt after [sframe draft 03 4.2](https://datatracker.ietf.org/doc/html/draft-omara-sframe-03#section-4.2)
    /// ```txt
    ///  0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+---------------------------+---------------------------+
    /// |R|LEN  |1|KLEN |   KID... (length=KLEN)    |    CTR... (length=LEN)    |
    /// +-+-+-+-+-+-+-+-+---------------------------+---------------------------+
    /// ```
    pub struct ExtendedHeaderBitField(MSB0 [u8]);
    impl Debug;
    u8;
    reserved, _: 0;
    u8, frame_counter_len, set_frame_counter_len: 3 , 1;
    bool, extend_key_id_flag, set_extended_key_flag: 4;
    u8, key_id_len, set_key_len: 7 , 5;
    key_id_and_ctr, set_key_id_and_ctr: 15, 8, 16;
}

impl HeaderFields for ExtendedHeader {
    type KeyIdType = ExtendedKeyId;
    fn get_frame_counter(&self) -> FrameCount {
        self.frame_counter
    }
    fn get_key_id(&self) -> ExtendedKeyId {
        self.key_id
    }

    fn size(&self) -> usize {
        ExtendedHeader::STATIC_HEADER_LENGHT_BYTE
            + get_nof_non_zero_bytes(self.key_id).max(1) as usize
            + self.frame_counter.length_in_bytes() as usize
    }
}

impl Serialization for ExtendedHeader {
    fn serialize(&self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() < self.size() {
            return Err(SframeError::Other(format!(
                "Buffer is to small to serialize the header {}<{}",
                buffer.len(),
                self.size()
            )));
        }
        let mut header_setter = ExtendedHeaderBitField(buffer);
        header_setter.set_frame_counter_len(self.frame_counter.length_in_bytes() - 1);
        header_setter.set_extended_key_flag(true);
        header_setter.set_key_len(get_nof_non_zero_bytes(self.key_id).max(1) - 1);

        for (index, value) in into_be_bytes(self.key_id)
            .into_iter()
            .chain(into_be_bytes(self.frame_counter.value()).into_iter())
            .enumerate()
        {
            header_setter.set_key_id_and_ctr(index, value);
        }
        Ok(())
    }
}

impl Deserialization for ExtendedHeader {
    type DeserializedOutput = Self;

    fn deserialize(data: &[u8]) -> Result<Self::DeserializedOutput> {
        let view = ExtendedHeaderBitField(data);

        let key_len: usize = (view.key_id_len() + 1).into();
        let ctr_len: usize = (view.frame_counter_len() + 1).into();
        let remainder_len = key_len + ctr_len;

        let remainder = || {
            let mut index = 0_usize;
            let view = &view;
            std::iter::from_fn(move || {
                index += 1;
                Some(view.key_id_and_ctr(remainder_len - index))
            })
        };

        let mut ctr = [0u8; 8];
        for (i, v) in remainder().take(ctr_len).enumerate() {
            ctr[8 - (i + 1)] = v;
        }

        let mut kid = [0u8; 8];
        for (i, v) in remainder().skip(ctr_len).take(key_len).enumerate() {
            kid[8 - (i + 1)] = v;
        }

        Ok(ExtendedHeader {
            key_id: u64::from_be_bytes(kid),
            frame_counter: FrameCount::new(u64::from_be_bytes(ctr)),
        })
    }

    fn is_valid(data: &[u8]) -> bool {
        const MIN_LENGTH_IN_BYTES: usize = 3;
        if data.len() < MIN_LENGTH_IN_BYTES {
            return false;
        }
        let header_view = ExtendedHeaderBitField(data);

        header_view.extend_key_id_flag()
            && data.len()
                >= ExtendedHeader::STATIC_HEADER_LENGHT_BYTE
                    + header_view.frame_counter_len() as usize
                    + header_view.key_id_len() as usize
    }
}

#[cfg(test)]
mod test {
    use crate::{
        header::{Deserialization, ExtendedHeader, FrameCount, HeaderFields, Serialization},
        util::test::assert_bytes_eq,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn fail_to_serialize_when_buffer_is_too_small() {
        let header = ExtendedHeader::new(30, FrameCount::new(5));
        let mut buffer = vec![0u8; header.size() - 1];

        let result = header.serialize(&mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_to_buffer() {
        let header = ExtendedHeader::new(6, FrameCount::new(154));
        let mut buffer = vec![0u8; header.size()];

        assert!(header.serialize(&mut buffer).is_ok());

        let expected_serialized_buffer = [0b0_000_1_000, 0b00000110, 0b10011010];
        assert_bytes_eq(&expected_serialized_buffer, &buffer);
    }
    #[test]
    fn calculate_header_size() {
        assert_eq!(1 + 2, ExtendedHeader::new(0, Default::default()).size());
        assert_eq!(1 + 3, ExtendedHeader::new(260, Default::default()).size());
        assert_eq!(1 + 3, ExtendedHeader::new(5000, Default::default()).size());
        assert_eq!(
            1 + 4,
            ExtendedHeader::new(5000, FrameCount::new(260)).size()
        );
    }

    #[test]
    fn serialize_when_frame_counter_and_key_id_is_0() {
        let header = ExtendedHeader::new(0, FrameCount::new(0));
        let mut buffer = vec![0u8; header.size()];

        assert!(header.serialize(&mut buffer).is_ok());

        let expected_serialized_buffer = vec![0b0_000_1_000, 0x0, 0x0];
        assert_bytes_eq(&expected_serialized_buffer, &buffer);
    }

    #[test]
    fn serialize_when_frame_counter_and_key_id_length_is_8() {
        let header = ExtendedHeader::new(u64::MAX, FrameCount::new(u64::MAX));
        let mut buffer = vec![0u8; header.size()];

        assert!(header.serialize(&mut buffer).is_ok());

        let mut expected_serialized_buffer = vec![0b0_111_1_111];
        expected_serialized_buffer.extend_from_slice(&u64::MAX.to_be_bytes());
        expected_serialized_buffer.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_bytes_eq(&expected_serialized_buffer, &buffer);
    }

    #[test]
    fn be_invalid_if_buffer_to_small() {
        let data = [0x00];
        assert_eq!(ExtendedHeader::is_valid(&data), false);
    }

    #[test]
    fn be_invalid_if_reserved_is_set() {
        let data = [0b1_000_0_000, 0x00, 0x00];
        assert_eq!(ExtendedHeader::is_valid(&data), false);
    }

    #[test]
    fn be_invalid_if_extended_header_flag_is_not_set() {
        let data = [0b0_000_0_000, 0x00, 0x00];
        assert_eq!(ExtendedHeader::is_valid(&data), false);
    }

    #[test]
    fn be_invalid_if_buffer_smaller_than_expected_size() {
        let data = [0b0_111_1_000, 0x00, 0x00];
        assert_eq!(ExtendedHeader::is_valid(&data), false);
    }

    #[test]
    fn be_valid_for_correct_data() {
        let data = [0b0_000_1_000, 0b00000010, 0b10011010];
        assert_eq!(ExtendedHeader::is_valid(&data), true);
    }

    #[test]
    fn deserialize_from_valid_data() {
        let data = [0b0_000_1_000, 0b00000010, 0b10011010];
        let header = ExtendedHeader::deserialize(&data).unwrap();
        assert_eq!(header.get_key_id(), 2);
        assert_eq!(header.get_frame_counter().value(), 154);
    }
}
