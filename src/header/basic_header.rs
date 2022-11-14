use bitfield::bitfield;

use crate::error::SframeError;

use super::{
    keyid::BasicKeyId, BasicHeader, Deserialization, FrameCount, HeaderFields, Serialization,
};

bitfield! {
    /// Modelt after [sframe draft 03 4.2](https://datatracker.ietf.org/doc/html/draft-omara-sframe-03#section-4.2)
    /// ```txt
    ///  0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+---------------------------------+
    /// |R|LEN  |0| KID |    CTR... (length=LEN)          |
    /// +-+-+-+-+-+-+-+-+---------------------------------+
    /// ```
    struct BasicHeaderBitfield(MSB0 [u8]);
    impl Debug;
    u8;
    get_reserved, _: 0;
    get_frame_counter_length, set_frame_counter_length: 3 , 1;
    get_extend_key_id_flag, set_extended_key_flag: 4;
    get_key_id, set_key_id: 7 , 5;
    get_frame_counter, set_frame_counter: 15, 8, 8;
}

impl HeaderFields for BasicHeader {
    type KeyIdType = BasicKeyId;
    fn get_frame_counter(&self) -> FrameCount {
        self.frame_counter
    }
    fn get_key_id(&self) -> BasicKeyId {
        self.key_id
    }

    fn size(&self) -> usize {
        BasicHeader::STATIC_HEADER_LENGHT_BYTE + self.frame_counter.length_in_bytes() as usize
    }
}

impl Serialization for BasicHeader {
    fn serialize(&self, buffer: &mut [u8]) -> crate::error::GenericResult<()> {
        if buffer.len() < self.size() {
            return Err(Box::new(SframeError::Other(format!(
                "Buffer is to small to serialize the header {}<{}",
                buffer.len(),
                self.size()
            ))));
        }
        let mut header_setter = BasicHeaderBitfield(buffer);
        header_setter.set_extended_key_flag(false);
        header_setter.set_key_id(self.key_id);

        let frame_counter_length = self.frame_counter.length_in_bytes();
        header_setter.set_frame_counter_length(frame_counter_length - 1); // frame counter length 1 is coded as 0

        let frame_counter_bytes = self.frame_counter.into_be_bytes();

        (0..frame_counter_length as usize).for_each(|idx| {
            header_setter.set_frame_counter(idx, frame_counter_bytes[idx]);
        });
        Ok(())
    }
}

impl Deserialization for BasicHeader {
    type DeserializedOutput = Self;

    fn deserialize(data: &[u8]) -> crate::error::Result<Self::DeserializedOutput> {
        let header_view = BasicHeaderBitfield(data);
        let key_id = header_view.get_key_id();
        let frame_counter_length: usize = (header_view.get_frame_counter_length() + 1).into(); // frame counter length 1 is coded as 0
        let mut numeric_value = [0u8; 8];
        let offset = numeric_value.len() - frame_counter_length;
        for index in 0..frame_counter_length {
            numeric_value[offset + index] = header_view.get_frame_counter(index);
        }

        Ok(BasicHeader::new(
            key_id,
            FrameCount::new(u64::from_be_bytes(numeric_value)),
        ))
    }

    fn is_valid(data: &[u8]) -> bool {
        const MIN_LENGTH_IN_BYTES: usize = 2;
        if data.len() < MIN_LENGTH_IN_BYTES {
            return false;
        }
        let header_view = BasicHeaderBitfield(data);

        !header_view.get_extend_key_id_flag()
            && data.len()
                >= BasicHeader::STATIC_HEADER_LENGHT_BYTE
                    + header_view.get_frame_counter_length() as usize
    }
}

#[cfg(test)]
mod test {
    use crate::{
        header::{BasicHeader, Deserialization, FrameCount, HeaderFields, Serialization},
        util::test::assert_bytes_eq,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn fail_to_serialize_when_buffer_is_too_small() {
        let header = BasicHeader::new(3, FrameCount::new(5));
        let mut buffer = vec![0u8; header.size() - 1];

        let result = header.serialize(&mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_to_buffer() {
        let header = BasicHeader::new(6, FrameCount::new(666));
        let mut buffer = vec![0u8; header.size()];

        assert!(header.serialize(&mut buffer).is_ok());

        let expected_serialized_buffer = [0b00010110, 0b00000010, 0b10011010];
        assert_bytes_eq(&expected_serialized_buffer, &buffer);
    }
    #[test]
    fn serialize_when_frame_counter_and_key_id_is_0() {
        let header = BasicHeader::new(0, FrameCount::new(0));
        let mut buffer = vec![0u8; header.size()];

        assert!(header.serialize(&mut buffer).is_ok());

        let expected_serialized_buffer = vec![0x0, 0x0];
        assert_eq!(expected_serialized_buffer, buffer);
    }

    #[test]
    fn be_invalid_if_buffer_to_small() {
        let data = [0x00];
        assert_eq!(BasicHeader::is_valid(&data), false);
    }

    #[test]
    fn be_invalid_if_extended_header_flag_is_set() {
        let data = [0b0000_1000, 0x00, 0x00];
        assert_eq!(BasicHeader::is_valid(&data), false);
    }

    #[test]
    fn be_invalid_if_buffer_smaller_than_expected_size() {
        let data = [0b0111_0000, 0x00, 0x00];
        assert_eq!(BasicHeader::is_valid(&data), false);
    }

    #[test]
    fn be_valid_for_correct_data() {
        let data = [0b00010110, 0b00000010, 0b10011010];
        assert_eq!(BasicHeader::is_valid(&data), true);
    }

    #[test]
    fn deserialize_from_valid_data() {
        let data = [0b00010110, 0b00000010, 0b10011010];
        let header = BasicHeader::deserialize(&data).unwrap();
        assert_eq!(header.get_key_id(), 6);
        assert_eq!(header.get_frame_counter().value(), 666);
    }
}
