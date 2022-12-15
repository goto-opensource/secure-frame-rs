// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

mod basic_header;
mod extended_header;
mod frame_count;
mod keyid;

pub use frame_count::{FrameCount, FrameCountGenerator};
pub mod frame_validation;
pub use keyid::KeyId;

use self::keyid::{BasicKeyId, ExtendedKeyId};

use super::error::{Result, SframeError};

pub trait Deserialization {
    type DeserializedOutput;
    fn deserialize(data: &[u8]) -> Result<Self::DeserializedOutput>;
    fn is_valid(data: &[u8]) -> bool;
}

pub trait Serialization {
    fn serialize(&self, buffer: &mut [u8]) -> Result<()>;
}

pub trait HeaderFields {
    type KeyIdType;
    fn frame_count(&self) -> FrameCount;
    fn key_id(&self) -> Self::KeyIdType;
    fn size(&self) -> usize;
}

#[derive(Copy, Clone, Debug)]
pub struct BasicHeader {
    key_id: BasicKeyId,
    frame_count: FrameCount,
}

impl BasicHeader {
    pub const MAX_KEY_ID_LEN_BIT: u32 = 3;
    pub const MAX_KEY_ID: u64 = (1 << Self::MAX_KEY_ID_LEN_BIT) - 1;
    const STATIC_HEADER_LENGHT_BYTE: usize = 1;

    pub fn new(key_id: BasicKeyId, frame_count: FrameCount) -> BasicHeader {
        BasicHeader {
            key_id,
            frame_count,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ExtendedHeader {
    key_id: ExtendedKeyId,
    frame_count: FrameCount,
}

impl ExtendedHeader {
    pub const MAX_KEY_ID_LEN_BIT: u32 = u64::BITS;
    pub const MAX_KEY_ID: u64 = u64::MAX;
    const STATIC_HEADER_LENGHT_BYTE: usize = 1;

    pub fn new(key_id: ExtendedKeyId, frame_count: FrameCount) -> ExtendedHeader {
        ExtendedHeader {
            key_id,
            frame_count,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Header {
    Basic(BasicHeader),
    Extended(ExtendedHeader),
}

impl Header {
    pub fn new<K: Into<KeyId>>(key_id: K) -> Header {
        Self::with_frame_count(key_id.into(), FrameCount::default())
    }

    pub fn with_frame_count<K: Into<KeyId>, F: Into<FrameCount>>(
        key_id: K,
        frame_count: F,
    ) -> Header {
        let key_id = key_id.into();
        let frame_count = frame_count.into();
        match key_id {
            KeyId::Basic(key_id) => Header::Basic(BasicHeader::new(key_id, frame_count)),
            KeyId::Extended(key_id) => Header::Extended(ExtendedHeader::new(key_id, frame_count)),
        }
    }

    pub fn is_extended(&self) -> bool {
        matches!(self, Header::Extended(_))
    }

    pub fn as_basic(&self) -> Option<&BasicHeader> {
        if let Header::Basic(basic) = self {
            Some(basic)
        } else {
            None
        }
    }

    pub fn as_extended(&self) -> Option<&ExtendedHeader> {
        if let Header::Extended(extended) = self {
            Some(extended)
        } else {
            None
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Header::with_frame_count(KeyId::default(), FrameCount::default())
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = SframeError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Header::deserialize(value)
    }
}

impl Deserialization for Header {
    type DeserializedOutput = Self;

    fn deserialize(data: &[u8]) -> Result<Self::DeserializedOutput> {
        if BasicHeader::is_valid(data) {
            BasicHeader::deserialize(data).map(Header::Basic)
        } else {
            ExtendedHeader::deserialize(data).map(Header::Extended)
        }
    }

    fn is_valid(data: &[u8]) -> bool {
        BasicHeader::is_valid(data) || ExtendedHeader::is_valid(data)
    }
}

impl Serialization for Header {
    fn serialize(&self, buffer: &mut [u8]) -> Result<()> {
        match self {
            Header::Basic(basic) => basic.serialize(buffer),
            Header::Extended(extended) => extended.serialize(buffer),
        }
    }
}

impl HeaderFields for Header {
    type KeyIdType = KeyId;

    fn frame_count(&self) -> FrameCount {
        match self {
            Header::Basic(basic) => basic.frame_count(),
            Header::Extended(extended) => extended.frame_count(),
        }
    }

    fn key_id(&self) -> Self::KeyIdType {
        match self {
            Header::Basic(basic) => KeyId::Basic(basic.key_id()),
            Header::Extended(extended) => KeyId::Extended(extended.key_id()),
        }
    }

    fn size(&self) -> usize {
        match self {
            Header::Basic(basic) => basic.size(),
            Header::Extended(extended) => extended.size(),
        }
    }
}

impl From<&Header> for Vec<u8> {
    fn from(header: &Header) -> Self {
        let mut buffer = vec![0u8; header.size()];
        header.serialize(buffer.as_mut_slice()).unwrap();
        buffer
    }
}

// TODO remove the verify-test-vectors feature as soon the test vectors are fixed in the draft
// Due to a spec change the lenghth offset changed (0 now means lenght of 1)
#[cfg(not(feature = "verify-test-vectors"))]
const LEN_OFFSET: u8 = 1;
#[cfg(feature = "verify-test-vectors")]
const LEN_OFFSET: u8 = 0;
#[cfg(test)]
mod test {

    use super::{frame_count::FrameCount, keyid::KeyId, Header};
    use crate::header::{Deserialization, HeaderFields};
    #[cfg(feature = "verify-test-vectors")]
    use crate::{test_vectors::*, util::test::assert_bytes_eq};

    use pretty_assertions::assert_eq;

    #[test]
    fn create_basic_header_from_basic_key_id_with_correct_fields() {
        let key_id = KeyId::Basic(0);
        let frame_count = FrameCount::from(0);
        let header = Header::with_frame_count(key_id, frame_count);
        assert!(matches!(header, Header::Basic(_)));

        assert_eq!(key_id, header.key_id());
        assert_eq!(frame_count, header.frame_count());
        assert_eq!(2, header.size());
    }

    #[test]
    fn create_extended_header_from_extended_key_id_with_correct_fields() {
        let key_id = KeyId::Extended(666);
        let frame_count = FrameCount::from(0);
        let header = Header::with_frame_count(key_id, frame_count);
        assert!(matches!(header, Header::Extended(_)));

        assert_eq!(key_id, header.key_id());
        assert_eq!(frame_count, header.frame_count());
    }

    #[test]
    fn deserialize_basic_header() {
        let data = [0b00010110, 0b00000010, 0b10011010];
        let header = Header::deserialize(&data).unwrap();
        assert!(matches!(header, Header::Basic(_)));
    }

    #[test]
    #[cfg(feature = "verify-test-vectors")]
    fn serialize_test_vectors() {
        aes_gcm_256_sha512::get_test_vectors()
            .into_iter()
            .for_each(|test_vector| {
                let header = Header::with_frame_count(
                    KeyId::from(test_vector.key_id),
                    FrameCount::from(test_vector.frame_count),
                );
                assert_bytes_eq(Vec::from(&header).as_slice(), &test_vector.header);
            });
    }

    #[test]
    #[cfg(feature = "verify-test-vectors")]
    fn deserialize_test_vectors() {
        aes_gcm_256_sha512::get_test_vectors()
            .into_iter()
            .for_each(|test_vector| {
                let header = Header::deserialize(&test_vector.header).unwrap();
                assert_eq!(header.key_id(), KeyId::from(test_vector.key_id));
                assert_eq!(header.frame_count(), test_vector.frame_count);
            });
    }
}
