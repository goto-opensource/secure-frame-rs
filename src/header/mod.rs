// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

mod basic_header;
mod extended_header;
mod frame_count;
mod keyid;
mod util;

pub use frame_count::FrameCount;
pub(crate) use frame_count::FrameCountGenerator;
pub use keyid::KeyId;

use self::keyid::{BasicKeyId, ExtendedKeyId};

use super::error::{Result, SframeError};

/// Allows to deserialze and validate a sframe header from a byte buffer.
pub trait Deserialization {
    /// The derialized type
    type DeserializedOutput;
    /// Tries to deserialize [`DeserializedOutput`], returns an error if this is not successful
    fn deserialize(data: &[u8]) -> Result<Self::DeserializedOutput>;
    /// Returns `true` if [`DeserializedOutput`] can be derialized from the given buffer
    fn is_valid(data: &[u8]) -> bool;
}

/// Allows to serialze a type from a byte buffer. This is used for our sframe header implementations.
pub trait Serialization {
    /// serializes a sframe header into the given buffer.
    fn serialize(&self, buffer: &mut [u8]) -> Result<()>;
}

/// Represents the accessible fields in a sframe header
pub trait HeaderFields {
    /// associated key ID type (basic/extended)
    type KeyIdType;
    /// the frame count field (CTR)
    fn frame_count(&self) -> FrameCount;
    /// the key id field (KID)
    fn key_id(&self) -> Self::KeyIdType;
    /// size in bytes of the header
    fn size(&self) -> usize;
}

/// Sframe header with a KID with a length of up to 3bits
/// modeled after [sframe draft 00 4.2](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-00#name-sframe-header)
/// ```txt
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+---------------------------------+
/// |R|LEN  |0| KID |    CTR... (length=LEN)          |
/// +-+-+-+-+-+-+-+-+---------------------------------+
/// ```
#[derive(Copy, Clone, Debug)]
pub struct BasicHeader {
    key_id: BasicKeyId,
    frame_count: FrameCount,
}

impl BasicHeader {
    /// Maximum length of the KID field in bits
    pub const MAX_KEY_ID_LEN_BIT: u32 = 3;
    /// Maximum value of the KID
    pub const MAX_KEY_ID: u64 = (1 << Self::MAX_KEY_ID_LEN_BIT) - 1;
    const STATIC_HEADER_LENGHT_BYTE: usize = 1;

    /// Create a new [`BasicHeader`] from key id and frame count
    pub fn new(key_id: BasicKeyId, frame_count: FrameCount) -> BasicHeader {
        BasicHeader {
            key_id,
            frame_count,
        }
    }
}
/// Extended sframe header with a KID with a length of up to 8 bytes
/// modeled after [sframe draft 00 4.2](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-00#name-sframe-header)
/// ```txt
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+---------------------------+---------------------------+
/// |R|LEN  |1|KLEN |   KID... (length=KLEN)    |    CTR... (length=LEN)    |
/// +-+-----+-+-----+---------------------------+---------------------------+
#[derive(Copy, Clone, Debug)]
pub struct ExtendedHeader {
    key_id: ExtendedKeyId,
    frame_count: FrameCount,
}

impl ExtendedHeader {
    /// Maximum length of the KID field in bits
    pub const MAX_KEY_ID_LEN_BIT: u32 = u64::BITS;
    /// Maximum value of the KID
    pub const MAX_KEY_ID: u64 = u64::MAX;
    const STATIC_HEADER_LENGHT_BYTE: usize = 1;

    /// Create a new [`ExtendedHeader`] from key id and frame count
    pub fn new(key_id: ExtendedKeyId, frame_count: FrameCount) -> ExtendedHeader {
        ExtendedHeader {
            key_id,
            frame_count,
        }
    }
}

#[derive(Copy, Clone, Debug)]
/// Represents an Sframe header modeled after [sframe draft 00 4.2](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-00#name-sframe-header)
/// containing the key id of the sender (KID) and the current frame count (CTR).
/// There are two variants, either with a KID represented by 3 bits (Basic) and an extended version with a KID of up to 8 bytes (Extended).
/// The CTR field has a variable length of up to 8 bytes where the size is represented with LEN. Here LEN=0 represents a length of 1.
/// Same holds for the extended HEADER with the fields KID and KLEN.
pub enum Header {
    /// see [`BasicHeader`]
    Basic(BasicHeader),
    /// see [`ExtendedHeader`]
    Extended(ExtendedHeader),
}

impl Header {
    /// Creates a new [`Header`] from a given key ID with frame count 0
    pub fn new<K: Into<KeyId>>(key_id: K) -> Header {
        Self::with_frame_count(key_id.into(), FrameCount::default())
    }

    /// Creates a new [`Header`] from a given key ID and frame count
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

    /// Returns true if the header is [`Header::Extended`]
    pub fn is_extended(&self) -> bool {
        matches!(self, Header::Extended(_))
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

const LEN_OFFSET: u8 = 1;
#[cfg(test)]
mod test {

    use super::{frame_count::FrameCount, keyid::KeyId, Header};
    use crate::header::{Deserialization, HeaderFields};
    use crate::util::test::assert_bytes_eq;

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
    fn serialize_test_vectors() {
        crate::test_vectors::get_test_vector(crate::CipherSuiteVariant::AesGcm128Sha256 as u8)
            .encryptions
            .iter()
            .for_each(|test_vector| {
                let header = Header::with_frame_count(
                    KeyId::from(test_vector.key_id),
                    FrameCount::from(test_vector.frame_count),
                );
                assert_bytes_eq(Vec::from(&header).as_slice(), &test_vector.header);
            });
    }

    #[test]
    fn deserialize_test_vectors() {
        crate::test_vectors::get_test_vector(crate::CipherSuiteVariant::AesGcm256Sha512 as u8)
            .encryptions
            .iter()
            .for_each(|test_vector| {
                let header = Header::deserialize(&test_vector.header).unwrap();
                assert_eq!(header.key_id(), KeyId::from(test_vector.key_id));
                assert_eq!(header.frame_count(), test_vector.frame_count);
            });
    }
}
