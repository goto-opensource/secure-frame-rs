use crate::{
    crypto::aead::AeadEncrypt,
    error::Result,
    header::{Header, HeaderFields, Serialization},
};

use super::{
    buffer::{Buffer, VectorBuffer},
    encrypted::{Encrypted, EncryptedFrame, EncryptedFrameView},
    key::Key,
};

pub trait Unencrypted: AsRef<[u8]> {
    fn encrypt<'obuf>(
        &self,
        key: &mut Key,
        out_buffer: &'obuf mut impl Buffer,
    ) -> Result<EncryptedFrameView<'obuf>>;
    fn encrypt_alloc(&self, key: &mut Key) -> Result<EncryptedFrame>;
}

// TODO trait for member access so we can reuse the impl
pub struct UnencryptedFrameView<'ibuf> {
    pub(super) skip: usize,
    pub(super) buffer: &'ibuf [u8],
}

impl<'ibuf, InBuffer> From<&'ibuf InBuffer> for UnencryptedFrameView<'ibuf>
where
    InBuffer: AsRef<[u8]>,
{
    fn from(in_buffer: &'ibuf InBuffer) -> Self {
        Self {
            skip: 0,
            buffer: in_buffer.as_ref(),
        }
    }
}

impl<'ibuf> UnencryptedFrameView<'ibuf> {
    pub fn from_skip<InBuffer>(in_buffer: &'ibuf InBuffer, skip: usize) -> Self
    where
        InBuffer: AsRef<[u8]>,
    {
        Self {
            skip,
            buffer: in_buffer.as_ref(),
        }
    }
}

impl AsRef<[u8]> for UnencryptedFrameView<'_> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

impl<'ibuf> Unencrypted for UnencryptedFrameView<'ibuf> {
    fn encrypt<'obuf>(
        &self,
        key: &mut Key,
        out_buffer: &'obuf mut impl Buffer,
    ) -> Result<EncryptedFrameView<'obuf>> {
        let skip = self.skip;

        let frame_count = key.frame_counter.increment();
        let header = Header::with_frame_count(key.key_id, frame_count);

        // TODO helper functions to clean this up here
        // allocate buffer large enough
        let in_len = self.buffer.len();
        let frame_size = in_len + header.size() + key.cipher_suite.auth_tag_len;
        let io_buf = out_buffer.allocate(frame_size)?.as_mut();

        // copy skipped payload
        io_buf[..skip].copy_from_slice(&self.buffer[..skip]);

        // copy header
        header.serialize(&mut io_buf[skip..])?;

        //copy to be encryed payload
        let l = self.buffer[skip..].len();
        io_buf[skip + header.size()..skip + header.size() + l]
            .copy_from_slice(&self.buffer[skip..]);

        // get encryption buffer
        let (leading_buffer, trailing_buffer) = io_buf.split_at_mut(skip + header.size());
        let (encrypt_buffer, auth_tag_buffer) =
            trailing_buffer.split_at_mut(trailing_buffer.len() - key.cipher_suite.auth_tag_len);

        let tag = key.cipher_suite.encrypt(
            encrypt_buffer,
            &key.secret,
            &leading_buffer[skip..],
            header.frame_count(),
        )?;

        auth_tag_buffer.copy_from_slice(tag.as_ref());

        Ok(EncryptedFrameView {
            header,
            skip: self.skip,
            buffer: io_buf,
        })
    }

    fn encrypt_alloc(&self, key: &mut Key) -> Result<EncryptedFrame> {
        let mut vec_buffer = VectorBuffer::default();
        let frame_view = self.encrypt(key, &mut vec_buffer)?;
        Ok(EncryptedFrame {
            header: frame_view.header(),
            buffer: vec_buffer.buffer,
        })
    }
}

pub struct UnencryptedFrame {
    skip: usize,
    in_buffer: Vec<u8>,
}

impl<'ibuf, InBuffer> From<&'ibuf InBuffer> for UnencryptedFrame
where
    InBuffer: AsRef<[u8]>,
{
    fn from(in_buffer: &'ibuf InBuffer) -> Self {
        Self {
            skip: 0,
            in_buffer: in_buffer.as_ref().to_vec(),
        }
    }
}

impl UnencryptedFrame {
    pub fn with_skip<InBuffer>(in_buffer: &InBuffer, skip: usize) -> Self
    where
        InBuffer: AsRef<[u8]>,
    {
        Self {
            skip,
            in_buffer: in_buffer.as_ref().to_vec(),
        }
    }
}

// TODO implement Unencrypted for UnencryptedFrame
