use crate::{
    crypto::aead::AeadDecrypt,
    error::Result,
    header::{Deserialization, Header, HeaderFields},
};

use super::{buffer::Buffer, key::Key, unencrypted::UnencryptedFrameView};

pub trait Encrypted: AsRef<[u8]> {
    fn header(&self) -> Header;
    fn decrypt<'buf>(
        &self,
        key: &Key,
        buffer: &'buf mut impl Buffer,
    ) -> Result<UnencryptedFrameView<'buf>>;
    fn decrypt_alloc(&self, key: &Key) -> Result<UnencryptedFrameView>;
}

// TODO implement Encrypted TryFrom, try_from_skip
#[derive(Clone, Debug)]
pub struct EncryptedFrame {
    pub(super) header: Header,
    pub(super) buffer: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptedFrameView<'buf> {
    pub(super) header: Header,
    pub(super) skip: usize,
    pub(super) buffer: &'buf [u8],
}

impl AsRef<[u8]> for EncryptedFrameView<'_> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

// TODO maybe add utilites>  find_key(keys: Map<Keys>), validate
impl Encrypted for EncryptedFrameView<'_> {
    fn header(&self) -> Header {
        self.header
    }

    fn decrypt<'buf>(
        &self,
        key: &Key,
        buffer: &'buf mut impl Buffer,
    ) -> Result<UnencryptedFrameView<'buf>> {
        let frame_len = self.buffer.len() - self.skip - self.header.size();
        let mut io_buf = buffer.allocate(frame_len)?.as_mut();

        // Copy skipped payload
        io_buf[..self.skip].copy_from_slice(&self.buffer[..self.skip]);

        // Copy encrypted payload (with tag)
        let payload_begin_idx = self.skip + self.header.size();
        io_buf[self.skip..frame_len - self.skip].copy_from_slice(&self.buffer[payload_begin_idx..]);

        key.cipher_suite.decrypt(
            &mut io_buf[self.skip..],
            &key.secret,
            &self.buffer[self.skip..payload_begin_idx],
            self.header.frame_count(),
        )?;

        // Remove tag
        io_buf = &mut io_buf[..frame_len - key.cipher_suite.auth_tag_len];
        Ok(UnencryptedFrameView {
            skip: self.skip,
            buffer: io_buf,
        })
    }

    fn decrypt_alloc(&self, key: &Key) -> Result<UnencryptedFrameView> {
        todo!()
    }
}

impl<'ibuf> EncryptedFrameView<'ibuf> {
    pub fn try_from_skip<InBuffer>(in_buffer: &'ibuf InBuffer, skip: usize) -> Result<Self>
    where
        InBuffer: AsRef<[u8]>,
    {
        let header = Header::deserialize(in_buffer.as_ref())?;
        Ok(Self {
            skip,
            header,
            buffer: in_buffer.as_ref(),
        })
    }

    pub fn try_from<InBuffer>(in_buffer: &'ibuf InBuffer) -> Result<Self>
    where
        InBuffer: AsRef<[u8]>,
    {
        Self::try_from_skip(in_buffer, 0)
    }
}
// TODO this is not working do to
//  downstream crates may implement trait `std::convert::From<&_>` for type `frame::EncryptedFrameView<'_>`
// impl<'ibuf, InBuffer> TryFrom<&'ibuf InBuffer> for EncryptedFrameView<'ibuf>
// where
//     InBuffer: AsRef<[u8]>,
// {
//     type Error = SframeError;

//     fn try_from(in_buffer: &'ibuf InBuffer) -> Result<Self> {
//         Self::try_from_skip(in_buffer, 0)
//     }
// }
