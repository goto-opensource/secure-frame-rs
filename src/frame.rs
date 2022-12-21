use std::borrow::BorrowMut;

use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        cipher_suite::CipherSuite,
        key_expansion::{KeyMaterial, Secret},
    },
    error::{Result, SframeError},
    header::{Deserialization, FrameCountGenerator, Header, HeaderFields, KeyId, Serialization},
    CipherSuiteVariant,
};

// TODO logging
pub struct Key {
    key_id: KeyId,
    cipher_suite: CipherSuite,
    secret: Secret,
    frame_counter: FrameCountGenerator,
}

impl Key {
    pub fn expand<Buffer>(
        key_id: u64,
        variant: CipherSuiteVariant,
        key_material: &Buffer,
    ) -> Result<Self>
    where
        Buffer: AsRef<[u8]>,
    {
        let cipher_suite = variant.into();
        let secret = KeyMaterial(key_material.as_ref()).expand_as_secret(&cipher_suite)?;
        Ok(Self {
            cipher_suite,
            secret,
            key_id: key_id.into(),
            frame_counter: Default::default(),
        })
    }
}
pub trait Buffer {
    type BufferSlice: AsMut<[u8]> + AsRef<[u8]>;
    fn allocate<'buf>(&'buf mut self, size: usize) -> Result<&'buf mut Self::BufferSlice>;
}

#[derive(Debug, Default)]
struct VectorBuffer {
    buffer: Vec<u8>,
}

impl Buffer for VectorBuffer {
    type BufferSlice = Vec<u8>;
    fn allocate<'buf>(&'buf mut self, size: usize) -> Result<&'buf mut Self::BufferSlice> {
        log::trace!("Allocating buffer of size {}", size);
        self.buffer.resize(size, 0);
        Ok(&mut self.buffer)
    }
}
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
    skip: usize,
    buffer: &'ibuf [u8],
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
            header: frame_view.header,
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
    header: Header,
    buffer: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptedFrameView<'buf> {
    header: Header,
    skip: usize,
    buffer: &'buf [u8],
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

#[cfg(test)]
mod test {
    use crate::{
        util::test::assert_bytes_eq, Encrypted, Key, Unencrypted, UnencryptedFrame,
        UnencryptedFrameView,
    };

    use super::VectorBuffer;

    #[test]
    fn playground() {
        let mut key = Key::expand(1, crate::CipherSuiteVariant::AesGcm256Sha512, b"1235").unwrap();

        let ibuf = b"abcdefg";
        let u = UnencryptedFrameView::from(ibuf);
        let u2 = UnencryptedFrame::with_skip(&vec![1, 2, 3, 4, 5], 2);

        let mut obuf = VectorBuffer::default();
        let e = u.encrypt(&mut key, &mut obuf).unwrap();

        let mut obuf2 = VectorBuffer::default();
        let r = e.decrypt(&key, &mut obuf2).unwrap();

        assert_bytes_eq(ibuf, r.as_ref());
    }
}
