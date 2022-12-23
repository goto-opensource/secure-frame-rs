// TODO logging
mod buffer;
mod encrypted;
mod key;
mod unencrypted;

#[cfg(test)]
mod test {
    use crate::{
        api::{
            buffer::VectorBuffer,
            key::Key,
            unencrypted::{Unencrypted, UnencryptedFrame, UnencryptedFrameView},
        },
        util::test::assert_bytes_eq,
    };

    use super::encrypted::Encrypted;

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
