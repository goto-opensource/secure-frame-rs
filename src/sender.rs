use crate::{
    crypto::{
        aead::AeadEncrypt,
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_expansion::{KeyMaterial, Secret},
    },
    error::{Result, SframeError},
    header::{FrameCountGenerator, Header, HeaderFields, KeyId},
};

pub struct Sender {
    frame_counter: FrameCountGenerator,
    sender_id: KeyId,
    cipher_suite: CipherSuite,
    secret: Option<Secret>,
}

impl Sender {
    pub fn new(sender_id: u64) -> Sender {
        log::info!("Setting up Sframe Sender with ID {}", sender_id);
        // TODO make this configurable
        let cipher_suite: CipherSuite = CipherSuiteVariant::AesGcm256Sha512.into();
        Sender {
            frame_counter: Default::default(),
            sender_id: sender_id.into(),
            cipher_suite,
            secret: Option::None,
        }
    }

    pub fn encrypt(&mut self, unencrypted_payload: &[u8], skip: usize) -> Result<Vec<u8>> {
        log::trace!("Encrypt frame # {:#?}!", self.frame_counter);
        if let Some(ref secret) = self.secret {
            log::trace!("Skipping first {} bytes in frame", skip);

            let frame_count = self.frame_counter.increment();
            log::trace!("frame count: {:?}", frame_count);

            log::trace!("Creating SFrame Header");
            let header = Header::with_frame_counter(self.sender_id, frame_count);

            log::trace!(
                "Sender: FrameCount: {:?}, FrameCount length: {:?}, KeyId: {:?}, Extend: {:?}",
                header.get_frame_counter(),
                header.get_frame_counter().length_in_bytes(),
                header.get_key_id(),
                header.is_extended()
            );

            let skipped_payload = &unencrypted_payload[0..skip];
            let to_be_encrypted_payload = &unencrypted_payload[skip..];

            let frame_length =
                unencrypted_payload.len() + header.size() + self.cipher_suite.auth_tag_len;
            let mut frame = Vec::<u8>::with_capacity(frame_length);
            frame.extend_from_slice(skipped_payload);
            frame.extend(Vec::from(&header));
            frame.extend(to_be_encrypted_payload);

            let (leading_buffer, encrypt_buffer) = frame.split_at_mut(skip + header.size());

            log::trace!("Encrypting Frame of size {}", unencrypted_payload.len(),);
            let tag = self.cipher_suite.encrypt(
                encrypt_buffer,
                secret,
                &leading_buffer[skip..],
                &header.get_frame_counter(),
            )?;

            frame.extend(tag.as_ref());

            Ok(frame)
        } else {
            Err(SframeError::EncryptionFailure)
        }
    }

    pub fn set_encryption_key(&mut self, key_material: &[u8]) -> Result<()> {
        self.secret = Some(KeyMaterial(key_material).expand_as_secret(&self.cipher_suite)?);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn fail_on_missing_secret() {
        let mut sender = Sender::new(1);
        // do not set the encryption-key
        let encrypted = sender.encrypt(b"foobar is unsafe", 0);

        assert_eq!(encrypted, Err(SframeError::EncryptionFailure));
    }
}
