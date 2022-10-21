use std::collections::HashMap;

use crate::{
    crypto::{
        aead::AeadDecrypt,
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_expansion::{KeyMaterial, Secret},
    },
    error::{Result, SframeError},
    header::{Deserialization, Header, HeaderFields, KeyId},
};

pub struct Receiver {
    secrets: HashMap<KeyId, Secret>,
    cipher_suite: CipherSuite,
}

impl Default for Receiver {
    fn default() -> Self {
        let cipher_suite: CipherSuite = CipherSuiteVariant::AesGcm256Sha512.into();
        Receiver {
            secrets: Default::default(),
            cipher_suite,
        }
    }
}

impl Receiver {
    pub fn new() -> Self {
        // TODO: make CipherSuite configurable
        Self::default()
    }

    pub fn decrypt(&self, encrypted_frame: &[u8], skip: usize) -> Result<Vec<u8>> {
        let header = Header::deserialize(&encrypted_frame[skip..])?;

        let key_id = header.get_key_id();

        if let Some(secret) = self.secrets.get(&key_id) {
            log::trace!(
                "Receiver: Frame counter: {:?}, Key id: {:?}",
                header.get_frame_counter(),
                header.get_key_id()
            );

            let payload_begin_idx = skip + header.size();
            let mut io_buffer: Vec<u8> = encrypted_frame[..skip]
                .iter()
                .chain(encrypted_frame[payload_begin_idx..].iter())
                .copied()
                .collect();

            self.cipher_suite.decrypt(
                &mut io_buffer[skip..],
                secret,
                &encrypted_frame[skip..payload_begin_idx],
                &header.get_frame_counter(),
            )?;

            io_buffer.truncate(io_buffer.len() - self.cipher_suite.auth_tag_len);
            Ok(io_buffer)
        } else {
            Err(SframeError::MissingDecryptionKey(key_id))
        }
    }

    // TODO: use KeyId instead of u64
    pub fn set_encryption_key(&mut self, receiver_id: u64, key_material: &[u8]) -> Result<()> {
        self.secrets.insert(
            KeyId::from(receiver_id),
            KeyMaterial(key_material).expand_as_secret(&self.cipher_suite)?,
        );
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fail_on_missing_secret() {
        let receiver = Receiver::new();
        // do not set the encryption-key
        let decrypted = receiver.decrypt(b"foobar is unsafe", 0);

        assert_eq!(
            decrypted,
            Err(SframeError::MissingDecryptionKey(KeyId::from(6u8)))
        );
    }
}
