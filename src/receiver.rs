// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use std::collections::HashMap;

use crate::{
    crypto::{
        aead::AeadDecrypt,
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_expansion::KeyMaterial,
        secret::Secret,
    },
    error::{Result, SframeError},
    frame_validation::{FrameValidation, ReplayAttackProtection},
    header::{Deserialization, Header, HeaderFields, KeyId},
};

pub struct ReceiverOptions {
    cipher_suite: CipherSuite,
    frame_validation: Box<dyn FrameValidation>,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuiteVariant::AesGcm256Sha512.into(),
            frame_validation: Box::new(ReplayAttackProtection::with_tolerance(128)),
        }
    }
}

#[derive(Default)]
pub struct Receiver {
    secrets: HashMap<KeyId, Secret>,
    options: ReceiverOptions,
    buffer: Vec<u8>,
}

impl Receiver {
    pub fn with_cipher_suite(variant: CipherSuiteVariant) -> Receiver {
        let cipher_suite: CipherSuite = variant.into();
        let replay_attack_tolerance = 128;
        log::debug!("Setting up sframe Receiver");
        log::trace!(
            "using ciphersuite {:?}, replay_attack_tolerance: {}",
            cipher_suite.variant,
            replay_attack_tolerance
        );
        Self {
            secrets: HashMap::default(),
            options: ReceiverOptions {
                cipher_suite,
                frame_validation: Box::new(ReplayAttackProtection::with_tolerance(
                    replay_attack_tolerance,
                )),
            },
            buffer: Default::default(),
        }
    }

    pub fn decrypt(&mut self, encrypted_frame: &[u8], skip: usize) -> Result<&[u8]> {
        let header = Header::deserialize(&encrypted_frame[skip..])?;

        self.options.frame_validation.validate(&header)?;
        let key_id = header.key_id();

        if let Some(secret) = self.secrets.get(&key_id) {
            log::trace!(
                "Receiver: Frame counter: {:?}, Key id: {:?}",
                header.frame_count(),
                header.key_id()
            );

            let payload_begin = skip + header.size();
            self.buffer.clear();
            self.buffer.extend(encrypted_frame[..skip].iter());
            self.buffer.extend(encrypted_frame[payload_begin..].iter());

            self.options.cipher_suite.decrypt(
                &mut self.buffer[skip..],
                secret,
                &encrypted_frame[skip..payload_begin],
                header.frame_count(),
            )?;

            let payload_end = self.buffer.len() - self.options.cipher_suite.auth_tag_len;
            Ok(&self.buffer[..payload_end])
        } else {
            Err(SframeError::MissingDecryptionKey(key_id))
        }
    }

    // TODO: use KeyId instead of u64
    pub fn set_encryption_key(&mut self, receiver_id: u64, key_material: &[u8]) -> Result<()> {
        self.secrets.insert(
            KeyId::from(receiver_id),
            KeyMaterial(key_material).expand_as_secret(&self.options.cipher_suite)?,
        );
        Ok(())
    }

    pub fn remove_encryption_key(&mut self, receiver_id: u64) -> bool {
        self.secrets.remove(&KeyId::from(receiver_id)).is_some()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn remove_key() {
        let mut receiver = Receiver::default();
        assert!(!receiver.remove_encryption_key(1234));

        receiver
            .set_encryption_key(4223, b"hendrikswaytoshortpassword")
            .unwrap();
        receiver
            .set_encryption_key(4711, b"tobismuchbetterpassword;)")
            .unwrap();

        assert!(receiver.remove_encryption_key(4223));
        assert!(!receiver.remove_encryption_key(4223));

        assert!(receiver.remove_encryption_key(4711));
        assert!(!receiver.remove_encryption_key(4711));
    }

    #[test]
    fn fail_on_missing_secret() {
        let mut receiver = Receiver::default();
        // do not set the encryption-key
        let decrypted = receiver.decrypt(b"foobar is unsafe", 0);

        assert_eq!(
            decrypted,
            Err(SframeError::MissingDecryptionKey(KeyId::from(6u8)))
        );
    }
}
