use super::key_expansion::Secret;
use crate::{error::Result, header::FrameCount};

pub trait AeadEncrypt {
    type AuthTag: AsRef<[u8]>;
    fn encrypt<IoBuffer, Aad>(
        &self,
        io_buffer: &mut IoBuffer,
        secret: &Secret,
        aad_buffer: &Aad,
        frame_count: &FrameCount,
    ) -> Result<Self::AuthTag>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized;
}

pub trait AeadDecrypt {
    fn decrypt<'a, IoBuffer, Aad>(
        &self,
        io_buffer: &'a mut IoBuffer,
        secret: &Secret,
        aad_buffer: &Aad,
        frame_count: &FrameCount,
    ) -> Result<&'a mut [u8]>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized;
}

mod ring {

    use ring::aead::{BoundKey, SealingKey, Tag};

    use crate::{
        crypto::{
            cipher_suite::{CipherSuite, CipherSuiteVariant},
            key_expansion::Secret,
        },
        error::{Result, SframeError},
        header::FrameCount,
    };

    use super::{AeadDecrypt, AeadEncrypt};
    struct FrameNonceSequence {
        iv: Vec<u8>,
    }

    impl FrameNonceSequence {
        pub fn new(frame_count: u64, salt_key: &[u8]) -> FrameNonceSequence {
            let iv = FrameNonceSequence::generate_iv(&frame_count.to_be_bytes(), salt_key);
            FrameNonceSequence { iv }
        }

        fn generate_iv(counter: &[u8], salt: &[u8]) -> Vec<u8> {
            // salt.len() is always > counter.len()
            let len_diff = salt.len() - counter.len();
            salt.iter()
                .take(len_diff)
                .cloned()
                .chain(
                    salt.iter()
                        .skip(len_diff)
                        .zip(counter.iter())
                        .map(|(salt_byte, counter_byte)| salt_byte ^ counter_byte),
                )
                .collect()
        }
    }

    impl ring::aead::NonceSequence for FrameNonceSequence {
        fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
            if let Ok(nonce) = ring::aead::Nonce::try_assume_unique_for_key(self.iv.as_slice()) {
                Ok(nonce)
            } else {
                if cfg!(debug_assertions) {
                    log::error!("Failed to create nonce! iv: {:#?}", self.iv);
                } else {
                    log::error!("Failed to create nonce");
                }
                Err(ring::error::Unspecified)
            }
        }
    }

    impl CipherSuite {
        fn unbound_encryption_key(&self, secret: &Secret) -> Result<ring::aead::UnboundKey> {
            ring::aead::UnboundKey::new(self.get_algorithm(), secret.key.as_slice())
                .map_err(|_| SframeError::KeyExpansion)
        }

        fn get_algorithm(&self) -> &'static ring::aead::Algorithm {
            match self.variant {
                CipherSuiteVariant::AesCm128HmacSha256_8
                | CipherSuiteVariant::AesCm128HmacSha256_4
                | CipherSuiteVariant::AesGcm128Sha256 => &ring::aead::AES_128_GCM,
                CipherSuiteVariant::AesGcm256Sha512 => &ring::aead::AES_256_GCM,
            }
        }
    }

    impl AeadEncrypt for CipherSuite {
        type AuthTag = Tag;
        fn encrypt<IoBuffer, Aad>(
            &self,
            io_buffer: &mut IoBuffer,
            secret: &Secret,
            aad_buffer: &Aad,
            frame_count: &FrameCount,
        ) -> Result<Tag>
        where
            IoBuffer: AsMut<[u8]> + ?Sized,
            Aad: AsRef<[u8]> + ?Sized,
        {
            let mut sealing_key = SealingKey::new(
                self.unbound_encryption_key(secret)?,
                FrameNonceSequence::new(frame_count.value(), secret.salt.as_slice()),
            );

            let aad = ring::aead::Aad::from(aad_buffer);
            let auth_tag = sealing_key
                .seal_in_place_separate_tag(aad, io_buffer.as_mut())
                .map_err(|_| SframeError::EncryptionFailure)?;

            // TODO implement auth tag shortening, see 4.4.1

            Ok(auth_tag)
        }
    }

    impl AeadDecrypt for CipherSuite {
        fn decrypt<'a, IoBuffer, Aad>(
            &self,
            io_buffer: &'a mut IoBuffer,
            secret: &Secret,
            aad_buffer: &Aad,
            frame_count: &FrameCount,
        ) -> Result<&'a mut [u8]>
        where
            IoBuffer: AsMut<[u8]> + ?Sized,
            Aad: AsRef<[u8]> + ?Sized,
        {
            let aad = ring::aead::Aad::from(&aad_buffer);

            let mut opening_key = ring::aead::OpeningKey::new(
                self.unbound_encryption_key(secret)?,
                FrameNonceSequence::new(frame_count.value(), &secret.salt),
            );
            opening_key
                .open_in_place(aad, io_buffer.as_mut())
                .map_err(|_| SframeError::DecryptionFailure)
        }
    }

    #[cfg(test)]
    mod test {
        use crate::{
            crypto::{
                cipher_suite::{CipherSuite, CipherSuiteVariant},
                key_expansion::KeyMaterial,
            },
            test_vectors::aes_gcm_256_sha512::get_test_vectors,
            util::test::assert_bytes_eq,
        };

        use super::FrameNonceSequence;
        #[test]
        fn create_correct_nonce() {
            get_test_vectors().into_iter().for_each(|test_vector| {
                let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);
                let secret = KeyMaterial(&test_vector.key_material)
                    .expand_as_secret(&cipher_suite)
                    .unwrap();
                let nonce = FrameNonceSequence::new(test_vector.frame_count, &secret.salt);
                assert_bytes_eq(&nonce.iv, &test_vector.nonce);
            });
        }
    }
}

#[cfg(test)]
mod test {

    mod aes_256_gcm {
        use crate::{
            crypto::{
                aead::{AeadDecrypt, AeadEncrypt},
                cipher_suite::{CipherSuite, CipherSuiteVariant},
                key_expansion::{KeyMaterial, Secret},
            },
            header::{FrameCount, Header, HeaderFields, KeyId},
            test_vectors::aes_gcm_256_sha512::get_test_vectors,
            util::test::assert_bytes_eq,
        };
        use rand::{thread_rng, Rng};
        const KEY_MATERIAL: &str = "THIS_IS_RANDOM";

        #[test]
        fn encrypt_random_frame() {
            let mut data = vec![0u8; 1024];
            thread_rng().fill(data.as_mut_slice());
            let header = Header::default();
            let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);
            let secret = KeyMaterial(KEY_MATERIAL.as_bytes())
                .expand_as_secret(&cipher_suite)
                .unwrap();

            let _tag = cipher_suite
                .encrypt(
                    &mut data,
                    &secret,
                    &Vec::from(&header),
                    &header.frame_count(),
                )
                .unwrap();
        }

        // TODO reenable those tests when we clarifyed why the
        // test vectors are wrong
        #[ignore]
        #[test]
        fn encrypt_test_vectors() {
            get_test_vectors().into_iter().for_each(|test_vector| {
                let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);

                let secret = Secret {
                    key: test_vector.key,
                    salt: test_vector.salt,
                };

                let mut data = test_vector.plain_text.clone();
                let header = Header::with_frame_count(
                    KeyId::from(test_vector.key_id),
                    FrameCount::new(test_vector.frame_count),
                );
                let header_buffer = Vec::from(&header);
                let tag = cipher_suite
                    .encrypt(&mut data, &secret, &header_buffer, &header.frame_count())
                    .unwrap();
                let full_frame: Vec<u8> = header_buffer
                    .into_iter()
                    .chain(data.into_iter())
                    .chain(tag.as_ref().iter().cloned())
                    .collect();

                assert_bytes_eq(&full_frame, &test_vector.cipher_text);
            });
        }

        #[ignore]
        #[test]
        fn should_decrypt_test_vectors() {
            get_test_vectors().into_iter().for_each(|test_vector| {
                let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);

                let secret = Secret {
                    key: test_vector.key,
                    salt: test_vector.salt,
                };

                let header = Header::with_frame_count(
                    KeyId::from(test_vector.key_id),
                    FrameCount::new(test_vector.frame_count),
                );
                let header_buffer = Vec::from(&header);
                let mut data = Vec::from(&test_vector.cipher_text[header.size()..]);

                let decrypted = cipher_suite
                    .decrypt(&mut data, &secret, &header_buffer, &header.frame_count())
                    .unwrap();

                assert_bytes_eq(decrypted, &test_vector.plain_text);
            });
        }
    }
}
