// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use super::secret::Secret;
use crate::{error::Result, header::FrameCount};

pub trait AeadEncrypt {
    type AuthTag: AsRef<[u8]>;
    fn encrypt<IoBuffer, Aad>(
        &self,
        io_buffer: &mut IoBuffer,
        secret: &Secret,
        aad_buffer: &Aad,
        frame_count: FrameCount,
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
        frame_count: FrameCount,
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
            secret::Secret,
        },
        error::{Result, SframeError},
        header::FrameCount,
    };

    use super::{AeadDecrypt, AeadEncrypt};
    struct FrameNonceSequence {
        buffer: [u8; ring::aead::NONCE_LEN],
    }

    impl From<[u8; ring::aead::NONCE_LEN]> for FrameNonceSequence {
        fn from(buffer: [u8; ring::aead::NONCE_LEN]) -> Self {
            Self { buffer }
        }
    }

    impl ring::aead::NonceSequence for FrameNonceSequence {
        fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
            let nonce = ring::aead::Nonce::assume_unique_for_key(std::mem::take(&mut self.buffer));
            Ok(nonce)
        }
    }

    impl From<CipherSuiteVariant> for &'static ring::aead::Algorithm {
        fn from(variant: CipherSuiteVariant) -> Self {
            use CipherSuiteVariant::*;
            match variant {
                AesGcm128Sha256 => &ring::aead::AES_128_GCM,
                AesGcm256Sha512 => &ring::aead::AES_256_GCM,
            }
        }
    }

    impl CipherSuite {
        fn unbound_encryption_key(&self, secret: &Secret) -> Result<ring::aead::UnboundKey> {
            ring::aead::UnboundKey::new(self.variant.into(), secret.key.as_slice())
                .map_err(|_| SframeError::KeyExpansion)
        }
    }

    impl AeadEncrypt for CipherSuite {
        type AuthTag = Tag;
        fn encrypt<IoBuffer, Aad>(
            &self,
            io_buffer: &mut IoBuffer,
            secret: &Secret,
            aad_buffer: &Aad,
            frame_count: FrameCount,
        ) -> Result<Tag>
        where
            IoBuffer: AsMut<[u8]> + ?Sized,
            Aad: AsRef<[u8]> + ?Sized,
        {
            let mut sealing_key = SealingKey::<FrameNonceSequence>::new(
                self.unbound_encryption_key(secret)?,
                secret.create_nonce(&frame_count).into(),
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
            frame_count: FrameCount,
        ) -> Result<&'a mut [u8]>
        where
            IoBuffer: AsMut<[u8]> + ?Sized,
            Aad: AsRef<[u8]> + ?Sized,
        {
            let aad = ring::aead::Aad::from(&aad_buffer);

            let mut opening_key = ring::aead::OpeningKey::<FrameNonceSequence>::new(
                self.unbound_encryption_key(secret)?,
                secret.create_nonce(&frame_count).into(),
            );
            opening_key
                .open_in_place(aad, io_buffer.as_mut())
                .map_err(|_| SframeError::DecryptionFailure)
        }
    }
}

#[cfg(test)]
mod test {

    mod aes_gcm {
        use crate::{
            crypto::{
                aead::AeadEncrypt,
                cipher_suite::{CipherSuite, CipherSuiteVariant},
                key_expansion::KeyMaterial,
            },
            header::{Header, HeaderFields},
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
                    header.frame_count(),
                )
                .unwrap();
        }

        #[cfg(feature = "verify-test-vectors")]
        mod test_vectors {
            use crate::{
                crypto::{
                    aead::{AeadDecrypt, AeadEncrypt},
                    cipher_suite::{CipherSuite, CipherSuiteVariant},
                    secret::Secret,
                },
                header::{FrameCount, Header, HeaderFields, KeyId},
                test_vectors::{aes_gcm_128_sha256, *},
                util::test::assert_bytes_eq,
            };
            #[test]
            fn encrypt_test_vectors_aes_gcm_128_sha256() {
                aes_gcm_128_sha256::get_test_vectors()
                    .into_iter()
                    .for_each(|test_vector| {
                        let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm128Sha256);

                        let secret = Secret {
                            key: test_vector.key,
                            salt: test_vector.salt,
                        };

                        let mut data = test_vector.plain_text.clone();
                        let header = Header::with_frame_count(
                            KeyId::from(test_vector.key_id),
                            FrameCount::from(test_vector.frame_count),
                        );
                        let header_buffer = Vec::from(&header);
                        let tag = cipher_suite
                            .encrypt(&mut data, &secret, &header_buffer, header.frame_count())
                            .unwrap();
                        let full_frame: Vec<u8> = header_buffer
                            .into_iter()
                            .chain(data.into_iter())
                            .chain(tag.as_ref().iter().cloned())
                            .collect();

                        assert_bytes_eq(&full_frame, &test_vector.cipher_text);
                    });
            }

            #[test]
            fn should_decrypt_test_vectors_aes_gcm_128_sha256() {
                aes_gcm_128_sha256::get_test_vectors()
                    .into_iter()
                    .for_each(|test_vector| {
                        let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm128Sha256);

                        let secret = Secret {
                            key: test_vector.key,
                            salt: test_vector.salt,
                        };

                        let header = Header::with_frame_count(
                            KeyId::from(test_vector.key_id),
                            FrameCount::from(test_vector.frame_count),
                        );
                        let header_buffer = Vec::from(&header);
                        let mut data = Vec::from(&test_vector.cipher_text[header.size()..]);

                        let decrypted = cipher_suite
                            .decrypt(&mut data, &secret, &header_buffer, header.frame_count())
                            .unwrap();

                        assert_bytes_eq(decrypted, &test_vector.plain_text);
                    });
            }
            #[test]
            fn encrypt_test_vectors_aes_gcm_256_sha512() {
                aes_gcm_256_sha512::get_test_vectors()
                    .into_iter()
                    .for_each(|test_vector| {
                        let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);

                        let secret = Secret {
                            key: test_vector.key,
                            salt: test_vector.salt,
                        };

                        let mut data = test_vector.plain_text.clone();
                        let header = Header::with_frame_count(
                            KeyId::from(test_vector.key_id),
                            FrameCount::from(test_vector.frame_count),
                        );
                        let header_buffer = Vec::from(&header);
                        let tag = cipher_suite
                            .encrypt(&mut data, &secret, &header_buffer, header.frame_count())
                            .unwrap();
                        let full_frame: Vec<u8> = header_buffer
                            .into_iter()
                            .chain(data.into_iter())
                            .chain(tag.as_ref().iter().cloned())
                            .collect();

                        assert_bytes_eq(&full_frame, &test_vector.cipher_text);
                    });
            }

            #[test]
            fn should_decrypt_test_vectors_aes_gcm_256_sha512() {
                aes_gcm_256_sha512::get_test_vectors()
                    .into_iter()
                    .for_each(|test_vector| {
                        let cipher_suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);

                        let secret = Secret {
                            key: test_vector.key,
                            salt: test_vector.salt,
                        };

                        let header = Header::with_frame_count(
                            KeyId::from(test_vector.key_id),
                            FrameCount::from(test_vector.frame_count),
                        );
                        let header_buffer = Vec::from(&header);
                        let mut data = Vec::from(&test_vector.cipher_text[header.size()..]);

                        let decrypted = cipher_suite
                            .decrypt(&mut data, &secret, &header_buffer, header.frame_count())
                            .unwrap();

                        assert_bytes_eq(decrypted, &test_vector.plain_text);
                    });
            }
        }
    }
}
