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

#[cfg(test)]
mod test {

    mod aes_gcm {
        use crate::{
            crypto::{
                aead::AeadEncrypt,
                cipher_suite::{CipherSuite, CipherSuiteVariant},
                key_expansion::{ExpandAsSecret, KeyMaterial},
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

        mod test_vectors {
            use crate::test_vectors::get_test_vector;

            use crate::{
                crypto::{
                    aead::{AeadDecrypt, AeadEncrypt},
                    cipher_suite::{CipherSuite, CipherSuiteVariant},
                    secret::Secret,
                },
                header::{FrameCount, Header, HeaderFields, KeyId},
                util::test::assert_bytes_eq,
            };

            fn encrypt_test_vector(variant: CipherSuiteVariant) {
                let test_vector = get_test_vector(&variant.to_string());
                let cipher_suite = CipherSuite::from(variant);

                let secret = Secret {
                    key: test_vector.key.clone(),
                    salt: test_vector.salt.clone(),
                };

                for enc in &test_vector.encryptions {
                    let mut data = test_vector.plain_text.clone();
                    let header = Header::with_frame_count(
                        KeyId::from(enc.key_id),
                        FrameCount::from(enc.frame_count),
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

                    assert_bytes_eq(&full_frame, &enc.cipher_text);
                }
            }

            fn decrypt_test_vector(variant: CipherSuiteVariant) {
                let test_vector = get_test_vector(&variant.to_string());
                let cipher_suite = CipherSuite::from(variant);

                let secret = Secret {
                    key: test_vector.key.clone(),
                    salt: test_vector.salt.clone(),
                };

                for enc in &test_vector.encryptions {
                    let header = Header::with_frame_count(
                        KeyId::from(enc.key_id),
                        FrameCount::from(enc.frame_count),
                    );
                    let header_buffer = Vec::from(&header);
                    let mut data = Vec::from(&enc.cipher_text[header.size()..]);

                    let decrypted = cipher_suite
                        .decrypt(&mut data, &secret, &header_buffer, header.frame_count())
                        .unwrap();

                    assert_bytes_eq(decrypted, &test_vector.plain_text);
                }
            }

            #[test]
            fn encrypt_test_vector_aes_gcm_128_sha256() {
                encrypt_test_vector(CipherSuiteVariant::AesGcm128Sha256);
            }

            #[test]
            fn should_decrypt_test_vector_aes_gcm_128_sha256() {
                decrypt_test_vector(CipherSuiteVariant::AesGcm128Sha256);
            }

            #[test]
            fn encrypt_test_vectors_aes_gcm_256_sha512() {
                encrypt_test_vector(CipherSuiteVariant::AesGcm256Sha512);
            }

            #[test]
            fn should_decrypt_test_vectors_aes_gcm_256_sha512() {
                decrypt_test_vector(CipherSuiteVariant::AesGcm256Sha512);
            }
        }
    }
}
