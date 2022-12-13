// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use super::cipher_suite::CipherSuite;
use crate::error::Result;

#[derive(Debug, Default, Clone, Copy)]
pub struct KeyMaterial<'a>(pub &'a [u8]);

impl KeyMaterial<'_> {
    pub fn expand_as_secret(&self, cipher_suite: &CipherSuite) -> Result<Secret> {
        ring::expand_secret_from(self.0, cipher_suite)
    }
}

pub struct Secret {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
}

const SFRAME_HKDF_SALT: &[u8] = "SFrame10".as_bytes();
const SFRAME_HKDF_KEY_EXPAND_INFO: &[u8] = "key".as_bytes();
const SFRAME_HDKF_SALT_EXPAND_INFO: &[u8] = "salt".as_bytes();

mod ring {
    use crate::{
        crypto::cipher_suite::{CipherSuite, CipherSuiteVariant},
        error::{Result, SframeError},
    };

    use super::{
        Secret, SFRAME_HDKF_SALT_EXPAND_INFO, SFRAME_HKDF_KEY_EXPAND_INFO, SFRAME_HKDF_SALT,
    };

    struct OkmKeyLength(usize);

    impl ring::hkdf::KeyType for OkmKeyLength {
        fn len(&self) -> usize {
            self.0
        }
    }

    impl From<&CipherSuite> for ring::hkdf::Algorithm {
        fn from(cipher_suite: &CipherSuite) -> Self {
            match cipher_suite.variant {
                CipherSuiteVariant::AesCm128HmacSha256_8
                | CipherSuiteVariant::AesCm128HmacSha256_4
                | CipherSuiteVariant::AesGcm128Sha256 => ring::hkdf::HKDF_SHA256,
                CipherSuiteVariant::AesGcm256Sha512 => ring::hkdf::HKDF_SHA512,
            }
        }
    }

    pub fn expand_secret_from(key_material: &[u8], cipher_suite: &CipherSuite) -> Result<Secret> {
        let algorithm = cipher_suite.into();
        let prk = ring::hkdf::Salt::new(algorithm, SFRAME_HKDF_SALT).extract(key_material);

        let key = expand_key(&prk, SFRAME_HKDF_KEY_EXPAND_INFO, cipher_suite.key_len)?;
        let salt = expand_key(&prk, SFRAME_HDKF_SALT_EXPAND_INFO, cipher_suite.nonce_len)?;

        Ok(Secret { key, salt })
    }

    fn expand_key(prk: &ring::hkdf::Prk, info: &[u8], key_len: usize) -> Result<Vec<u8>> {
        let mut sframe_key = vec![0_u8; key_len];

        prk.expand(&[info], OkmKeyLength(key_len))
            .and_then(|okm| okm.fill(sframe_key.as_mut_slice()))
            .map_err(|_| SframeError::KeyExpansion)?;

        Ok(sframe_key)
    }
}

#[cfg(test)]
mod test {
    mod aes_gcm_256_sha512 {
        use crate::{
            crypto::{
                cipher_suite::{CipherSuite, CipherSuiteVariant},
                key_expansion::KeyMaterial,
            },
            test_vectors::aes_gcm_256_sha512::get_test_vectors,
            util::test::assert_bytes_eq,
        };

        #[test]
        fn derive_correct_keys() {
            // Test vectors are based on the same key, so we test only one here
            let test_vector = &get_test_vectors()[0];
            let secret = KeyMaterial(&test_vector.key_material)
                .expand_as_secret(&CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512))
                .unwrap();
            assert_bytes_eq(&secret.key, &test_vector.key);
            assert_bytes_eq(&secret.salt, &test_vector.salt);
        }
    }
}
