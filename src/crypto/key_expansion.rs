// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use super::{cipher_suite::CipherSuite, secret::Secret};
use crate::error::Result;

pub trait KeyExpansion {
    fn expand_from<T>(cipher_suite: &CipherSuite, key_material: T) -> Result<Secret>
    where
        T: AsRef<[u8]>;
}

pub const SFRAME_HKDF_SALT: &[u8] = "SFrame10".as_bytes();
pub const SFRAME_HKDF_KEY_EXPAND_INFO: &[u8] = "key".as_bytes();
pub const SFRAME_HDKF_SALT_EXPAND_INFO: &[u8] = "salt".as_bytes();

#[cfg(not(feature = "ring"))]
pub const SFRAME_HKDF_SUB_SALT: &[u8] = "SFrame10 AES CTR AEAD".as_bytes();
#[cfg(not(feature = "ring"))]
pub const SFRAME_HKDF_SUB_ENC_EXPAND_INFO: &[u8] = "enc".as_bytes();
#[cfg(not(feature = "ring"))]
pub const SFRAME_HDKF_SUB_AUTH_EXPAND_INFO: &[u8] = "auth".as_bytes();

#[cfg(test)]
mod test {
    use crate::crypto::cipher_suite::CipherSuite;
    use crate::crypto::secret::Secret;
    use crate::test_vectors::get_test_vector;

    use crate::{crypto::cipher_suite::CipherSuiteVariant, util::test::assert_bytes_eq};

    use super::KeyExpansion;

    fn derive_correct_base_keys(variant: CipherSuiteVariant) {
        let test_vector = get_test_vector(&variant.to_string());
        let secret =
            Secret::expand_from(&CipherSuite::from(variant), &test_vector.key_material).unwrap();

        assert_bytes_eq(&secret.key, &test_vector.key);
        assert_bytes_eq(&secret.salt, &test_vector.salt);
    }

    #[test]
    fn derive_correct_keys_aes_gcm_128_sha256() {
        derive_correct_base_keys(CipherSuiteVariant::AesGcm128Sha256);
    }

    #[test]
    fn derive_correct_keys_aes_gcm_256_sha512() {
        derive_correct_base_keys(CipherSuiteVariant::AesGcm256Sha512);
    }

    #[cfg(not(feature = "ring"))]
    mod aes_ctr {
        use super::*;

        fn derive_correct_sub_keys(variant: CipherSuiteVariant) {
            let test_vector = get_test_vector(&variant.to_string());
            let cipher_suite = CipherSuite::from(variant);
            let secret = Secret::expand_from(&cipher_suite, &test_vector.key_material).unwrap();

            assert_bytes_eq(&secret.salt, &test_vector.salt);
            // the subkeys stored in secret.key and secret.auth are not included in the test vectors
            assert_eq!(secret.auth.unwrap().len(), cipher_suite.hash_len);
            assert_eq!(secret.key.len(), cipher_suite.key_len);
        }

        #[test]
        fn derive_correct_keys_aes_ctr_128_hmac_sha256_64() {
            derive_correct_sub_keys(CipherSuiteVariant::AesCtr128HmacSha256_64);
        }

        #[test]
        fn derive_correct_keys_aes_ctr_128_hmac_sha256_32() {
            derive_correct_sub_keys(CipherSuiteVariant::AesCtr128HmacSha256_32);
        }

        // AesCtr128HmacSha256_80 is not available in the test vectors
        // #[test]
        // fn derive_correct_keys_aes_ctr_128_hmac_sha256_80() {
        //     derive_correct_sub_keys(CipherSuiteVariant::AesCtr128HmacSha256_80);
        // }
    }
}
