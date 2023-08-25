// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use super::{cipher_suite::CipherSuite, secret::Secret};
use crate::error::Result;

pub trait KeyExpansion {
    fn expand_from<T>(cipher_suite: &CipherSuite, key_material: T) -> Result<Secret>
    where
        T: AsRef<[u8]>;
}

pub const SFRAME_HKDF_SALT: &[u8] = b"SFrame10";
pub const SFRAME_HKDF_KEY_EXPAND_INFO: &[u8] = b"key";
pub const SFRAME_HDKF_SALT_EXPAND_INFO: &[u8] = b"salt";

#[cfg(feature = "openssl")]
pub const SFRAME_HKDF_SUB_SALT: &[u8] = b"SFrame10 AES CTR AEAD";
#[cfg(feature = "openssl")]
pub const SFRAME_HKDF_SUB_ENC_EXPAND_INFO: &[u8] = b"enc";
#[cfg(feature = "openssl")]
pub const SFRAME_HDKF_SUB_AUTH_EXPAND_INFO: &[u8] = b"auth";

#[cfg(test)]
mod test {
    use super::KeyExpansion;
    use crate::crypto::cipher_suite::CipherSuite;
    use crate::crypto::secret::Secret;
    use crate::test_vectors::get_sframe_test_vector;
    use crate::{crypto::cipher_suite::CipherSuiteVariant, util::test::assert_bytes_eq};

    mod aes_gcm {
        use super::*;

        use test_case::test_case;

        #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
        #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
        fn derive_correct_base_keys(variant: CipherSuiteVariant) {
            let test_vec = get_sframe_test_vector(&variant.to_string());
            let secret =
                Secret::expand_from(&CipherSuite::from(variant), &test_vec.key_material).unwrap();

            assert_bytes_eq(&secret.key, &test_vec.sframe_key);
            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
        }
    }

    #[cfg(feature = "openssl")]
    mod aes_ctr {
        use super::*;
        use crate::test_vectors::get_aes_ctr_test_vector;

        use test_case::test_case;

        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80")]
        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64")]
        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32")]
        fn derive_correct_sub_keys(variant: CipherSuiteVariant) {
            let test_vec = get_aes_ctr_test_vector(&variant.to_string());
            let cipher_suite = CipherSuite::from(variant);
            let secret = Secret::expand_from(&cipher_suite, &test_vec.key_material).unwrap();

            assert_bytes_eq(&secret.auth.unwrap(), &test_vec.auth_key);
            assert_bytes_eq(&secret.key, &test_vec.enc_key);
        }

        #[test]
        fn derive_correct_keys_aes_ctr_128_hmac_sha256_64() {
            derive_correct_sub_keys(CipherSuiteVariant::AesCtr128HmacSha256_64);
        }

        #[test]
        fn derive_correct_keys_aes_ctr_128_hmac_sha256_32() {
            derive_correct_sub_keys(CipherSuiteVariant::AesCtr128HmacSha256_32);
        }

        #[test]
        // AesCtr128HmacSha256_80 is not available in the test vectors
        #[ignore]
        fn derive_correct_keys_aes_ctr_128_hmac_sha256_80() {
            derive_correct_sub_keys(CipherSuiteVariant::AesCtr128HmacSha256_80);
        }
    }
}
