// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use super::{cipher_suite::CipherSuite, secret::Secret};
use crate::error::Result;

pub trait KeyExpansion {
    fn expand_from<M, K>(cipher_suite: &CipherSuite, key_material: M, key_id: K) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<u64>;
}

pub fn get_hkdf_key_expand_info(key_id: u64) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HKDF_KEY_EXPAND_INFO,
        &key_id.to_be_bytes(),
    ]
    .concat()
}

pub fn get_hkdf_salt_expand_info(key_id: u64) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HDKF_SALT_EXPAND_INFO,
        &key_id.to_be_bytes(),
    ]
    .concat()
}

const SFRAME_LABEL: &[u8] = b"SFrame 1.0 ";

// For the current test vectors different labels than specified were used
// see https://github.com/sframe-wg/sframe/issues/137
cfg_if::cfg_if! {
    if #[cfg(test)] {
        const SFRAME_HKDF_KEY_EXPAND_INFO: &[u8] = b"key ";
        const SFRAME_HDKF_SALT_EXPAND_INFO: &[u8] = b"salt ";
    } else {
        const SFRAME_HKDF_KEY_EXPAND_INFO: &[u8] = b"Secret key ";
        const SFRAME_HDKF_SALT_EXPAND_INFO: &[u8] = b"Secret salt ";
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "openssl")] {
        pub fn get_hkdf_aead_label(tag_len: usize) -> Vec<u8> {
            // for current platforms there is no issue casting from usize to u64
            return [SFRAME_HDKF_SUB_AEAD_LABEL, &(tag_len).to_be_bytes()].concat()
        }

        pub const SFRAME_HDKF_SUB_AEAD_LABEL: &[u8] = b"SFrame 1.0 AES CTR AEAD ";
        pub const SFRAME_HKDF_SUB_ENC_EXPAND_INFO: &[u8] = b"enc";
        pub const SFRAME_HDKF_SUB_AUTH_EXPAND_INFO: &[u8] = b"auth";
    }
}

#[cfg(feature = "openssl")]
#[cfg(test)]
mod test {
    use super::KeyExpansion;
    use crate::crypto::cipher_suite::CipherSuite;
    use crate::crypto::secret::Secret;
    use crate::test_vectors::get_sframe_test_vector;
    use crate::{crypto::cipher_suite::CipherSuiteVariant, util::test::assert_bytes_eq};

    mod aes_gcm {
        use crate::crypto::key_expansion::SFRAME_LABEL;

        use super::*;

        use test_case::test_case;

        #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
        #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]

        fn derive_correct_base_keys(variant: CipherSuiteVariant) {
            let test_vec = get_sframe_test_vector(&variant.to_string());

            assert_bytes_eq(SFRAME_LABEL, &test_vec.sframe_label);

            let secret = Secret::expand_from(
                &CipherSuite::from(variant),
                &test_vec.key_material,
                test_vec.key_id,
            )
            .unwrap();

            assert_bytes_eq(&secret.key, &test_vec.sframe_key);
            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
        }
    }

    #[cfg(feature = "openssl")]
    mod aes_ctr {
        use super::*;
        use test_case::test_case;

        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80")]
        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64")]
        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32")]
        fn derive_correct_sub_keys(variant: CipherSuiteVariant) {
            let test_vec = get_sframe_test_vector(&variant.to_string());
            let cipher_suite = CipherSuite::from(variant);

            let secret =
                Secret::expand_from(&cipher_suite, &test_vec.key_material, test_vec.key_id)
                    .unwrap();

            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
            // the subkeys stored in secret.key and secret.auth are not included in the test vectors
            assert_eq!(secret.auth.unwrap().len(), cipher_suite.hash_len);
            assert_eq!(secret.key.len(), cipher_suite.key_len);
        }
    }
}
