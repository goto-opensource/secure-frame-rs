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

#[cfg(test)]
mod test {
    use crate::crypto::cipher_suite::CipherSuite;
    use crate::crypto::secret::Secret;
    use crate::test_vectors::get_test_vector;

    use crate::{crypto::cipher_suite::CipherSuiteVariant, util::test::assert_bytes_eq};

    use super::KeyExpansion;

    fn derive_correct_keys(variant: CipherSuiteVariant) {
        let test_vector = get_test_vector(&variant.to_string());
        let secret =
            Secret::expand_from(&CipherSuite::from(variant), &test_vector.key_material).unwrap();

        assert_bytes_eq(&secret.key, &test_vector.key);
        assert_bytes_eq(&secret.salt, &test_vector.salt);
    }

    #[test]
    fn derive_correct_keys_aes_gcm_128_sha256() {
        derive_correct_keys(CipherSuiteVariant::AesGcm128Sha256);
    }

    #[test]
    fn derive_correct_keys_aes_gcm_256_sha512() {
        derive_correct_keys(CipherSuiteVariant::AesGcm256Sha512);
    }
}
