// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use crate::{
    crypto::{
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_expansion::{
            ExpandAsSecret, KeyMaterial, SFRAME_HDKF_SALT_EXPAND_INFO, SFRAME_HKDF_KEY_EXPAND_INFO,
            SFRAME_HKDF_SALT,
        },
        secret::Secret,
    },
    error::{Result, SframeError},
};

impl ExpandAsSecret for KeyMaterial<'_> {
    fn expand_as_secret(&self, cipher_suite: &CipherSuite) -> Result<Secret> {
        let algorithm = cipher_suite.into();
        let prk = ring::hkdf::Salt::new(algorithm, SFRAME_HKDF_SALT).extract(self.0);

        let key = expand_key(&prk, SFRAME_HKDF_KEY_EXPAND_INFO, cipher_suite.key_len)?;
        let salt = expand_key(&prk, SFRAME_HDKF_SALT_EXPAND_INFO, cipher_suite.nonce_len)?;

        Ok(Secret { key, salt })
    }
}

struct OkmKeyLength(usize);

impl ring::hkdf::KeyType for OkmKeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<&CipherSuite> for ring::hkdf::Algorithm {
    fn from(cipher_suite: &CipherSuite) -> Self {
        match cipher_suite.variant {
            CipherSuiteVariant::AesGcm128Sha256 => ring::hkdf::HKDF_SHA256,
            CipherSuiteVariant::AesGcm256Sha512 => ring::hkdf::HKDF_SHA512,
        }
    }
}

fn expand_key(prk: &ring::hkdf::Prk, info: &[u8], key_len: usize) -> Result<Vec<u8>> {
    let mut sframe_key = vec![0_u8; key_len];

    prk.expand(&[info], OkmKeyLength(key_len))
        .and_then(|okm| okm.fill(sframe_key.as_mut_slice()))
        .map_err(|_| SframeError::KeyExpansion)?;

    Ok(sframe_key)
}
