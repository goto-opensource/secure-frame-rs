// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use crate::{
    crypto::{
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_expansion::{
            KeyExpansion, SFRAME_HDKF_SALT_EXPAND_INFO, SFRAME_HKDF_KEY_EXPAND_INFO,
            SFRAME_HKDF_SALT,
        },
        secret::Secret,
    },
    error::{Result, SframeError},
};

impl KeyExpansion for Secret {
    fn expand_from<T>(cipher_suite: &CipherSuite, key_material: T) -> Result<Secret>
    where
        T: AsRef<[u8]>,
    {
        let algorithm = cipher_suite.variant.into();
        let prk = ring::hkdf::Salt::new(algorithm, SFRAME_HKDF_SALT).extract(key_material.as_ref());

        let key = expand_key(&prk, SFRAME_HKDF_KEY_EXPAND_INFO, cipher_suite.key_len)?;
        let salt = expand_key(&prk, SFRAME_HDKF_SALT_EXPAND_INFO, cipher_suite.nonce_len)?;

        Ok(Secret {
            key,
            salt,
            auth: None,
        })
    }
}

struct OkmKeyLength(usize);

impl ring::hkdf::KeyType for OkmKeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<CipherSuiteVariant> for ring::hkdf::Algorithm {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
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
