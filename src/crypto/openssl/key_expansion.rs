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
        let try_expand = || {
            let prk = extract_prk(&cipher_suite, key_material.as_ref())?;
            let key = expand_key(
                &cipher_suite,
                &prk,
                SFRAME_HKDF_KEY_EXPAND_INFO,
                cipher_suite.key_len,
            )?;
            let salt = expand_key(
                &cipher_suite,
                &prk,
                SFRAME_HDKF_SALT_EXPAND_INFO,
                cipher_suite.nonce_len,
            )?;

            Ok(Secret { key, salt })
        };

        try_expand().map_err(|_: openssl::error::ErrorStack| SframeError::KeyExpansion)
    }
}

fn extract_prk(
    cipher_suite: &CipherSuite,
    key_material: &[u8],
) -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut ctx = init_openssl_ctx(cipher_suite)?;

    ctx.set_hkdf_mode(openssl::pkey_ctx::HkdfMode::EXTRACT_ONLY)?;
    ctx.set_hkdf_salt(SFRAME_HKDF_SALT)?;
    ctx.set_hkdf_key(key_material)?;

    let mut prk = vec![];
    ctx.derive_to_vec(&mut prk)?;

    Ok(prk)
}

fn expand_key(
    cipher_suite: &CipherSuite,
    prk: &[u8],
    info: &[u8],
    key_len: usize,
) -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut ctx = init_openssl_ctx(cipher_suite)?;

    ctx.set_hkdf_mode(openssl::pkey_ctx::HkdfMode::EXPAND_ONLY)?;
    ctx.set_hkdf_key(prk)?;
    ctx.add_hkdf_info(info)?;

    let mut key = vec![0; key_len];
    ctx.derive(Some(&mut key))?;

    Ok(key)
}

fn init_openssl_ctx(
    cipher_suite: &CipherSuite,
) -> std::result::Result<openssl::pkey_ctx::PkeyCtx<()>, openssl::error::ErrorStack> {
    let mut ctx = openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::HKDF)?;
    ctx.derive_init()?;

    let digest = cipher_suite.variant.into();
    ctx.set_hkdf_md(digest)?;

    Ok(ctx)
}

impl From<CipherSuiteVariant> for &'static openssl::md::MdRef {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            CipherSuiteVariant::AesGcm128Sha256 => openssl::md::Md::sha256(),
            CipherSuiteVariant::AesGcm256Sha512 => openssl::md::Md::sha512(),
        }
    }
}
