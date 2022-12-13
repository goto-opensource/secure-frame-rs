// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CipherSuiteVariant {
    AesCm128HmacSha256_8,
    AesCm128HmacSha256_4,
    AesGcm128Sha256,
    AesGcm256Sha512,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CipherSuite {
    pub variant: CipherSuiteVariant,
    pub hash_len: usize,
    pub key_len: usize,
    pub nonce_len: usize,
    pub auth_tag_len: usize,
}

impl From<CipherSuiteVariant> for CipherSuite {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            // TODO implement the missing variants. Change the API so the user can configure it.
            CipherSuiteVariant::AesCm128HmacSha256_8 => unimplemented!(),
            CipherSuiteVariant::AesCm128HmacSha256_4 => unimplemented!(),
            CipherSuiteVariant::AesGcm128Sha256 => unimplemented!(),
            CipherSuiteVariant::AesGcm256Sha512 => CipherSuite {
                variant,
                hash_len: 64,
                key_len: 32,
                nonce_len: 12,
                auth_tag_len: 16,
            },
        }
    }
}
