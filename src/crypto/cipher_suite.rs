#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CipherSuiteVariant {
    // /// counter mode is [not implemented in ring](https://github.com/briansmith/ring/issues/656)
    // AesCm128HmacSha256_8,
    // /// counter mode is [not implemented in ring](https://github.com/briansmith/ring/issues/656)
    // AesCm128HmacSha256_4,
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
            // CipherSuiteVariant::AesCm128HmacSha256_8 => unimplemented!(),
            // CipherSuiteVariant::AesCm128HmacSha256_4 => unimplemented!(),
            CipherSuiteVariant::AesGcm128Sha256 => CipherSuite {
                variant,
                hash_len: 32,
                key_len: 16,
                nonce_len: 12,
                auth_tag_len: 8,
            },
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
