use crate::header::FrameCount;

pub struct Secret {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
}

impl Secret {
    pub(crate) fn create_nonce<const LEN: usize>(&self, frame_count: &FrameCount) -> [u8; LEN] {
        debug_assert!(
            self.salt.len() >= LEN,
            "Salt key is too short, is the cipher suite misconfigured?"
        );

        let mut counter = frame_count.as_be_bytes().rev();
        let mut iv = [0u8; LEN];
        for i in (0..LEN).rev() {
            iv[i] = self.salt[i];
            if let Some(counter_byte) = counter.next() {
                iv[i] ^= counter_byte;
            }
        }

        iv
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::cipher_suite::CipherSuite;
    use crate::crypto::key_expansion::KeyExpansion;
    use crate::test_vectors::get_test_vector;

    use crate::{
        crypto::cipher_suite::CipherSuiteVariant, header::FrameCount, util::test::assert_bytes_eq,
    };

    use super::Secret;

    const NONCE_LEN: usize = 12;

    fn test_nonce(variant: CipherSuiteVariant) {
        let tv = get_test_vector(&variant.to_string());

        for enc in &tv.encryptions {
            let secret =
                Secret::expand_from(&CipherSuite::from(variant), &tv.key_material).unwrap();
            let nonce: [u8; NONCE_LEN] = secret.create_nonce(&FrameCount::from(enc.frame_count));
            assert_bytes_eq(&nonce, &enc.nonce);
        }
    }

    #[test]
    fn create_correct_nonce_aes_gcm_128_sha256() {
        test_nonce(CipherSuiteVariant::AesGcm128Sha256);
    }
    #[test]
    fn create_correct_nonce_aes_gcm_256_sha512() {
        test_nonce(CipherSuiteVariant::AesGcm256Sha512);
    }
}
