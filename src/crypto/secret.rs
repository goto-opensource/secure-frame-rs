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
    use crate::{
        crypto::{
            cipher_suite::{CipherSuite, CipherSuiteVariant},
            key_expansion::KeyMaterial,
        },
        header::FrameCount,
        test_vectors::*,
        util::test::assert_bytes_eq,
    };

    const NONCE_LEN: usize = 12;

    fn test_nonce(cipher_suite: CipherSuite, test_vector: TestVector) {
        let secret = KeyMaterial(&test_vector.key_material)
            .expand_as_secret(&cipher_suite)
            .unwrap();
        let nonce: [u8; NONCE_LEN] =
            secret.create_nonce(&FrameCount::from(test_vector.frame_count));

        assert_bytes_eq(&nonce, &test_vector.nonce);
    }

    #[test]
    fn create_correct_nonce_aes_gcm_128_sha256() {
        aes_gcm_128_sha256::get_test_vectors()
            .into_iter()
            .for_each(|test_vector| {
                test_nonce(CipherSuiteVariant::AesGcm128Sha256.into(), test_vector);
            });
    }
    #[test]
    fn create_correct_nonce_aes_gcm_256_sha512() {
        aes_gcm_256_sha512::get_test_vectors()
            .into_iter()
            .for_each(|test_vector| {
                test_nonce(CipherSuiteVariant::AesGcm256Sha512.into(), test_vector);
            });
    }
}
