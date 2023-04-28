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
    use crate::test_vectors::get_test_vector;

    use crate::{
        crypto::{cipher_suite::CipherSuiteVariant, key_expansion::KeyMaterial},
        header::FrameCount,
        util::test::assert_bytes_eq,
    };

    const NONCE_LEN: usize = 12;

    fn test_nonce(cipher_suite_variant: CipherSuiteVariant) {
        let tv = get_test_vector(cipher_suite_variant as u8);
        let cipher_suite = cipher_suite_variant.into();

        for enc in &tv.encryptions {
            let secret = KeyMaterial(&tv.key_material)
                .expand_as_secret(&cipher_suite)
                .unwrap();
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
