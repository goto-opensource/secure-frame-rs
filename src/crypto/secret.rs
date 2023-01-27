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
