// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

extern crate serde;

pub fn get_test_vector(cipher_suite_variant: u8) -> &'static TestVector {
    TEST_VECTORS
        .iter()
        .find(|v| v.cipher_suite_variant == cipher_suite_variant)
        .unwrap()
}

const TEST_VECTORS_STR: &str = std::include_str!("test-vectors.json");
lazy_static::lazy_static! {
static ref TEST_VECTORS: Vec<TestVector> = {
     parse_test_vectors()
};
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct EncryptionTestCase {
    #[serde(rename = "kid")]
    pub key_id: u64,
    #[serde(rename = "ctr")]
    pub frame_count: u64,
    #[serde(deserialize_with = "vec_from_hex_str")]
    pub header: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex_str")]
    pub nonce: Vec<u8>,
    #[serde(rename = "ciphertext", deserialize_with = "vec_from_hex_str")]
    pub cipher_text: Vec<u8>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct TestVector {
    #[serde(rename = "cipher_suite")]
    pub cipher_suite_variant: u8,
    #[serde(rename = "base_key", deserialize_with = "vec_from_hex_str")]
    pub key_material: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex_str")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex_str")]
    pub salt: Vec<u8>,
    #[serde(rename = "plaintext", deserialize_with = "vec_from_hex_str")]
    pub plain_text: Vec<u8>,

    pub encryptions: Vec<EncryptionTestCase>,
}

fn vec_from_hex_str<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: &str = serde::Deserialize::deserialize(deserializer)?;
    hex::decode(hex_str).map_err(serde::de::Error::custom)
}

fn parse_test_vectors() -> Vec<TestVector> {
    serde_json::from_str(TEST_VECTORS_STR).unwrap()
}

#[cfg(test)]
mod test {
    use crate::get_test_vector;

    #[test]
    fn should_parse_test_vectors() {
        let valid_cipher_suite_variants = 1..4;
        for variant in valid_cipher_suite_variants {
            let vector = get_test_vector(variant);
            assert_eq!(vector.cipher_suite_variant, variant);
        }
    }
}
