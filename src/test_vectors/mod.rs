// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT
#![allow(clippy::missing_panics_doc)]

extern crate serde;
use phf::phf_map;

pub fn get_test_vector(cipher_suite_variant: &str) -> &'static TestVector {
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

const CIPHER_SUITE_NAME_FROM_ID: phf::Map<u8, &str> = phf_map! {
        // AesCtr128HmacSha256_80 is not included in the test vectors
        1u8 => "AesCtr128HmacSha256_32",
        2u8 => "AesCtr128HmacSha256_64",
        3u8 => "AesGcm128Sha256",
        4u8 => "AesGcm256Sha512",
};

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
    #[serde(
        rename = "cipher_suite",
        deserialize_with = "cipher_suite_name_from_id"
    )]
    pub cipher_suite_variant: String,

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

fn cipher_suite_name_from_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let id: u8 = serde::Deserialize::deserialize(deserializer)?;

    if let Some(&name) = CIPHER_SUITE_NAME_FROM_ID.get(&id) {
        Ok(String::from(name))
    } else {
        Err(serde::de::Error::custom(format!(
            "Invalid cipher suite id {}",
            id
        )))
    }
}

fn parse_test_vectors() -> Vec<TestVector> {
    serde_json::from_str(TEST_VECTORS_STR).unwrap()
}

#[cfg(test)]
mod test {
    use super::{get_test_vector, CIPHER_SUITE_NAME_FROM_ID};

    #[test]
    fn should_parse_test_vectors() {
        let valid_cipher_suite_variants = CIPHER_SUITE_NAME_FROM_ID.values();
        for &variant in valid_cipher_suite_variants {
            let vector = get_test_vector(variant);
            assert_eq!(vector.cipher_suite_variant, variant);
        }
    }
}
