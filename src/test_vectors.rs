use crate::crypto::cipher_suite::CipherSuiteVariant;

#[derive(Debug, Clone)]
pub struct TestVector {
    pub cipher_suite_variant: CipherSuiteVariant,
    pub key_material: Vec<u8>,
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub plain_text: Vec<u8>,

    pub key_id: u64,
    pub frame_count: u64,
    pub header: Vec<u8>,
    pub nonce: Vec<u8>,
    pub cipher_text: Vec<u8>,
}

fn vec_from_hex_str(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap()
}

pub mod aes_gcm_128_sha256 {

    use std::vec;

    use crate::crypto::cipher_suite::CipherSuiteVariant;

    use super::{vec_from_hex_str, TestVector};

    fn create_test_vector(
        key_id: u64,
        frame_count: u64,
        header: &str,
        nonce: &str,
        cipher_text: &str,
    ) -> TestVector {
        TestVector {
            cipher_suite_variant: CipherSuiteVariant::AesGcm128Sha256,
            key_material: vec_from_hex_str("303132333435363738393a3b3c3d3e3f"),
            key: vec_from_hex_str("2ea2e8163ff56c0613e6fa9f20a213da"),
            salt: vec_from_hex_str("a80478b3f6fba19983d540d5"),
            plain_text: vec_from_hex_str("46726f6d2068656176656e6c79206861726d6f6e79202f2f205468697320756e6976657273616c206672616d6520626567616e"),
            key_id,
            frame_count,
            header: vec_from_hex_str(header),
            nonce: vec_from_hex_str(nonce),
            cipher_text: vec_from_hex_str(cipher_text),
        }
    }

    pub fn get_test_vectors() -> Vec<TestVector> {
        vec![
        create_test_vector(0x7, 0x0, "1700",            "a80478b3f6fba19983d540d5", "17000e426255e47ed70dd7d15d69d759bf459032ca15f5e8b2a91e7d348aa7c186d403f620801c495b1717a35097411aa97cbb140671eb3b49ac3775926db74d57b91e8e6c"),
        create_test_vector(0x7, 0x1, "1701",            "a80478b3f6fba19983d540d4", "170103bbafa34ada8a6b9f2066bc34a1959d87384c9f4b1ce34fed58e938bde143393910b1aeb55b48d91d5b0db3ea67e3d0e02b843afd41630c940b1948e72dd45396a43a"),
        create_test_vector(0x7, 0x2, "1702",            "a80478b3f6fba19983d540d7", "170258d58adebd8bf6f3cc0c1fcacf34ba4d7a763b2683fe302a57f1be7f2a274bf81b2236995fec1203cadb146cd402e1c52d5e6a10989dfe0f4116da1ee4c2fad0d21f8f"),
        create_test_vector(0xf, 0xaa, "190faa",         "a80478b3f6fba19983d5407f", "190faad0b1743bf5248f90869c9456366d55724d16bbe08060875815565e90b114f9ccbdba192422b33848a1ae1e3bd266a001b2f5bb727112772e0072ea8679ca1850cf11d8"),
        create_test_vector(0x1ff, 0xaa, "1a01ffaa",     "a80478b3f6fba19983d5407f", "1a01ffaad0b1743bf5248f90869c9456366d55724d16bbe08060875815565e90b114f9ccbdba192422b33848a1ae1e3bd266a001b2f5bbc9c63bd3973c19bd57127f565380ed4a"),
        create_test_vector(0x1ff, 0xaaaa, "2a01ffaaaa", "a80478b3f6fba19983d5ea7f", "2a01ffaaaa9de65e21e4f1ca2247b87943c03c5cb7b182090e93d508dcfb76e08174c6397356e682d2eaddabc0b3c1018d2c13c3570f61c1beaab805f27b565e1329a823a7a649b6"),
        create_test_vector(0xffffffffffffff, 0xffffffffffffff, "7fffffffffffffffffffffffffffff", "a80478b3f6045e667c2abf2a", "7fffffffffffffffffffffffffffff09981bdcdad80e380b6f74cf6afdbce946839bedadd57578bfcd809dbcea535546cc24660613d2761adea852155785011e633534f4ecc3b8257c8d34321c27854a1422"),
    ]
    }
}

pub mod aes_gcm_256_sha512 {

    use std::vec;

    use crate::crypto::cipher_suite::CipherSuiteVariant;

    use super::{vec_from_hex_str, TestVector};

    fn create_test_vector(
        key_id: u64,
        frame_count: u64,
        header: &str,
        nonce: &str,
        cipher_text: &str,
    ) -> TestVector {
        TestVector {
            cipher_suite_variant: CipherSuiteVariant::AesGcm256Sha512,
            key_material: vec_from_hex_str("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
            key: vec_from_hex_str("436774b0b5ae45633d96547f8f3cb06c8e6628eff2e4255b5c4d77e721aa3355"),
            salt: vec_from_hex_str("31ed26f90a072e6aee646298"),
            plain_text: vec_from_hex_str("46726f6d2068656176656e6c79206861726d6f6e79202f2f205468697320756e6976657273616c206672616d6520626567616e"),
            key_id,
            frame_count,
            header: vec_from_hex_str(header),
            nonce: vec_from_hex_str(nonce),
            cipher_text: vec_from_hex_str(cipher_text),
        }
    }

    pub fn get_test_vectors() -> Vec<TestVector> {
        vec![
        create_test_vector(0x7, 0x0, "1700", "31ed26f90a072e6aee646298", "1700f3e297c1e95207710bd31ccc4ba396fbef7b257440bde638ff0f3c8911540136df61b26220249d6c432c245ae8d55ef45bfccf32530a15aeaaf313a03838e51bd45652"),
        create_test_vector(0x7, 0x1, "1701", "31ed26f90a072e6aee646299", "170193268b0bf030071bff443bb6b4471bdfb1cc81bc9625f4697b0336ff4665d15f152f02169448d8a967fb06359a87d2145398de0ce3fbe257b0992a3da1537590459f3c"),
        create_test_vector(0x7, 0x2, "1702", "31ed26f90a072e6aee64629a", "1702649691ba27c4c01a41280fba4657c03fa7fe21c8f5c862e9094227c3ca3ec0d9468b1a2cb060ff0978f25a24e6b106f5a6e1053c1b8f5fce794d88a0e4818c081e18ea"),
        create_test_vector(0xf, 0xaa, "190faa", "31ed26f90a072e6aee646232", "190faa2858c10b5ddd231c1f26819490521678603a050448d563c503b1fd890d02ead01d754f074ecb6f32da9b2f3859f380b4f47d4edd1e15f42f9a2d7ecfac99067e238321"),
        create_test_vector(0x1ff, 0xaa, "1a01ffaa", "31ed26f90a072e6aee646232", "1a01ffaa2858c10b5ddd231c1f26819490521678603a050448d563c503b1fd890d02ead01d754f074ecb6f32da9b2f3859f380b4f47d4e3bf7040eb10ec25b8126b2ce7b1d9d31"),
        create_test_vector(0x1ff, 0xaaaa, "2a01ffaaaa", "31ed26f90a072e6aee64c832", "2a01ffaaaad9bc6a258a07d210a814d545eca70321c0e87498ada6e5c708b7ead162ffcf4fbaba1eb82650590a87122b4d95fe36bd88b278812166d26e046ed0a530b7ee232ee0f2"),
        create_test_vector(0xffffffffffffff, 0xffffffffffffff, "7fffffffffffffffffffffffffffff", "31ed26f90af8d195119b9d67", "7fffffffffffffffffffffffffffffaf480d4779ce0c02b5137ee6a61e026c04ac999cb0c97319feceeb258d58df23bce14979e5c67a431777b34498062e72f939ca42ec84ffbc7b50eff923f515a2df760c"),
    ]
    }
}
