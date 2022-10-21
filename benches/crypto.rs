use criterion::{black_box, criterion_group, Criterion};
use rand::{thread_rng, Rng};
use sframe::{receiver::Receiver, sender::Sender};

const KEY_MATERIAL: &str = "THIS_IS_SOME_MATERIAL";
const PARTICIPANT_ID: u64 = 42;
const SKIP: usize = 0;
const PAYLOAD_SIZE: usize = 2056;

fn encryption(c: &mut Criterion) {
    let mut sender = Sender::new(PARTICIPANT_ID);
    sender.set_encryption_key(KEY_MATERIAL.as_bytes());

    c.bench_function("encrypt with AES_GCM_256_SHA512", |b| {
        let mut unencrypted_payload = [0u8; PAYLOAD_SIZE];
        thread_rng().fill(unencrypted_payload.as_mut_slice());

        b.iter(|| {
            let encrypted_frame = sender.encrypt(&unencrypted_payload, SKIP).unwrap();
            black_box(encrypted_frame);
        });
    });
}

fn decryption(c: &mut Criterion) {
    let mut sender = Sender::new(PARTICIPANT_ID);
    sender.set_encryption_key(KEY_MATERIAL.as_bytes());

    let receiver = Receiver::new();

    c.bench_function("decrypt with AES_GCM_256_SHA512", |b| {
        let mut unencrypted_payload = [0u8; PAYLOAD_SIZE];
        thread_rng().fill(unencrypted_payload.as_mut_slice());
        let encrypted_frame = sender.encrypt(&unencrypted_payload, SKIP).unwrap();

        b.iter(|| {
            let decrypted_frame = receiver.decrypt(&encrypted_frame, SKIP).unwrap();
            black_box(decrypted_frame);
        });
    });
}

#[cfg(feature = "benchmark-internals")]
fn key_expansion(c: &mut Criterion) {
    use sframe::internals::{CipherSuite, CipherSuiteVariant, KeyMaterial};

    c.bench_function("expand key with AesGcm256Sha512 cipher suite", |b| {
        let suite = CipherSuite::from(CipherSuiteVariant::AesGcm256Sha512);
        b.iter(|| {
            let secret = KeyMaterial(KEY_MATERIAL.as_bytes()).expand_as_secret(&suite);
            black_box(secret);
        })
    });
}

#[cfg(not(feature = "benchmark-internals"))]
criterion_group!(benches, encryption, decryption);

#[cfg(feature = "benchmark-internals")]
criterion_group!(benches, encryption, decryption, key_expansion);
