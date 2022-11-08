use criterion::{black_box, criterion_group, Criterion};
use rand::{thread_rng, Rng};
use sframe::{receiver::Receiver, sender::Sender};

const KEY_MATERIAL: &[u8] = b"THIS_IS_SOME_MATERIAL";
const PARTICIPANT_ID: u64 = 42;
const SKIP: usize = 0;
const PAYLOAD_SIZE: usize = 2056;

fn encryption(c: &mut Criterion) {
    let mut sender = Sender::new(PARTICIPANT_ID);
    sender.set_encryption_key(KEY_MATERIAL).unwrap();

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
    sender.set_encryption_key(KEY_MATERIAL).unwrap();

    let mut receiver = Receiver::new();
    receiver
        .set_encryption_key(PARTICIPANT_ID, KEY_MATERIAL)
        .unwrap();

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

fn key_expansion(c: &mut Criterion) {
    c.bench_function("expand key with AES_GCM_256_SHA512 cipher suite", |b| {
        // currently defaults to AES_GCM_256_SHA512
        let mut sender = Sender::new(PARTICIPANT_ID);
        b.iter(|| {
            black_box(sender.set_encryption_key(KEY_MATERIAL).unwrap());
        })
    });
}
criterion_group!(benches, encryption, decryption, key_expansion);
