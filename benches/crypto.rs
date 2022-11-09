use criterion::{black_box, criterion_group, BatchSize, Bencher, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use sframe::{receiver::Receiver, sender::Sender};

const KEY_MATERIAL: &[u8] = b"THIS_IS_SOME_MATERIAL";
const PARTICIPANT_ID: u64 = 42;
const SKIP: usize = 0;
const PAYLOAD_SIZES: [usize; 4] = [512, 5120, 51200, 512000];

fn bench_over_payload_sizes<F>(c: &mut Criterion, name: &str, mut bench: F)
where
    F: FnMut(&mut Bencher, &usize),
{
    let mut group = c.benchmark_group(name);
    for payload_size in PAYLOAD_SIZES.iter() {
        group.throughput(criterion::Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            payload_size,
            &mut bench,
        );
    }
}

fn create_random_payload(size: usize) -> Vec<u8> {
    let mut unencrypted_payload = vec![0; size];
    thread_rng().fill(unencrypted_payload.as_mut_slice());
    unencrypted_payload
}
fn create_random_encrypted_payload(size: usize, sender: &mut Sender) -> Vec<u8> {
    sender.encrypt(&create_random_payload(size), SKIP).unwrap()
}

fn aes_gcm256_sha512(c: &mut Criterion) {
    let mut sender = Sender::new(PARTICIPANT_ID);
    sender.set_encryption_key(KEY_MATERIAL).unwrap();
    let mut receiver = Receiver::new();
    receiver
        .set_encryption_key(PARTICIPANT_ID, KEY_MATERIAL)
        .unwrap();

    bench_over_payload_sizes(c, "encrypt with AES_GCM_256_SHA512", |b, &payload_size| {
        b.iter_batched(
            || create_random_payload(payload_size),
            |unencrypted_payload| {
                let encrypted_frame = sender.encrypt(&unencrypted_payload, SKIP).unwrap();
                black_box(encrypted_frame);
            },
            BatchSize::SmallInput,
        );
    });

    bench_over_payload_sizes(c, "decrypt with AES_GCM_256_SHA512", |b, &payload_size| {
        b.iter_batched(
            || create_random_encrypted_payload(payload_size, &mut sender),
            |encrypted_frame| {
                let decrypted_frame = receiver.decrypt(&encrypted_frame, SKIP).unwrap();
                black_box(decrypted_frame);
            },
            BatchSize::SmallInput,
        );
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
criterion_group!(benches, aes_gcm256_sha512, key_expansion);
