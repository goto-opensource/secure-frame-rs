// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use criterion::{black_box, criterion_group, Criterion};

use sframe::header::{Deserialization, FrameCount, Header, KeyId, Serialization};

fn header_serialization(c: &mut Criterion) {
    c.bench_function("basic header", |b| {
        let mut buffer = vec![0_u8; 4];
        let basic_header = Header::new(7_u8);
        b.iter(|| black_box(basic_header.serialize(&mut buffer)))
    });

    c.bench_function("extended header", |b| {
        let mut buffer = vec![0_u8; 4];
        let extended_header = Header::extended(128_u64);
        b.iter(|| black_box(extended_header.serialize(&mut buffer)))
    });

    c.bench_function("deserialize 1000 basic headers", |b| {
        let serialized_headers = (0..1000_u64)
            .map(|i| {
                let k: u8 = (i % 8) as u8;
                let header = Header::with_frame_count(KeyId::Basic(k), FrameCount::from(1000 - i));
                let mut buffer = vec![0_u8; 4];
                header.serialize(&mut buffer).unwrap();
                buffer
            })
            .collect::<Vec<_>>();

        b.iter(move || {
            serialized_headers.iter().for_each(|header| {
                let h = Header::deserialize(header).unwrap();
                black_box(h);
            })
        })
    });

    c.bench_function("deserialize 1000 extended headers", |b| {
        let serialized_headers = (0..1000_u64)
            .map(|k| {
                let header = Header::with_frame_count(k, FrameCount::from(1000 - k));
                let mut buffer = vec![0_u8; 7];
                header.serialize(&mut buffer).unwrap();
                buffer
            })
            .collect::<Vec<_>>();

        b.iter(move || {
            serialized_headers.iter().for_each(|header| {
                let h = Header::deserialize(header).unwrap();
                black_box(h);
            })
        })
    });
}

criterion_group!(benches, header_serialization);
