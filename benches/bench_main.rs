// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use criterion::criterion_main;

mod crypto;
mod header_parsing;

criterion_main!(header_parsing::benches, crypto::benches);
