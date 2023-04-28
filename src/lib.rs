// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT
//! # Secure Frame (`SFrame`)
//! This library is an implementation of [draft-ietf-sframe-enc-latest](https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html).
//!
//! It is in it's current form a subset of the specification (e.g. Aes-CTR is not implemented).

#![deny(clippy::missing_panics_doc)]
#![deny(
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications
)]
#![warn(
    // missing_docs,
    clippy::doc_markdown,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    clippy::inconsistent_struct_constructor,
    clippy::map_unwrap_or,
    clippy::match_same_arms
)]

mod crypto;
mod util;

pub mod error;
pub mod frame_validation;
pub mod header;
pub mod receiver;
pub mod sender;
pub use crypto::cipher_suite::CipherSuiteVariant;

#[cfg(test)]
pub mod test_vectors;
