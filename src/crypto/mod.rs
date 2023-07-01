// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

pub mod aead;
pub mod cipher_suite;
pub mod key_expansion;
pub mod secret;

cfg_if::cfg_if! {
if #[cfg(all(feature = "openssl", feature = "wasm-bindgen"))]{
    // TODO issue a warning
    // compile_error!{"Cannot use openssl with wasm-bindgen. Falling back to ring."};
    mod ring;
}
else if #[cfg(all(feature = "openssl", not(feature = "ring")))] {
    mod openssl;
} else {
    mod ring;
}
}
