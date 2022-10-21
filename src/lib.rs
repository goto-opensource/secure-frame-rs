#![deny(clippy::missing_panics_doc)]

mod crypto;
#[cfg(test)]
mod test_vectors;

pub mod error;
pub mod header;
pub mod receiver;
pub mod sender;
pub mod util;

#[cfg(feature = "benchmark-internals")]
pub mod internals {
    pub use crate::crypto::{cipher_suite::*, key_expansion::*};
}
