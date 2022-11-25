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
#[cfg(test)]
mod test_vectors;

pub mod error;
pub mod header;
pub mod receiver;
pub mod sender;
pub mod util;
