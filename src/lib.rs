#![warn(missing_docs)]
//! Archive reader for ZIP-derived container formats with safe-by-default extraction checks.

pub mod error;
mod archive;
mod crx;
mod security;
mod types;

pub use types::*;
