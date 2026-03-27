#![warn(missing_docs)]
#![allow(missing_docs)]
//! Archive reader for ZIP-derived container formats with safe-by-default extraction checks.

mod archive;
mod crx;
mod security;
mod types;

pub use types::*;
