use std::fmt::{self, Display};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(not(any(feature = "zip", feature = "apk", feature = "crx", feature = "ipa")))]
compile_error!("openpack needs at least one feature enabled");

/// Archive format detected from path extension or CRX magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Jar,
    Apk,
    Ipa,
    Crx,
}

impl Display for ArchiveFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Zip => "zip",
            Self::Jar => "jar",
            Self::Apk => "apk",
            Self::Ipa => "ipa",
            Self::Crx => "crx",
        };
        write!(f, "{value}")
    }
}

/// Safety guardrails for archive size and expansion limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_archive_size: u64,
    pub max_entry_uncompressed_size: u64,
    pub max_total_uncompressed_size: u64,
    pub max_entries: usize,
    pub max_compression_ratio: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive_size: 256 * 1024 * 1024,
            max_entry_uncompressed_size: 50 * 1024 * 1024,
            max_total_uncompressed_size: 128 * 1024 * 1024,
            max_entries: 2048,
            max_compression_ratio: 100.0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArchiveEntry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc: u32,
    pub is_dir: bool,
}

#[derive(Debug)]
pub struct OpenPack {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) format: ArchiveFormat,
    pub(crate) limits: Limits,
}

#[cfg(feature = "apk")]
#[derive(Debug, Clone)]
pub struct AndroidManifest {
    pub package: String,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
}

#[cfg(feature = "ipa")]
#[derive(Debug, Clone)]
pub struct IpaInfoPlist {
    pub bundle_identifier: Option<String>,
    pub bundle_version: Option<String>,
    pub executable: Option<String>,
}

#[derive(Error, Debug)]
pub enum OpenPackError {
    #[error("invalid openpack configuration: {0}. Fix: use positive limits and keep max archive and entry sizes consistent.")]
    InvalidConfig(String),

    #[error("archive I/O error: {0}. Fix: verify the archive path exists, is readable, and is not concurrently truncated.")]
    Io(#[from] io::Error),

    #[error("ZIP parsing error: {0}. Fix: verify the file is a valid ZIP-derived archive and not truncated or encrypted in an unsupported way.")]
    Zip(#[from] zip::result::ZipError),

    #[error("invalid archive structure: {0}. Fix: inspect the archive for malformed headers, invalid paths, or unsupported layout.")]
    InvalidArchive(String),

    #[error("blocked suspicious archive entry `{0}` because it would escape the extraction root. Fix: remove path traversal segments like `../` from the archive.")]
    ZipSlip(String),

    #[error("archive entry `{0}` was not found. Fix: inspect `pack.entries()` first and use one of the returned entry names.")]
    MissingEntry(String),

    #[error("archive safety limit exceeded: {0}. Fix: raise the relevant `Limits` value only if you trust the archive source.")]
    LimitExceeded(String),

    #[error("unsupported archive format. Fix: use a ZIP, JAR, APK, IPA, or CRX file with the matching crate feature enabled.")]
    Unsupported,
}
