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
    /// Standard ZIP archive format.
    Zip,
    /// Java Archive (JAR) format - treated as ZIP.
    Jar,
    /// Android Application Package (APK) format.
    Apk,
    /// iOS App Store Package (IPA) format.
    Ipa,
    /// Chrome Extension (CRX) format.
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
///
/// These limits protect against zip bombs, resource exhaustion, and other
/// denial-of-service attacks via malicious archives.
///
/// # Examples
///
/// ```
/// use openpack::Limits;
///
/// // Use default limits for most use cases
/// let limits = Limits::default();
/// assert!(limits.max_archive_size > 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum size of the archive file itself in bytes.
    ///
    /// Default: 256 MiB
    pub max_archive_size: u64,
    /// Maximum uncompressed size of any single entry in bytes.
    ///
    /// Default: 50 MiB
    pub max_entry_uncompressed_size: u64,
    /// Maximum total uncompressed size of all entries combined in bytes.
    ///
    /// Default: 128 MiB
    pub max_total_uncompressed_size: u64,
    /// Maximum number of entries allowed in the archive.
    ///
    /// Default: 2048
    pub max_entries: usize,
    /// Maximum compression ratio (uncompressed / compressed) allowed.
    /// Higher ratios may indicate zip bombs.
    ///
    /// Default: 100.0
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

/// Metadata for a single entry (file or directory) within an archive.
///
/// This struct contains information about an archive entry without
/// the actual file data. Use [`OpenPack::read_entry`](crate::OpenPack::read_entry)
/// to read the entry's contents.
///
/// # Examples
///
/// ```
/// use openpack::OpenPack;
///
/// # fn example(pack: OpenPack) -> Result<(), Box<dyn std::error::Error>> {
/// for entry in pack.entries()? {
///     println!("{}: {} bytes", entry.name, entry.uncompressed_size);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ArchiveEntry {
    /// The entry's path name within the archive.
    pub name: String,
    /// Size of the entry's compressed data in bytes.
    pub compressed_size: u64,
    /// Size of the entry's uncompressed data in bytes.
    pub uncompressed_size: u64,
    /// CRC32 checksum of the uncompressed data.
    pub crc: u32,
    /// Whether this entry represents a directory.
    pub is_dir: bool,
}

/// A handle to an opened archive file.
///
/// `OpenPack` provides safe access to ZIP-derived archives with built-in
/// protection against Zip Slip, zip bombs, and other malicious archive
/// structures.
///
/// The archive data is memory-mapped for efficient access, and all
/// operations enforce the safety limits specified when opening.
///
/// # Examples
///
/// ```
/// use openpack::{OpenPack, Limits};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Open with default limits
/// let pack = OpenPack::open_default("archive.zip")?;
///
/// // List all entries
/// for entry in pack.entries()? {
///     println!("Found: {}", entry.name);
/// }
///
/// // Read a specific entry
/// if pack.contains("readme.txt")? {
///     let content = pack.read_entry("readme.txt")?;
///     println!("Content: {:?}", String::from_utf8_lossy(&content));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct OpenPack {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) format: ArchiveFormat,
    pub(crate) limits: Limits,
}

/// Parsed Android manifest data from an APK file.
///
/// This struct contains key metadata extracted from the `AndroidManifest.xml`
/// file within an APK archive.
///
/// Requires the `"apk"` feature to be enabled.
///
/// # Examples
///
/// ```
/// use openpack::OpenPack;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # #[cfg(feature = "apk")]
/// # {
/// let pack = OpenPack::open_default("app.apk")?;
/// let manifest = pack.read_android_manifest()?;
/// println!("Package: {}", manifest.package);
/// if let Some(version) = manifest.version_name {
///     println!("Version: {}", version);
/// }
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "apk")]
#[derive(Debug, Clone)]
pub struct AndroidManifest {
    /// The package name (e.g., "com.example.app").
    pub package: String,
    /// The human-readable version name (e.g., "1.2.3").
    pub version_name: Option<String>,
    /// The internal version code (e.g., "42").
    pub version_code: Option<String>,
    /// The minimum Android SDK version required.
    pub min_sdk: Option<String>,
}

/// Parsed Info.plist data from an IPA file.
///
/// This struct contains key metadata extracted from the `Info.plist`
/// file within an iOS app bundle in an IPA archive.
///
/// Requires the `"ipa"` feature to be enabled.
///
/// # Examples
///
/// ```
/// use openpack::OpenPack;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # #[cfg(feature = "ipa")]
/// # {
/// let pack = OpenPack::open_default("app.ipa")?;
/// let info = pack.read_info_plist()?;
/// if let Some(bundle_id) = info.bundle_identifier {
///     println!("Bundle ID: {}", bundle_id);
/// }
/// # }
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "ipa")]
#[derive(Debug, Clone)]
pub struct IpaInfoPlist {
    /// The bundle identifier (e.g., "com.example.MyApp").
    pub bundle_identifier: Option<String>,
    /// The bundle version string (e.g., "1.2.3").
    pub bundle_version: Option<String>,
    /// The name of the executable file.
    pub executable: Option<String>,
}

/// Errors that can occur when working with archives.
///
/// This enum covers all failure modes when opening, inspecting, or
/// extracting archive contents. Each variant includes a helpful message
/// explaining what went wrong and how to fix it.
#[derive(Error, Debug)]
pub enum OpenPackError {
    /// The provided configuration is invalid.
    #[error("invalid openpack configuration: {0}. Fix: use positive limits and keep max archive and entry sizes consistent.")]
    InvalidConfig(String),

    /// An I/O error occurred while reading the archive.
    #[error("archive I/O error: {0}. Fix: verify the archive path exists, is readable, and is not concurrently truncated.")]
    Io(#[from] io::Error),

    /// The ZIP format is invalid or unsupported.
    #[error("ZIP parsing error: {0}. Fix: verify the file is a valid ZIP-derived archive and not truncated or encrypted in an unsupported way.")]
    Zip(#[from] zip::result::ZipError),

    /// The archive structure is malformed.
    #[error("invalid archive structure: {0}. Fix: inspect the archive for malformed headers, invalid paths, or unsupported layout.")]
    InvalidArchive(String),

    /// A path traversal attack was detected (Zip Slip).
    #[error("blocked suspicious archive entry `{0}` because it would escape the extraction root. Fix: remove path traversal segments like `../` from the archive.")]
    ZipSlip(String),

    /// The requested entry was not found in the archive.
    #[error("archive entry `{0}` was not found. Fix: inspect `pack.entries()` first and use one of the returned entry names.")]
    MissingEntry(String),

    /// A safety limit was exceeded (size, count, or compression ratio).
    #[error("archive safety limit exceeded: {0}. Fix: raise the relevant `Limits` value only if you trust the archive source.")]
    LimitExceeded(String),

    /// The archive format is not supported (feature not enabled).
    #[error("unsupported archive format. Fix: use a ZIP, JAR, APK, IPA, or CRX file with the matching crate feature enabled.")]
    Unsupported,
}
