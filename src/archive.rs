use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "apk")]
use std::str::from_utf8;
use zip::ZipArchive;

use crate::crx::crx_zip_payload_range;
use crate::security::{
    check_entry_limits, enforce_entry_count_limit, entry_meta, reject_duplicate_entry_name,
    validate_entry_name,
};
use crate::types::{ArchiveEntry, ArchiveFormat, Limits, OpenPack, OpenPackError};

impl Limits {
    pub fn strict() -> Self {
        Self {
            max_archive_size: 10 * 1024 * 1024,
            max_entry_uncompressed_size: 2 * 1024 * 1024,
            max_total_uncompressed_size: 20 * 1024 * 1024,
            max_entries: 100,
            max_compression_ratio: 20.0,
        }
    }

    pub fn permissive() -> Self {
        Self {
            max_archive_size: 2 * 1024 * 1024 * 1024,
            max_entry_uncompressed_size: 1024 * 1024 * 1024,
            max_total_uncompressed_size: 4 * 1024 * 1024 * 1024,
            max_entries: 100000,
            max_compression_ratio: 1000.0,
        }
    }

    pub fn from_toml(raw: &str) -> Result<Self, OpenPackError> {
        toml::from_str(raw).map_err(|err| OpenPackError::InvalidConfig(err.to_string()))
    }

    pub fn from_toml_file(path: &Path) -> Result<Self, OpenPackError> {
        let mut file = File::open(path)?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)?;
        Self::from_toml(&raw)
    }

    pub fn builtin() -> Self {
        Self::from_toml(include_str!("../config/limits.toml")).unwrap_or_else(|_| Self::default())
    }
}

impl OpenPack {
    pub fn open<P: AsRef<Path>>(path: P, limits: Limits) -> Result<Self, OpenPackError> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let metadata = file.metadata()?;

        if metadata.len() > limits.max_archive_size {
            return Err(OpenPackError::LimitExceeded("archive too large".into()));
        }

        let bytes = read_archive_bytes(file, metadata.len())?;
        let format = detect_format(&path, &bytes)?;

        Ok(Self {
            path,
            bytes,
            format,
            limits,
        })
    }

    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self, OpenPackError> {
        Self::open(path, Limits::default())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format(&self) -> ArchiveFormat {
        self.format
    }

    #[doc(hidden)]
    pub fn mmap(&self) -> &[u8] {
        &self.bytes
    }

    fn zip_data(&self) -> Result<&[u8], OpenPackError> {
        let range = match self.format {
            ArchiveFormat::Zip | ArchiveFormat::Jar | ArchiveFormat::Apk | ArchiveFormat::Ipa => {
                0..self.bytes.len()
            }
            ArchiveFormat::Crx => crx_zip_payload_range(&self.bytes)?,
        };
        Ok(&self.bytes[range])
    }

    fn open_zip_reader(&self) -> Result<ZipArchive<Cursor<&[u8]>>, OpenPackError> {
        let data = self.zip_data()?;
        Ok(ZipArchive::new(Cursor::new(data))?)
    }

    pub fn entries(&self) -> Result<Vec<ArchiveEntry>, OpenPackError> {
        let mut archive = self.open_zip_reader()?;
        let entry_count = archive.len();
        enforce_entry_count_limit(entry_count, &self.limits)?;

        let mut names = BTreeSet::new();
        let mut entries = Vec::with_capacity(entry_count);
        let mut total_uncompressed = 0u64;

        for i in 0..entry_count {
            let mut file = archive.by_index(i)?;
            let entry = entry_meta(&mut file)?;
            validate_entry_name(&entry.name)?;
            reject_duplicate_entry_name(&mut names, &entry.name)?;
            check_entry_limits(&self.limits, &entry, &mut total_uncompressed)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    pub fn contains(&self, name: &str) -> Result<bool, OpenPackError> {
        validate_entry_name(name)?;
        let mut archive = self.open_zip_reader()?;

        let result = match archive.by_name(name) {
            Ok(file) => {
                let _ = file.size();
                Ok(true)
            }
            Err(zip::result::ZipError::FileNotFound) => Ok(false),
            Err(err) => Err(OpenPackError::from(err)),
        };

        result
    }

    pub fn read_entry(&self, name: &str) -> Result<Vec<u8>, OpenPackError> {
        validate_entry_name(name)?;
        let mut archive = self.open_zip_reader()?;
        let mut file = archive.by_name(name)?;
        let entry = entry_meta(&mut file)?;

        if entry.uncompressed_size > self.limits.max_entry_uncompressed_size {
            return Err(OpenPackError::LimitExceeded(format!(
                "entry '{}' exceeds uncompressed size limit",
                name
            )));
        }

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        if data.len() as u64 > self.limits.max_entry_uncompressed_size {
            return Err(OpenPackError::LimitExceeded(format!(
                "entry '{}' decompressed bytes exceed size limit",
                name
            )));
        }

        if crc32fast::hash(&data) != entry.crc {
            return Err(OpenPackError::InvalidArchive(format!(
                "entry '{}' failed CRC32 validation",
                name
            )));
        }

        Ok(data)
    }

    #[cfg(feature = "apk")]
    pub fn read_android_manifest(&self) -> Result<crate::AndroidManifest, OpenPackError> {
        let bytes = self.read_entry("AndroidManifest.xml")?;
        parse_android_manifest(&bytes).ok_or(OpenPackError::InvalidArchive(
            "failed parsing AndroidManifest.xml".into(),
        ))
    }

    #[cfg(feature = "ipa")]
    pub fn read_info_plist(&self) -> Result<crate::IpaInfoPlist, OpenPackError> {
        let entry_name = self
            .entries()?
            .into_iter()
            .find_map(|entry| {
                entry
                    .name
                    .strip_prefix("Payload/")
                    .filter(|inner| inner.ends_with(".app/Info.plist"))
                    .map(|_| entry.name.clone())
            })
            .ok_or_else(|| OpenPackError::MissingEntry("Info.plist".into()))?;

        let bytes = self.read_entry(&entry_name)?;
        let text = String::from_utf8_lossy(&bytes);
        parse_info_plist(&text)
            .ok_or_else(|| OpenPackError::InvalidArchive("failed parsing Info.plist".into()))
    }
}

fn detect_format(path: &Path, bytes: &[u8]) -> Result<ArchiveFormat, OpenPackError> {
    let ext = path
        .extension()
        .and_then(OsStr::to_str)
        .map(|value| value.to_ascii_lowercase());

    let format = match ext.as_deref() {
        Some("jar") => ArchiveFormat::Jar,
        Some("apk") => ArchiveFormat::Apk,
        Some("ipa") => ArchiveFormat::Ipa,
        Some("crx") => ArchiveFormat::Crx,
        Some("zip") => ArchiveFormat::Zip,
        _ if bytes.starts_with(b"Cr24") => ArchiveFormat::Crx,
        _ => ArchiveFormat::Zip,
    };

    #[cfg(not(feature = "crx"))]
    if format == ArchiveFormat::Crx {
        return Err(OpenPackError::Unsupported);
    }

    Ok(format)
}

fn read_archive_bytes(file: File, file_len: u64) -> Result<Arc<[u8]>, OpenPackError> {
    let capacity = usize::try_from(file_len)
        .map_err(|_| OpenPackError::LimitExceeded("archive too large for platform".into()))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut reader = io::BufReader::new(file);
    reader.read_to_end(&mut bytes)?;
    Ok(Arc::from(bytes))
}

#[cfg(feature = "apk")]
fn parse_android_manifest(bytes: &[u8]) -> Option<crate::AndroidManifest> {
    let xml = from_utf8(bytes).ok()?;
    let package = extract_xml_attr(xml, "package")?;
    Some(crate::AndroidManifest {
        package,
        version_name: extract_xml_attr(xml, "versionName"),
        version_code: extract_xml_attr(xml, "versionCode"),
        min_sdk: extract_block_attr(xml, "uses-sdk", "android:minSdkVersion")
            .or_else(|| extract_block_attr(xml, "uses-sdk", "android:targetSdkVersion")),
    })
}

#[cfg(feature = "apk")]
fn extract_xml_attr(xml: &str, attr: &str) -> Option<String> {
    let token = format!(" {}=\"", attr);
    let start = xml.find(&token)? + token.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(feature = "apk")]
fn extract_block_attr(xml: &str, block: &str, attr: &str) -> Option<String> {
    let block_start = xml.find(&format!("<{}", block))?;
    let after_block = &xml[block_start..];
    let token = format!(" {}=\"", attr);
    let start = after_block.find(&token)? + block_start + token.len();
    let value_tail = &xml[start..];
    let end = value_tail.find('"')?;
    Some(value_tail[..end].to_string())
}

#[cfg(feature = "ipa")]
fn parse_info_plist(xml: &str) -> Option<crate::IpaInfoPlist> {
    Some(crate::IpaInfoPlist {
        bundle_identifier: parse_plist_key(xml, "CFBundleIdentifier"),
        bundle_version: parse_plist_key(xml, "CFBundleShortVersionString"),
        executable: parse_plist_key(xml, "CFBundleExecutable"),
    })
}

#[cfg(feature = "ipa")]
fn parse_plist_key(xml: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{}</key>", key);
    let key_pos = xml.find(&marker)?;
    let start =
        xml[key_pos + marker.len()..].find("<string>")? + key_pos + marker.len() + "<string>".len();
    let value_tail = &xml[start..];
    let end = value_tail.find("</string>")?;
    Some(value_tail[..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    struct Scratch {
        _tmp: tempfile::TempDir,
        path: PathBuf,
    }

    impl Scratch {
        fn new(suffix: &str) -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join(format!("archive.{suffix}"));
            Self { _tmp: tmp, path }
        }
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8], CompressionMethod)]) {
        let file = File::create(path).expect("create archive");
        let mut zip = zip::ZipWriter::new(file);
        for (name, data, method) in entries {
            let options = SimpleFileOptions::default().compression_method(*method);
            zip.start_file(name, options).expect("start file");
            zip.write_all(data).expect("write entry");
        }
        zip.finish().expect("finish zip");
    }

    fn write_file(path: &Path, data: &[u8]) {
        std::fs::write(path, data).expect("write file");
    }

    fn write_empty_zip(path: &Path) {
        let file = File::create(path).expect("create archive");
        let zip = zip::ZipWriter::new(file);
        zip.finish().expect("finish zip");
    }

    fn crx_payload(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Cr24");
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[cfg(feature = "crx")]
    fn crx3_payload(header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Cr24");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn loads_limits_from_embedded_toml() {
        let cfg = include_str!("../config/limits.toml");
        let parsed = Limits::from_toml(cfg).expect("valid config");
        assert!(parsed.max_entries > 0);
        assert!(parsed.max_archive_size > 0);
    }

    #[test]
    fn limits_roundtrip_from_file() {
        let fixture = Scratch::new("toml");
        write_file(
            fixture.path.as_path(),
            include_bytes!("../config/limits.toml"),
        );
        let parsed = Limits::from_toml_file(&fixture.path).expect("loaded from file");
        let defaults = Limits::builtin();
        assert_eq!(parsed.max_entries, defaults.max_entries);
        assert_eq!(parsed.max_compression_ratio, defaults.max_compression_ratio);
    }

    #[test]
    fn invalid_limits_are_rejected() {
        let raw = "max_archive_size = \"big\"";
        assert!(Limits::from_toml(raw).is_err());
    }

    #[test]
    fn detects_zip_and_other_extensions() {
        for (name, expected) in [
            ("archive.zip", ArchiveFormat::Zip),
            ("archive.jar", ArchiveFormat::Jar),
            ("archive.apk", ArchiveFormat::Apk),
            ("archive.ipa", ArchiveFormat::Ipa),
        ] {
            let fixture = Scratch::new("detect");
            let path = fixture.path.with_file_name(name);
            write_file(&path, b"PK\x03\x04");
            let pack = OpenPack::open_default(&path).expect("open with extension");
            assert_eq!(pack.format(), expected);
        }
    }

    #[test]
    fn detects_crx_signature_when_enabled() {
        let payload = Scratch::new("format");
        let zip_payload = payload.path.with_extension("zip");
        write_zip(
            &zip_payload,
            &[("a.txt", b"hello", CompressionMethod::Stored)],
        );
        let bytes = std::fs::read(&zip_payload).unwrap();
        let crx_path = payload.path.with_extension("crx");

        #[cfg(feature = "crx")]
        {
            write_file(&crx_path, &crx_payload(&bytes));
            let pack = OpenPack::open_default(&crx_path).expect("open crx");
            assert_eq!(pack.format(), ArchiveFormat::Crx);
            assert!(pack.entries().is_ok());
        }

        #[cfg(not(feature = "crx"))]
        {
            write_file(&crx_path, &crx_payload(&bytes));
            assert!(matches!(
                OpenPack::open_default(&crx_path),
                Err(OpenPackError::Unsupported)
            ));
        }
    }

    #[test]
    fn unknown_extensions_default_to_zip_format() {
        let archive = Scratch::new("mystery.dat");
        write_file(archive.path.as_path(), b"PK\x03\x04");
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.format(), ArchiveFormat::Zip);
    }

    #[test]
    fn opening_missing_file_fails() {
        let scratch = Scratch::new("missing.zip");
        assert!(OpenPack::open_default(scratch.path).is_err());
    }

    #[test]
    fn open_enforces_archive_size_limit() {
        let path = Scratch::new("big.zip");
        write_file(path.path.as_path(), &vec![0u8; 256]);
        let limits = Limits {
            max_archive_size: 1,
            ..Limits::default()
        };
        assert!(matches!(
            OpenPack::open(path.path, limits),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn lists_entries_and_sizes() {
        let archive = Scratch::new("list.zip");
        write_zip(
            &archive.path,
            &[
                ("a", b"one", CompressionMethod::Stored),
                ("b", b"two", CompressionMethod::Stored),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().expect("entries");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| entry.name == "a"));
        assert!(entries.iter().any(|entry| entry.name == "b"));
        assert!(entries.iter().all(|entry| !entry.is_dir));
    }

    #[test]
    fn reads_entry_bytes() {
        let archive = Scratch::new("read.zip");
        write_zip(
            &archive.path,
            &[("read.txt", b"hello-world", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let data = pack.read_entry("read.txt").expect("read");
        assert_eq!(data, b"hello-world");
    }

    #[test]
    fn missing_entry_returns_file_not_found() {
        let archive = Scratch::new("missing-entry.zip");
        write_zip(
            &archive.path,
            &[("present.txt", b"hello", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry("absent.txt"),
            Err(OpenPackError::Zip(zip::result::ZipError::FileNotFound))
        ));
    }

    #[test]
    fn contains_true_and_false() {
        let archive = Scratch::new("contains.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.contains("x").expect("contains x"));
        assert!(!pack.contains("missing").expect("contains missing"));
    }

    #[test]
    fn contains_on_empty_archive_is_false() {
        let archive = Scratch::new("contains-empty.zip");
        write_empty_zip(&archive.path);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(!pack.contains("missing").unwrap());
    }

    #[test]
    fn contains_blocks_traversal() {
        let archive = Scratch::new("contains.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.contains("../x"),
            Err(OpenPackError::ZipSlip(_))
        ));
    }

    #[test]
    fn read_entry_blocks_traversal() {
        let archive = Scratch::new("readbad.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry("../../x"),
            Err(OpenPackError::ZipSlip(_))
        ));
    }

    #[test]
    fn rejects_zip_slip_entry_names() {
        let archive = Scratch::new("zip-slip.zip");
        write_zip(
            &archive.path,
            &[
                ("good.txt", b"ok", CompressionMethod::Stored),
                ("../bad.txt", b"bad", CompressionMethod::Stored),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.entries().is_err());
    }

    #[test]
    fn zip_writer_rejects_duplicate_entry_names() {
        let archive = Scratch::new("dupe.zip");
        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("dup.txt", options).expect("start first");
        zip.write_all(b"one").expect("write first");
        assert!(zip.start_file("dup.txt", options).is_err());
    }

    #[test]
    fn rejects_zip_slip_absolute_path_entries() {
        let archive = Scratch::new("zip-slip-abs.zip");
        write_zip(
            &archive.path,
            &[("/etc/passwd", b"bad", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[test]
    fn rejects_zip_slip_backslash_paths() {
        let archive = Scratch::new("zip-slip-win.zip");
        write_zip(
            &archive.path,
            &[("..\\windows\\system.ini", b"bad", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[test]
    fn rejects_zip_slip_terminal_parent_component() {
        let archive = Scratch::new("zip-slip-parent.zip");
        write_zip(
            &archive.path,
            &[("safe/..", b"x", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
    }

    #[test]
    fn memory_map_is_exposed() {
        let archive = Scratch::new("mmap.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(
            pack.mmap().len(),
            std::fs::metadata(&archive.path).unwrap().len() as usize
        );
    }

    #[test]
    fn read_entry_size_limit_is_enforced() {
        let archive = Scratch::new("limit.zip");
        let payload = vec![b'a'; 64];
        write_zip(
            &archive.path,
            &[("big", payload.as_slice(), CompressionMethod::Stored)],
        );
        let strict = Limits {
            max_entry_uncompressed_size: 4,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.read_entry("big"),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn total_uncompressed_size_limit_is_enforced() {
        let archive = Scratch::new("total.zip");
        let mut entries = vec![];
        for i in 0..10 {
            entries.push((
                format!("file{i}"),
                vec![b'a'; 1024].into_boxed_slice(),
                CompressionMethod::Stored,
            ));
        }

        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        for (name, payload, method) in &entries {
            let options = SimpleFileOptions::default().compression_method(*method);
            zip.start_file(name.as_str(), options).expect("start file");
            zip.write_all(payload.as_ref()).expect("write payload");
        }
        zip.finish().expect("finish");

        let strict = Limits {
            max_total_uncompressed_size: 1024,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn compression_ratio_limit_is_enforced() {
        let archive = Scratch::new("ratio.zip");
        let payload = vec![b'a'; 4 * 1024];
        write_zip(
            &archive.path,
            &[("payload", payload.as_slice(), CompressionMethod::Deflated)],
        );
        let strict = Limits {
            max_compression_ratio: 0.5,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(pack.entries().is_err());
    }

    #[test]
    fn zip_bomb_detection_rejects_high_ratio_payload() {
        let archive = Scratch::new("bomb.zip");
        let payload = vec![b'z'; 256 * 1024];
        write_zip(
            &archive.path,
            &[(
                "payload.bin",
                payload.as_slice(),
                CompressionMethod::Deflated,
            )],
        );
        let strict = Limits {
            max_compression_ratio: 2.0,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn entry_limit_is_enforced() {
        let archive = Scratch::new("entries.zip");
        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        for i in 0..50 {
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zip.start_file(format!("item{i}"), options).expect("start");
            zip.write_all(b"x").expect("write");
        }
        zip.finish().expect("finish");

        let strict = Limits {
            max_entries: 10,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn list_is_stable_over_multiple_calls() {
        let archive = Scratch::new("stable.zip");
        write_zip(&archive.path, &[("a", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.entries().unwrap().len(), 1);
        assert_eq!(pack.entries().unwrap().len(), 1);
    }

    #[test]
    fn reads_entries_multiple_times() {
        let archive = Scratch::new("twice.zip");
        write_zip(&archive.path, &[("a", b"v", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let first = pack.read_entry("a").expect("first");
        let second = pack.read_entry("a").expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn supports_junit_entry_names() {
        let archive = Scratch::new("names.zip");
        write_zip(
            &archive.path,
            &[
                ("dir/file.txt", b"a", CompressionMethod::Stored),
                ("dir2/file2.txt", b"b", CompressionMethod::Stored),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().expect("entries");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn detects_path_component_parents_with_dotdot() {
        let archive = Scratch::new("dotzip.zip");
        write_zip(
            &archive.path,
            &[("a/../b.txt", b"x", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.entries().is_err());
    }

    #[test]
    fn path_api_returns_original_path() {
        let archive = Scratch::new("path.zip");
        write_zip(&archive.path, &[("a", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.path(), archive.path);
    }

    #[test]
    fn reads_entry_after_listing() {
        let archive = Scratch::new("after-list.zip");
        write_zip(
            &archive.path,
            &[("readme", b"abc", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.entries().unwrap().len(), 1);
        assert_eq!(pack.read_entry("readme").unwrap(), b"abc");
    }

    #[test]
    fn directory_entries_are_reported_as_directories() {
        let archive = Scratch::new("dirs.zip");
        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.add_directory("nested/", options).expect("dir");
        zip.start_file("nested/file.txt", options).expect("file");
        zip.write_all(b"content").expect("write");
        zip.finish().expect("finish");

        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().unwrap();
        assert!(entries
            .iter()
            .any(|entry| entry.name == "nested/" && entry.is_dir));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "nested/file.txt" && !entry.is_dir));
    }

    #[test]
    fn empty_archives_are_supported() {
        let archive = Scratch::new("empty.zip");
        write_empty_zip(&archive.path);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().expect("entries");
        assert!(entries.is_empty());
    }

    #[test]
    fn empty_archives_report_missing_entries() {
        let archive = Scratch::new("empty-read.zip");
        write_empty_zip(&archive.path);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry("missing.txt"),
            Err(OpenPackError::Zip(zip::result::ZipError::FileNotFound))
        ));
    }

    #[test]
    fn builtin_limits_match_positive_defaults() {
        let limits = Limits::builtin();
        assert!(limits.max_archive_size > 0);
        assert!(limits.max_total_uncompressed_size >= limits.max_entry_uncompressed_size);
        assert!(limits.max_compression_ratio >= 1.0);
    }

    #[test]
    fn open_default_uses_standard_limits() {
        let archive = Scratch::new("default-limits.zip");
        write_zip(
            &archive.path,
            &[("hello.txt", b"hello", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.entries().unwrap().len(), 1);
        assert_eq!(pack.format(), ArchiveFormat::Zip);
    }

    #[test]
    fn corrupted_zip_is_rejected() {
        let archive = Scratch::new("corrupted.zip");
        write_file(
            &archive.path,
            b"PK\x03\x04this-is-not-a-valid-central-directory",
        );
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::Zip(_))
        ));
    }

    #[test]
    fn non_archive_bytes_fail_zip_parsing() {
        let archive = Scratch::new("plain.zip");
        write_file(&archive.path, b"not-a-zip");
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::Zip(_))
        ));
    }

    #[test]
    fn nested_archives_can_be_read_via_inner_entry() {
        let inner = Scratch::new("inner.zip");
        write_zip(
            &inner.path,
            &[("inner.txt", b"nested-data", CompressionMethod::Stored)],
        );
        let inner_bytes = std::fs::read(&inner.path).expect("read inner");

        let outer = Scratch::new("outer.zip");
        write_zip(
            &outer.path,
            &[(
                "nested/inner.zip",
                inner_bytes.as_slice(),
                CompressionMethod::Stored,
            )],
        );

        let outer_pack = OpenPack::open_default(&outer.path).expect("open outer");
        let nested_bytes = outer_pack
            .read_entry("nested/inner.zip")
            .expect("inner bytes");
        let extracted = outer.path.with_file_name("extracted-inner.zip");
        write_file(&extracted, &nested_bytes);

        let inner_pack = OpenPack::open_default(&extracted).expect("open nested archive");
        assert_eq!(inner_pack.read_entry("inner.txt").unwrap(), b"nested-data");
    }

    #[cfg(feature = "crx")]
    #[test]
    fn crx_header_too_short_is_rejected() {
        let archive = Scratch::new("short.crx");
        write_file(&archive.path, b"Cr24\x02\x00");
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[cfg(feature = "crx")]
    #[test]
    fn crx_invalid_magic_is_rejected() {
        let archive = Scratch::new("badmagic.crx");
        let mut bytes = crx_payload(b"PK\x03\x04");
        bytes[0..4].copy_from_slice(b"Bad!");
        write_file(&archive.path, &bytes);
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[cfg(feature = "crx")]
    #[test]
    fn crx_unsupported_version_is_rejected() {
        let archive = Scratch::new("badversion.crx");
        let mut bytes = crx_payload(b"PK\x03\x04");
        bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
        write_file(&archive.path, &bytes);
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[cfg(feature = "crx")]
    #[test]
    fn crx_invalid_header_lengths_are_rejected() {
        let archive = Scratch::new("badlengths.crx");
        let mut bytes = crx_payload(b"PK\x03\x04");
        bytes[8..12].copy_from_slice(&100u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&100u32.to_le_bytes());
        write_file(&archive.path, &bytes);
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[cfg(feature = "crx")]
    #[test]
    fn crx_header_overflow_is_rejected_without_panicking() {
        let archive = Scratch::new("overflow.crx");
        let mut bytes = crx_payload(b"PK\x03\x04");
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        write_file(&archive.path, &bytes);
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[cfg(feature = "crx")]
    #[test]
    fn crx3_payloads_are_supported() {
        let archive = Scratch::new("crx3.zip");
        write_zip(&archive.path, &[("x", b"hello", CompressionMethod::Stored)]);
        let payload = std::fs::read(&archive.path).expect("read payload");
        let crx = Scratch::new("crx3.crx");
        write_file(&crx.path, &crx3_payload(&[1, 2, 3], &payload));

        let pack = OpenPack::open_default(&crx.path).expect("open crx3");
        assert_eq!(pack.format(), ArchiveFormat::Crx);
        assert_eq!(pack.read_entry("x").expect("entry"), b"hello");
    }

    #[cfg(feature = "apk")]
    #[test]
    fn parse_android_manifest() {
        let archive = Scratch::new("app.apk");
        let manifest = r#"<manifest package="com.example.app" versionName="1.2.3" versionCode="5"><uses-sdk android:minSdkVersion="21"/></manifest>"#;
        write_zip(
            &archive.path,
            &[(
                "AndroidManifest.xml",
                manifest.as_bytes(),
                CompressionMethod::Stored,
            )],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let parsed = pack.read_android_manifest().expect("manifest");
        assert_eq!(parsed.package, "com.example.app");
        assert_eq!(parsed.version_name.as_deref(), Some("1.2.3"));
    }

    #[cfg(feature = "ipa")]
    #[test]
    fn parse_ipa_info_plist() {
        let archive = Scratch::new("app.ipa");
        let plist = r#"
        <plist>
          <dict>
            <key>CFBundleIdentifier</key><string>com.example.bundle</string>
            <key>CFBundleExecutable</key><string>Binary</string>
            <key>CFBundleShortVersionString</key><string>4.2.1</string>
          </dict>
        </plist>
        "#;
        write_zip(
            &archive.path,
            &[(
                "Payload/App.app/Info.plist",
                plist.as_bytes(),
                CompressionMethod::Stored,
            )],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let parsed = pack.read_info_plist().expect("plist");
        assert_eq!(
            parsed.bundle_identifier.as_deref(),
            Some("com.example.bundle")
        );
    }

    #[cfg(feature = "crx")]
    #[test]
    fn handles_crx_with_nested_zip() {
        let archive = Scratch::new("crx.zip");
        write_zip(&archive.path, &[("x", b"hello", CompressionMethod::Stored)]);
        let payload = std::fs::read(&archive.path).expect("read payload");
        let crx = Scratch::new("crx");
        let crx_path = crx.path;
        write_file(&crx_path, &crx_payload(&payload));
        let pack = OpenPack::open_default(&crx_path).expect("open crx");
        assert!(pack.entries().is_ok());
    }
}
