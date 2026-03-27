use std::collections::BTreeSet;
use std::path::{Component, Path};

use percent_encoding::percent_decode_str;
use zip::read::ZipFile;

use crate::types::{ArchiveEntry, Limits, OpenPackError};

pub(crate) fn check_entry_limits(
    limits: &Limits,
    entry: &ArchiveEntry,
    total_uncompressed: &mut u64,
) -> Result<(), OpenPackError> {
    if !entry.is_dir {
        if entry.uncompressed_size > limits.max_entry_uncompressed_size {
            return Err(OpenPackError::LimitExceeded(format!(
                "entry '{}' exceeds uncompressed size limit",
                entry.name
            )));
        }

        let ratio = if entry.compressed_size == 0 {
            if entry.uncompressed_size == 0 {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            entry.uncompressed_size as f64 / entry.compressed_size as f64
        };

        if ratio > limits.max_compression_ratio {
            return Err(OpenPackError::LimitExceeded(format!(
                "entry '{}' exceeds compression ratio limit",
                entry.name
            )));
        }

        *total_uncompressed = total_uncompressed.saturating_add(entry.uncompressed_size);
        if *total_uncompressed > limits.max_total_uncompressed_size {
            return Err(OpenPackError::LimitExceeded(
                "total uncompressed size exceeds limit".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn enforce_entry_count_limit(
    entry_count: usize,
    limits: &Limits,
) -> Result<(), OpenPackError> {
    if entry_count > limits.max_entries {
        Err(OpenPackError::LimitExceeded(
            "entry count exceeds limit".into(),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_entry_name(name: &str) -> Result<(), OpenPackError> {
    if name.is_empty() {
        return Err(OpenPackError::InvalidArchive("empty entry name".into()));
    }

    let decoded = fully_percent_decode(name);

    if name.starts_with('/') || decoded.starts_with('/') {
        return Err(OpenPackError::InvalidArchive("absolute path entry".into()));
    }

    if name.contains('\\') || decoded.contains('\\') {
        return Err(OpenPackError::InvalidArchive(
            "backslash in entry name".into(),
        ));
    }

    if contains_parent_traversal(name) || contains_parent_traversal(&decoded) {
        return Err(OpenPackError::ZipSlip(name.to_string()));
    }

    if Path::new(&decoded)
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(OpenPackError::ZipSlip(name.to_string()));
    }

    Ok(())
}

pub(crate) fn reject_duplicate_entry_name(
    names: &mut BTreeSet<String>,
    name: &str,
) -> Result<(), OpenPackError> {
    if names.insert(name.to_string()) {
        Ok(())
    } else {
        Err(OpenPackError::InvalidArchive("duplicate entry name".into()))
    }
}

pub(crate) fn entry_meta(file: &mut ZipFile<'_>) -> Result<ArchiveEntry, OpenPackError> {
    Ok(ArchiveEntry {
        name: file.name().to_string(),
        compressed_size: file.compressed_size(),
        uncompressed_size: file.size(),
        crc: file.crc32(),
        is_dir: file.is_dir(),
    })
}

fn fully_percent_decode(value: &str) -> String {
    let mut current = value.to_string();
    for _ in 0..4 {
        let decoded = percent_decode_str(&current).decode_utf8_lossy().into_owned();
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

fn contains_parent_traversal(value: &str) -> bool {
    value.contains("../") || value.ends_with("/..") || value == ".."
}
