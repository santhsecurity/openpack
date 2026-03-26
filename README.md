# openpack

Safe archive reader for ZIP-derived container formats. It reads ZIP, JAR, APK, IPA, and CRX files with mandatory guardrails against Zip Slip, zip bombs, and resource exhaustion.

```rust
use openpack::{OpenPack, Limits};

let limits = Limits {
    max_archive_size: 256 * 1024 * 1024,
    max_entry_uncompressed_size: 50 * 1024 * 1024,
    max_total_uncompressed_size: 128 * 1024 * 1024,
    max_entries: 2048,
    max_compression_ratio: 100.0,
};

let pack = OpenPack::open("app.apk", limits).unwrap();

for entry in pack.entries().unwrap() {
    println!("{} ({} bytes)", entry.name, entry.uncompressed_size);
}

let bytes = pack.read_entry("AndroidManifest.xml").unwrap();
```

## Why this exists

Standard archive readers trust the metadata inside the archive. Security tools reading user-supplied APKs or CRXs face Zip Slip path traversal, extreme compression ratio abuse, and excessive file counts. `openpack` enforces strict safety limits, rejects malicious paths like `../etc/passwd`, and prevents reading beyond configured memory boundaries.

## Supported formats

| Format | Features | Internal behavior |
|--------|----------|-------------------|
| Zip | Default | Standard ZIP archive reading. |
| Jar | Default | Treated as standard ZIP. |
| Apk | `apk` feature | Adds `read_android_manifest()` to extract package and version info. |
| Ipa | `ipa` feature | Adds `read_info_plist()` to extract bundle identifiers. |
| Crx | `crx` feature | Parses Chrome extension headers and locates the nested ZIP payload. |

## Feature extraction

Read format-specific metadata directly.

```rust
// Requires the "apk" feature
let pack = OpenPack::open_default("app.apk").unwrap();
let manifest = pack.read_android_manifest().unwrap();
println!("Package: {}", manifest.package);
```

## Configuration

Override safety limits via TOML.

```toml
max_archive_size = 104857600
max_entry_uncompressed_size = 10485760
max_total_uncompressed_size = 52428800
max_entries = 1000
max_compression_ratio = 50.0
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/openpack.svg)](https://crates.io/crates/openpack)
[![docs.rs](https://docs.rs/openpack/badge.svg)](https://docs.rs/openpack)