# Contributing to openpack

## Build setup

- Install Rust via `rustup`.
- Run checks before submitting: `cargo check` and `cargo test`.
- Run with feature sets relevant to your change:
  - `cargo test --features "zip,apk,ipa,crx"`

## What to test

- Add regression tests for every parsing branch.
- Add archive samples for regressions of new formats.
- Keep limits checks explicit and deterministic.

## Pull request checklist

- [ ] New tests for security limits and archive validation paths
- [ ] No panics inside parser paths
- [ ] Manifest parsing and feature-gated behavior covered
