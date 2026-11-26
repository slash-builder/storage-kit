# Changelog

All notable changes to **storage-kit** (published as `slashbuilder-storage-kit`) will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/slash-builder/storage-kit/compare/v0.2.0...v0.2.1) - 2026-11-26

### Added

- *(ns)* add the namespace layer, one file tree over mounted backends ([#17](https://github.com/slash-builder/storage-kit/pull/17))

### Fixed

- *(ns)* correct HostDir hard-link, FIFO and version docs; fix a Windows test flake ([#18](https://github.com/slash-builder/storage-kit/pull/18))
- *(deps)* update url to 2.5.9 (RUSTSEC-2026-0592) ([#10](https://github.com/slash-builder/storage-kit/pull/10))

### Other

- date the 0.2.0 changelog heading ([#8](https://github.com/slash-builder/storage-kit/pull/8))
- *(deps)* Bump zstd from 0.13.5 to 0.14.4 ([#4](https://github.com/slash-builder/storage-kit/pull/4))

## [0.2.0] - 2026-11-17

This is the first version published on crates.io, under the package name
**`slashbuilder-storage-kit`**. The library name is unchanged: you still write
`use storage_kit::...`.

This Kit is **pre-1.0** and its version numbers say so. `0.2.0` is the
format-v3 engine plus everything additive since the format-v2 engine (`0.1.x`).
Pre-1.0, a breaking change bumps the **minor** version; 1.0 comes only when the
API and its conformance tests are frozen and the maintainer rules it.
`FORMAT_VERSION` (the on-disk layout) is a **separate number** from the crate
version and is never used to pick one. The key-and-encryption seam (format v4)
would be `0.3.0`.

Minimum supported Rust version: **1.88**, set by the AWS SDK dependencies of the
default `s3` feature and verified with `cargo check --all-features --locked`.

### Changed (breaking relative to 0.1.x) — format v3

- **`Context` and `Address` retired.** The address of record is
  `(partition_id, content_id)`; logical identity lives in the reference layer
  of the product above this crate (`bitchain`'s manifest, for one), not the
  engine. Pack/idx layout bumped to `FORMAT_VERSION = 3`.
- **`PartitionStore::create` / `open` split.** `open` no longer creates a
  partition on first use; an unprovisioned partition returns an error. Callers
  must provision explicitly.
- **Partition metadata record** (`partition.json`), including
  `encryption_mode`, and **`PartitionId::for_service`**.
- A conformance case replaced the old tripwire: no free-form logical-identity
  constructor may exist on the public surface other than `PartitionId::derive`,
  which is gated by `PartitionStore::create`'s derivation check.

- **`aws-sdk-s3` is now depended on with `default-features = false`**
  (`default-https-client`, `rt-tokio`, `http-1x` enabled). This drops two of its
  default features: the legacy hyper 0.14 / rustls 0.21 connector, which carries
  open RustSec advisories and is not the connector `aws-config` selects, and
  `sigv4a` (multi-region access point signing, not used by this crate). The
  HTTPS client is the rustls 0.23 one `aws-config` already used. A consumer that
  relied on either dropped feature through this crate's `s3` feature must
  enable it on its own `aws-sdk-s3` dependency.

### Added

- **`s3` and `http` Cargo features**, gating `aws-sdk-s3`/`aws-config` and
  `reqwest` respectively (plus `bytes`, which only `S3Backend` uses).
  `default = ["s3", "http"]`, so existing consumers are unaffected; a
  local-only consumer can set `default-features = false` to link neither cloud
  transport. `cargo tree --no-default-features` shows no `aws-*`, `reqwest` or
  `hyper` crates. The root re-exports of `HttpBackend` and `S3Backend` are
  behind their respective features, with the same names and shapes when the
  feature is enabled.
- **`PartitionId::for_person` / `PartitionId::for_household`**: domain-separated
  convenience constructors (`person:{account_id}`, `household:{hid}`) over
  `PartitionId::derive`. They do not change existing `PartitionId` derivation,
  encoding or the on-disk format. The no-cross-partition-dedup rule (shared
  content is a copy into the household partition, wrapped per member above this
  crate) is documented at the crate root.

### Frozen — interface lock, 2026-08-26

The **public surface is locked**: the crate-root re-export block in
`src/lib.rs` is the frozen surface, frozen as a whole (names, signatures, field
shapes, trait method sets and enum variants), together with at least one
CI-enforced conformance test.

- `addressing::{Hash, PartitionId}`, plus the `HASH_LEN` / `PARTITION_ID_LEN`
  layout constants.
- `fragment::{ChunkingProfile, FragmentTree, RootType}` and the verbs
  `build_fragment_tree`, `read_fragment_tree`, `walk_hashes`.
- `store::{ImmutableStore, MutableStore, PartitionStore}` and
  `list_partitions`. The four-method `ImmutableStore`
  (`get`/`has`/`put`/`partition_id`) is frozen so other crates can compose it
  rather than fork it.
- `backend::{AsyncImmutableStore, LocalBackend, S3Backend, HttpBackend}`.
- `error::{Result, StorageError}` and the `FORMAT_VERSION` constant.

**Behaviour frozen alongside the shape:** identical bytes address identically
within a partition (`put` dedups, and its returned address agrees with
`Hash::of`); `get` verifies the BLAKE3 digest on every read and fails rather
than return corrupt bytes; `build_fragment_tree` / `read_fragment_tree`
round-trip exactly; and every hash `walk_hashes` reaches is resident in the
store.

**Not frozen, explicitly:** `store::packfile`'s writer/reader API (`PackWriter`,
`Codec`, `EntryMeta`, `SealedLocation`, `encode`/`decode`, `get_at`,
`read_index`/`write_index`, `rebuild_index_entries`, `verify_trailer`). The
module stays public so the on-disk format is inspectable, and its *format*
constants (`PACK_MAGIC`, `IDX_MAGIC`, `FORMAT_VERSION`, and the `*_LEN` layout
constants) carry the freeze as wire format, but the API around them is
implementation and may change in a minor release. Compose `ImmutableStore`
instead.

**Lock gate:** `tests/conformance.rs` is an integration test, so it links
`storage-kit` as an external crate, and it imports the frozen
`spec_kit::conformance::{Case, run_suite}` harness from
`slashbuilder-spec-kit`. Its imports are deliberately flat
(`use storage_kit::{…}` only, no module paths): if a future case cannot be
written against the root re-exports alone, the frozen surface is incomplete and
`lib.rs` is what gets fixed.

### Changed — before 0.2.0

- The crate-root re-exports include the `fragment` verbs (`build_fragment_tree`,
  `read_fragment_tree`, `walk_hashes`) and `store::list_partitions`. They were
  reachable only through module paths, which left the "frozen surface"
  ambiguous. Additive; nothing was removed.
- `src/lib.rs` documents the freeze boundary explicitly, including that this
  crate deliberately owns **no** manifest type.

### Added — the engine, as of 0.1.x

- The v2 content-addressing engine, relocated here from `slash-builder/bitchain`
  as a location fix, not a shape change. The dependency direction inverted: this
  crate does not depend on `bitchain`; `bitchain` depends on it.
- `addressing`: BLAKE3 `Hash` and `PartitionId`, with hex encode/decode
  throughout.
- `fragment`: `ChunkingProfile` (fixed-size and FastCDC), recursive
  fragmentation with a fixed 1024-child fanout, and the `build_fragment_tree` /
  `read_fragment_tree` / `walk_hashes` verbs.
- `store`: the `ImmutableStore` / `MutableStore` traits and `PartitionStore`,
  the reference local-filesystem packfile implementation, with per-partition
  dedup, seal-at-cap and `list_partitions` discovery.
- `store::packfile`: the Zstd-compressed packfile and index format, with hash
  verification on read.
- `backend`: async transport wrappers (`LocalBackend`, `S3Backend`,
  `HttpBackend`) over `AsyncImmutableStore`, for hosts needing non-blocking I/O.
- `tests/conformance.rs`: a CI-enforced conformance gate with cases for
  round-trip, content-address determinism, the on-disk integrity gate,
  fragment-tree round-trip, and GC reachability plus partition discovery.

### Notes

- **This crate owns no `Manifest`.** The manifest schema lives in the `bitchain`
  product, and `bitchain-volume` keeps a distinct flat manifest shape over the
  same engine. Two products, two manifest formats, one storage engine.
- **v1 (SHA-256) is not read by this crate.** A legacy read path, if one is
  ever needed, is a CLI-level decision in the product above.

[Unreleased]: https://github.com/slash-builder/storage-kit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/slash-builder/storage-kit/commits/main
