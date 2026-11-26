//! # Storage Kit — bitchain's content-addressed storage engine (format v3)
//!
//! Content-addressed binary storage: BLAKE3 `(partition_id, content_id)`
//! addressing, recursive fragmentation (fixed 1024-child fanout),
//! Zstd-compressed packfiles, per-partition dedup, plus the async transport
//! `backend` layer (local/S3/HTTP). Locked by design decision;
//! relocated here from `slash-builder/bitchain` 2026-08-23 per
//! a follow-up design decision that this was a *location* defect, not a
//! *shape* defect.
//!
//! Layering:
//! - [`addressing`] — `Hash`, `PartitionId`
//! - [`fragment`] — chunking + the leaf/list-node recursive tree
//! - [`store`] — the [`store::ImmutableStore`]/[`store::MutableStore`]
//!   traits and the reference local-filesystem packfile implementation
//!   ([`store::PartitionStore`])
//! - [`backend`] — async transport wrappers (`LocalBackend`, `S3Backend`,
//!   `HttpBackend`) over the same content-addressed contract, for host
//!   applications that need non-blocking I/O
//!
//! `bitchain` (`slash-builder/bitchain`) is this crate's first consumer: it
//! depends on `storage-kit` for the engine and keeps only the CLI command
//! surface, the manifest protocol format, and GC. **This crate does not
//! depend on `bitchain`** — the dependency direction inverted with this
//! relocation; `Manifest`/`ManifestEntry` (the v2 manifest schema) stay in
//! `bitchain`, not here.
//!
//! **v1 is not read by this crate.** Format v3 is the primary surface; a
//! `--legacy` v1 read path is a bitchain-CLI-level decision, not this
//! crate's concern.
//!
//! ## The namespace layer (`ns` feature, additive)
//!
//! [`ns`] is a second, independent layer: one path-addressed file tree over mounted backends (an OS directory confined
//! with `cap-std`, an in-memory tree), with versions, atomic replace and a polling watcher. It shares no types or
//! dependencies with the content-addressed engine below and is not part of the frozen surface described next.
//!
//! ## Frozen public surface (interface lock, 2026-08-26)
//!
//! **The root re-export block below *is* the frozen surface.** Names, signatures,
//! field shapes, trait method sets, and enum variants are all locked;
//! breaking any of them requires a design decision, not a patch, and
//! (this crate is pre-1.0) bumps the **minor** version (the commit title says so, and release-plz carries it into `CHANGELOG.md`).
//!
//! Three rules make "frozen" mean one unambiguous thing:
//!
//! 1. **The root re-exports are complete.** A consumer must never have to
//!    reach through a module path to use the locked engine. If it is part
//!    of the contract it is re-exported here; the `tests/conformance.rs`
//!    suite is required to compile against the root re-exports alone. If
//!    a case cannot be written that way, this block is what gets fixed.
//!    As of 2026-09-22 (A4, standalone-first partitions), [`HttpBackend`]
//!    and [`S3Backend`] are re-exported behind the `http`/`s3` Cargo
//!    features respectively — still frozen names/shapes when the feature
//!    is enabled, just not unconditionally compiled. The same holds for
//!    the [`ns`] module (feature `ns`): additive, and outside the frozen
//!    engine surface described here. `default = ["s3", "http", "ns"]`
//!    means every consumer that hasn't opted out with
//!    `default-features = false` sees the engine unchanged (and gains
//!    the `ns` module and its three small direct dependencies).
//! 2. **Being re-exported here is necessary but not sufficient.** Until
//!    2026-09-23 `Context` and `Address` were re-exported while held
//!    explicitly outside the freeze pending a ruling — see "`Context` and
//!    `Address` are retired" below for how that resolved. Nothing is held
//!    out of the freeze silently; a future exception would be named here
//!    the same way.
//! 3. **Not everything public is frozen.** [`store::packfile`] is public
//!    because the on-disk format is inspectable, but only its *format*
//!    constants ([`store::packfile::PACK_MAGIC`],
//!    [`store::packfile::IDX_MAGIC`], [`store::packfile::FORMAT_VERSION`],
//!    and the `*_LEN` layout constants) carry the freeze — those are wire
//!    format and change only with [`FORMAT_VERSION`]. Its writer/reader
//!    API (`PackWriter`, `encode`/`decode`, `read_index`, …) is
//!    **implementation, explicitly outside the lock**, and may change in a
//!    minor release. Bind to [`ImmutableStore`] instead.
//!
//! ### `Context` and `Address` are retired, not provisional (2026-09-23)
//!
//! The 2026-06 storage lock named **`(hash, context)` addressing** as a
//! pillar of the format. Two independent 2026-09-23 rulings —
//! the design and security reviews', reached from different seats
//! and converging on the same answer — retire it: `storage_kit` addresses
//! by `(partition_id, content_id)` and knows nothing of logical identity.
//! The 2026-06 lock's `(hash, context)` address is satisfied across two
//! layers, not one: **the engine** holds the hash and deduplicates on it
//! alone — which is exactly what the lock's own clause *"same bytes,
//! different contexts = same payload deduplicated under one hash"*
//! requires — and **the product's manifest** holds the context, per
//! reference, beside the path (`bitchain`'s `ManifestEntry`, which
//! `bitchain` now owns byte-for-byte). Re-introducing a context field into
//! the pack entry would make identical bytes store twice, which the lock
//! forbids, and would place an open-vocabulary opaque identifier in a
//! cleartext replicated header, which the key design forbids.
//!
//! `Context` and `Address` no longer exist in this crate; the
//! `Address`-vs-`Hash` typing of [`FragmentTree::root`] is gone with them —
//! `tree.root` is a bare [`struct@Hash`]. The "internal fragmentation nodes are
//! anonymous" rule [`fragment`] used to state in terms of `Context` is gone
//! too: there is no longer a context for an internal node to be anonymous
//! *relative to*. See
//! `storage-addressing-hash-context-ruling-2026-09-23.md` and
//! `storage-addressing-hash-context-ruling-security-2026-09-23.md` for the
//! full rulings.
//!
//! `tests/conformance.rs`'s former "every address is anonymous" tripwire is
//! replaced, not merely deleted — per both rulings, that is a condition of
//! this retirement, not optional — by three cases asserting the property
//! directly: same-bytes-one-partition dedup to exactly one physical entry,
//! no unauthenticated caller-supplied value in any cleartext header, and no
//! free-form logical-identity constructor on the public surface other than
//! [`PartitionId`], whose use is gated by [`PartitionStore::create`]'s
//! derivation check against the closed `subject.kind` vocabulary.
//!
//! **This crate deliberately owns no manifest type.** The v2
//! `Manifest`/`ManifestEntry` schema lives in `bitchain`, and
//! `bitchain-volume`'s `bcv-cas` keeps its own distinct flat manifest
//! shape over the same engine (dependency inversion, re-affirmed 2026-08-26).
//! Two products, two manifest formats, one storage engine — that is the
//! intended factoring, and it is why a kit-owned `Manifest` would be
//! wrong. Both manifest formats are wire formats and are governed by their
//! own products under spec-kit discipline, not here.
//!
//! ## R3 partitions — person, household, and service (additive, 2026-09-22)
//!
//! [`PartitionId::for_person`], [`PartitionId::for_household`], and
//! [`PartitionId::for_service`] are additive convenience constructors
//! matching the "Standalone-first identity" ruling (R3) and its `service:`
//! extension (the format-reservations spec §R.5): **one
//! partition per person, one per household, and one per headless service
//! principal**, derived as `PartitionId::derive(&format!
//! ("person:{account_id}"))` / `PartitionId::derive(&format!
//! ("household:{hid}"))` / `PartitionId::derive(&format!
//! ("service:{service_id}"))` respectively. The `person:`/`household:`/
//! `service:` string prefix is the domain separator — it guarantees these
//! three partitions can never collide even if the raw ids happen to share a
//! value, and it matches the canonical-construction convention
//! [`PartitionId::derive`] already documents. `service` exists because a
//! headless principal needs a partition whose key is not a second wrap of a
//! person's — a division CI job cannot run under a person's principal.
//! Existing `PartitionId` derivation, encoding, and on-disk format are
//! unchanged; these are additive helpers over the same constructor, not a
//! new type or a new addressing scheme.
//!
//! **No-cross-partition-dedup rule (R3, binding):** this crate's dedup is
//! and stays scoped to a single partition ([`store::ImmutableStore::put`]
//! dedups only within the partition it was opened on; no pack ever spans
//! partitions — see [`store`]). Content shared into a household is a
//! **copy** written into the household partition, not a cross-partition
//! reference — callers wrap that copy under a per-member household key
//! above this crate, since this crate has no key-wrapping concept. This
//! crate provides no cross-partition dedup primitive and none should be
//! added without a format-version-bumping ruling.
//!
//! ## Partition provisioning and the metadata record (2026-09-23)
//!
//! [`PartitionStore::open`] **no longer creates a partition on first
//! use.** [`PartitionStore::create`]/[`PartitionStore::open`] split
//! mkdir-on-first-write into an explicit provisioning step
//! ([`error::StorageError::PartitionNotProvisioned`] /
//! [`error::StorageError::PartitionAlreadyProvisioned`]), per
//! the format-reservations spec §3.7 — a behavioural
//! break in a frozen name that the spec states is itself the
//! design decision authorizing it, scoped to exactly this change.
//! [`list_partitions`] reports only provisioned partitions.
//!
//! Every partition now carries a portable [`partition::PartitionRecord`]
//! (`partition.json`, replicated with the data — its `retention_class`
//! and key-epoch state are properties of the bytes) and, at the store
//! root outside every partition directory, a local
//! [`partition::LocalBinding`] (`partitions.local.json`, never
//! replicated). See [`partition`] for the full schema and for the
//! structural mechanism — not a code-review convention — that guarantees
//! retention reaches a person partition identically to a household
//! partition.
//!
//! This work's own `partition.json` schema is unaffected by the pack/idx
//! entry layout landing alongside it in the same v3 bump (see "`Context`
//! and `Address` are retired" above) — `format_version` here follows
//! [`FORMAT_VERSION`] and nothing else about this record's shape changes.

pub mod addressing;
pub mod backend;
pub mod error;
pub mod fragment;
pub mod partition;
pub mod store;

// The namespace layer (docs are on the module itself). Unsafe code is forbidden in this module and everything under it.
#[cfg(feature = "ns")]
#[forbid(unsafe_code)]
pub mod ns;

pub use addressing::{Hash, PartitionId};
#[cfg(feature = "http")]
pub use backend::HttpBackend;
#[cfg(feature = "s3")]
pub use backend::S3Backend;
pub use backend::{AsyncImmutableStore, LocalBackend};
pub use error::{Result, StorageError};
pub use fragment::{
    build_fragment_tree, read_fragment_tree, walk_hashes, ChunkingProfile, FragmentTree, RootType,
};
pub use partition::{
    copy_partition_record, EncryptionMode, LocalBinding, PartitionKey, PartitionRecord,
    PartitionSpec, RetentionClass, Subject, SubjectKind,
};
/// Re-exported so external inspectors (e.g. `tests/conformance.rs`, held to
/// the root-re-exports-only rule above) can reach the on-disk format
/// constants and the raw reader/writer without a `storage_kit::store::…`
/// module path. Only the `*_LEN`/`*_MAGIC`/`FORMAT_VERSION` constants carry
/// the freeze; see [`store::packfile`]'s module docs.
pub use store::packfile;
pub use store::{list_partitions, ImmutableStore, MutableStore, PartitionStore};

/// On-disk storage format version this crate implements. This is **not** the
/// crate's SemVer version (see `Cargo.toml` and the table in `README.md`); the
/// two are independent. See `manifest::FORMAT_VERSION`
/// (in `bitchain`) and `store::packfile::FORMAT_VERSION` for the same
/// constant scoped to each wire artifact — all are required to stay in
/// lockstep.
pub const FORMAT_VERSION: u32 = 3;

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_version_is_three() {
        assert_eq!(FORMAT_VERSION, 3);
    }

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
