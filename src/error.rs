//! Error type for Storage Kit — covers both the content-addressed storage
//! engine (`addressing`, `fragment`, `store`) and the transport `backend`
//! layer. Merged 2026-08-23 when the engine relocated here from
//! `bitchain` (design decision): the variants below are
//! the union of the old `bitchain::BitchainError` (engine-facing) and this
//! crate's own `StorageError` (backend-facing) — the `Bitchain(#[from] …)`
//! wrapper variant is gone since this crate no longer depends on
//! `bitchain` (the dependency direction inverted: `bitchain` now depends
//! on `storage-kit`, not the other way around).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corrupt pack: {0}")]
    CorruptPack(String),

    #[error("corrupt manifest: {0}")]
    CorruptManifest(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("partition boundary violation: {0}")]
    PartitionBoundary(String),

    /// The format-reservations spec §3.7:
    /// `PartitionStore::open` no longer creates a partition on first use.
    /// Returned when no `partition.json` exists for the requested partition.
    #[error("partition not provisioned: {0}")]
    PartitionNotProvisioned(String),

    /// Spec §3.7: `PartitionStore::create` is the only place a partition
    /// directory is ever created, and it refuses to provision over an
    /// existing record.
    #[error("partition already provisioned: {0}")]
    PartitionAlreadyProvisioned(String),

    #[error("compression: {0}")]
    Compression(String),

    #[error("backend: {0}")]
    Backend(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;
