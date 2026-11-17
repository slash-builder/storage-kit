//! Backend traits and implementations — the transport layer over this
//! crate's own format-v3 storage engine ([`crate::store`]).
//!
//! **Why this trait is async and [`crate::store::ImmutableStore`] is not:**
//! `ImmutableStore` is deliberately synchronous — it models local, blocking
//! disk I/O, which is the honest cost of the local-first reference backend.
//! `S3Backend`/`HttpBackend` are inherently network-bound; forcing them
//! through a sync trait would mean either blocking a runtime thread on
//! every call or silently spinning up a throwaway executor per call.
//! Neither is acceptable for a Kit meant to be embedded in async host
//! applications (Refraction, Quickring Courier).
//!
//! `AsyncImmutableStore` is the uniform contract all three backends here
//! implement. `LocalBackend` is a thin async wrapper over
//! [`crate::store::PartitionStore`] (dispatched via `spawn_blocking`, since
//! local disk I/O is legitimately blocking); it does **not** reimplement
//! the packfile/fragmentation engine — that lives once, in [`crate::store`]
//! / [`crate::fragment`], and this module only wraps it. (Prior to
//! 2026-08-23 this engine lived in `bitchain` and this crate depended on it
//! cross-org; that dependency inverted when the engine relocated here.)

// `http` and `s3` are feature-gated (A4, standalone-first partitions,
// 2026-09-22): both cloud transports pull in real network-client
// dependencies (`reqwest`, `aws-sdk-s3`/`aws-config`), so a local-only
// consumer can build with `default-features = false` and link neither.
// `local` stays unconditional — it has no cloud dependency and is the
// default, no-network reference backend.
#[cfg(feature = "http")]
pub mod http;
pub mod local;
#[cfg(feature = "s3")]
pub mod s3;

#[cfg(feature = "http")]
pub use http::HttpBackend;
pub use local::LocalBackend;
#[cfg(feature = "s3")]
pub use s3::S3Backend;

use crate::addressing::{Hash, PartitionId};
use crate::error::StorageError;
use async_trait::async_trait;

/// The uniform async storage contract every backend in this crate honors.
/// Mirrors [`crate::store::ImmutableStore`]'s semantics (content-addressed,
/// partition-scoped, hash-verified-on-read, dedup-by-hash-on-write) but
/// over `async fn` so remote transports don't have to fake synchrony.
#[async_trait]
pub trait AsyncImmutableStore: Send + Sync {
    /// Fetch and verify content by hash. Implementations MUST verify the
    /// returned bytes hash to `hash` before returning `Ok`.
    async fn get(&self, hash: &Hash) -> Result<Vec<u8>, StorageError>;

    /// Store `data`, returning its content hash. A `put` for content
    /// already present is a no-op dedup hit, not a duplicate write.
    async fn put(&self, data: &[u8]) -> Result<Hash, StorageError>;

    async fn has(&self, hash: &Hash) -> Result<bool, StorageError>;

    fn partition_id(&self) -> PartitionId;
}
