//! # The namespace layer: one tree for the app, many mounted backends underneath
//!
//! To a caller there is a single file structure rooted at `/` ([`NsPath`]). Under it is a mount table
//! ([`Namespace`]); each mount is a [`Backend`]. Today the backends are [`HostDir`] (an OS directory, confined with
//! `cap-std`) and [`Memory`] (tests and scratch). The five verbs are the studio's namespace verbs: `walk`, `read`,
//! `write`, `watch`, and `manifest` (here [`Stat`]).
//!
//! **Status: new, and not frozen.** Unlike the engine's locked surface, the [`Backend`] trait and the `ns` types may still change
//! (pre-1.0, a break is a minor bump). The trait stays unfrozen until a read-only content-addressed backend has been written
//! against it, because a trait shaped by two simple backends can bend when a third arrives.
//!
//! **This layer is independent of the content-addressed engine in the rest of this crate.** It uses only `std`,
//! `cap-std`, `unicode-normalization` and its own [`NsError`]; none of the engine's types or dependencies appear in it
//! (a test checks the source). It is built by the `ns` feature.
//!
//! The design in brief:
//!
//! - **Sync, path-addressed, stateless.** No file handle appears in any public trait, so a mount can later be served
//!   across a wire. An async adapter is a later layer.
//! - **A portable name grammar**, checked by one validator for every backend ([`path`]): NFC only, no `.`/`..`, no
//!   Windows reserved names, no case-colliding siblings. A name that is legal on Linux but breaks on a Mac or Windows is
//!   refused here, not discovered later.
//! - **Every read and `stat` returns a [`Version`]**, and `write` takes `if_version`: optimistic concurrency from the
//!   first release, because adding it later would change what a call means. It is exact on [`Memory`] and best effort on
//!   [`HostDir`], and [`Caps`] says which.
//! - **`write` has a closed set of ops** ([`WriteOp`]): `CreateExclusive`, `Replace` (atomic), `Remove`,
//!   `RenameWithinMount`, `MakeDir`. These are arguments to `write`, not new verbs. `append` and `at_offset` are
//!   reserved.
//! - **Confinement is the Kit's; policy is the embedder's.** The Kit refuses `..`, symlinks, reparse points, devices and
//!   multiply-linked files inside the root it is given. It has no notion of which host directories *may* be mounted, or by
//!   whom: the embedder supplies the resolver and the grants.
//! - **Watching** is a hint to re-read ([`Watch`], [`WatchBatch`]): a polling source in the Kit (std only), batches
//!   numbered by `(epoch, generation)` so a gap *is* a rescan, namespace paths only.
//! - **Errors never carry a host path** ([`NsError`]).
//! - **Backends say what they cannot do** ([`Caps`], a typed struct) and the [`conformance`] suite (feature
//!   `conformance`) runs the same cases against every backend, skipping and reporting what a backend declares missing.
//!
//! ```
//! # #[cfg(feature = "ns")] {
//! use std::sync::Arc;
//! use storage_kit::ns::{Access, Memory, Namespace, NsPath, WriteOp};
//!
//! let scratch = Arc::new(Memory::new());
//! let ns = Namespace::builder()
//!     .mount(NsPath::parse("/scratch")?, scratch, Access::ReadWrite)
//!     .build()?;
//!
//! let file = NsPath::parse("/scratch/hello.txt")?;
//! let v1 = ns.write(&file, WriteOp::Replace, b"hello", None)?;
//! let (bytes, version) = ns.read(&file, 1024)?;
//! assert_eq!(bytes, b"hello");
//! assert_eq!(v1, version);
//!
//! // Optimistic concurrency: this succeeds only if nobody changed the file since `version`.
//! ns.write(&file, WriteOp::Replace, b"hello, world", Some(&version))?;
//! assert!(ns.write(&file, WriteOp::Replace, b"stale", Some(&version)).is_err());
//! # }
//! # Ok::<(), storage_kit::ns::NsError>(())
//! ```
//!
//! ## What is not here yet
//!
//! A native (inotify, FSEvents, `ReadDirectoryChangesW`) watcher, a content-addressed (`Cas`) mount, remote mounts,
//! attributes and queries, and a handle-based or streaming read. Each is additive behind the same traits; none is
//! promised by this release.

pub mod backend;
#[cfg(any(feature = "conformance", test))]
pub mod conformance;
pub mod error;
pub mod hostdir;
pub mod memory;
pub mod namespace;
pub mod path;
pub mod watch;

pub use backend::{Access, Backend, Caps, Entry, Kind, Stat, Version, WatchKind, WriteOp};
pub use error::{Feature, InputReason, NsError, NsErrorKind, NsResult};
pub use hostdir::HostDir;
pub use memory::{Memory, MemoryOptions};
pub use namespace::{Namespace, NamespaceBuilder};
pub use path::{
    case_fold_key, is_format_character, validate_name, NsPath, PathReason, MAX_NAME_BYTES,
    MAX_PATH_BYTES, TEMP_PREFIX,
};
pub use watch::{
    Watch, WatchBatch, WatchCursor, WatchOpts, DEFAULT_INTERVAL, DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_TRACKED, MAX_INTERVAL, MIN_INTERVAL, QUEUE_DEPTH,
};
