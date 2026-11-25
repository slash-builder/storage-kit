//! The [`Backend`] trait and the plain-data types that cross it.
//!
//! This is the contract a mount implements. It is **synchronous, path-addressed and stateless**: there is no file handle
//! anywhere in it, because a handle cannot cross a remote boundary and a stateless call can be replayed, logged and
//! served. (An async adapter is a later layer over this, not a change to it.)
//!
//! It is also deliberately *not* the engine's `backend` module: that one is a block transport under the
//! content-addressed store. This one is a file tree. The two share no types.
//!
//! Every path a `Backend` receives is **relative to its mount** (the mount root is `/`). A backend never sees, and never
//! returns, the namespace path it is mounted at; the [`Namespace`](super::Namespace) adds and strips that prefix.

use std::fmt;
use std::time::SystemTime;

use super::error::NsResult;
use super::path::NsPath;
use super::watch::{Watch, WatchOpts};

/// An opaque token for "the state this entry was in when you looked".
///
/// Returned by every `read`, `stat` and `write`; handed back as `if_version` to say "only if nothing changed".
///
/// - **An opaque equality token.** Compare for equality, nothing else: the bytes mean different things per backend and
///   are not stable across versions of this crate. Do not order, parse or persist one across an upgrade.
/// - **Valid only against its own mount.** A version taken from one mount means nothing to another: `Memory` makes
///   every instance's versions distinct, and a `HostDir` version carries the file's device and inode. Offered to the
///   wrong mount it is a `VersionMismatch`, never a match.
/// - **A file's version** changes whenever its content is replaced (`HostDir` derives it from mtime in nanoseconds,
///   size, inode and device; `Memory` from a counter).
/// - **A directory's version** changes **at least whenever its set of entries changes** (an entry added, removed or
///   renamed in it). It may change more often (a backend is free to bump it for other reasons), so use it as "something
///   may have changed, re-list", never as "exactly these entries changed". It does *not* promise to change when an
///   entry's content changes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Version(Box<[u8]>);

impl Version {
    /// Wrap backend-defined bytes. For backend authors.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Version(bytes.into())
    }

    /// The raw token, for logging or for carrying over a wire. Not for interpretation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Version(")?;
        for b in self.0.iter() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// What an entry is. The namespace has exactly two kinds; everything else on a host disk is refused or hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
}

/// One name in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// The component name (inside the portable grammar; never a path).
    pub name: String,
    /// File or directory.
    pub kind: Kind,
}

impl Entry {
    /// An entry. For backend authors.
    pub fn new(name: impl Into<String>, kind: Kind) -> Self {
        Entry {
            name: name.into(),
            kind,
        }
    }
}

/// The `manifest` verb: what is known about one entry.
///
/// `owner`, `mode` and `links` are `Some` only where the backend has them (see [`Caps::owner_mode`]); the caller's
/// policy decides what to do with them. The Kit reports, it does not judge: whether "owned by you and not writable by
/// group or others" is acceptable is the embedder's rule.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stat {
    /// File or directory.
    pub kind: Kind,
    /// Size in bytes for a file; always 0 for a directory (a directory's size is not portable).
    pub size: u64,
    /// The current version of the entry.
    pub version: Version,
    /// Owning user id, where the backend has one (Unix `HostDir`).
    pub owner: Option<u32>,
    /// Permission bits (`0o7777` mask), where the backend has them.
    pub mode: Option<u32>,
    /// Hard-link count, where the backend can tell.
    pub links: Option<u64>,
    /// Last modification time, where known.
    pub modified: Option<SystemTime>,
}

/// An argument of the namespace verb `write`: **not new verbs**. The set is closed per release (`non_exhaustive`).
///
/// `append` and `at_offset` are **reserved and not implemented**: partial writes need a position model that survives a
/// remote hop and a `Cas` commit, and that is not settled. Do not simulate them with read-modify-write.
///
/// Except where noted, every op takes its data from the `data` argument of [`Backend::write`] (empty for ops that take
/// none; non-empty data on those is `InvalidInput`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteOp {
    /// Create a file with `data`; fail with `AlreadyExists` if the name is taken. Not atomic as to *content*: a
    /// concurrent reader can see a partial file. Use `Replace` if readers must never see one.
    CreateExclusive,
    /// Make the file's content exactly `data`, creating it if absent. **Atomic** where [`Caps::atomic_replace`]: a
    /// temporary file in the same directory, `fsync` of the file, `rename` over the target, `fsync` of the directory, so
    /// a reader sees the old content or the new content and a crash leaves one of them. Always yields a new file
    /// (mode `0600` on Unix), so it also resets permission bits. Refused on a directory (`IsADirectory`).
    Replace,
    /// Remove a file or an **empty** directory. Returns the version the entry had.
    Remove,
    /// Rename within this mount. The destination must not exist (`AlreadyExists`) and its name must not case-collide
    /// with a sibling. Across mounts the namespace returns `CrossMount`.
    RenameWithinMount {
        /// The destination, relative to the same mount as the source.
        to: NsPath,
    },
    /// Create one directory (not its parents: that would be `NotFound`). Mode `0700` on Unix.
    MakeDir,
}

/// What a watch is built from. Typed, so a caller can branch on it without parsing a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WatchKind {
    /// Events come from the platform or are delivered synchronously (immediate).
    Native,
    /// The backend re-scans on an interval. Changes are reported on the poll that sees them, never sooner.
    Polling,
    /// The only signal is that the whole root changed (a content-addressed mount's root hash).
    RootChanged,
    /// Not supported; `watch` returns `Unsupported`.
    None,
}

/// What a mount can and cannot do, and where it is weaker than it looks. A typed struct, not strings.
///
/// A capability that is `false` (or [`WatchKind::None`]) means the operation returns
/// [`NsErrorKind::Unsupported`](super::NsErrorKind::Unsupported), and the conformance suite checks that it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Caps {
    /// `write` is available at all.
    pub writable: bool,
    /// `WriteOp::Replace` is atomic (temp file plus rename, or a commit).
    pub atomic_replace: bool,
    /// `if_version` is **exact** (compare-and-swap). `false` means best effort: check, then act, with a window between.
    /// Either way a stale version is detected when the change happened before the check.
    pub exact_if_version: bool,
    /// How `watch` is implemented.
    pub watch: WatchKind,
    /// `Stat::owner` and `Stat::mode` are populated.
    pub owner_mode: bool,
    /// Two names differing only by case can address two entries on this backend. Informational: the portable grammar
    /// refuses to *create* a case-colliding sibling on every backend regardless.
    pub case_sensitive: bool,
    /// Confinement is as strict as the Kit claims everywhere: no symlink or reparse point followed, no hard-link alias
    /// written, identity checks on handles. `false` means a known weaker platform (Windows `HostDir`), so the embedder
    /// must not rely on the strong guarantee; the docs of the backend list what is missing.
    pub strict_confinement: bool,
}

impl Caps {
    /// Every capability off. A starting point for a backend author: set what you provide.
    pub const fn none() -> Self {
        Caps {
            writable: false,
            atomic_replace: false,
            exact_if_version: false,
            watch: WatchKind::None,
            owner_mode: false,
            case_sensitive: false,
            strict_confinement: false,
        }
    }
}

/// A mount's grant, enforced by the [`Namespace`](super::Namespace) on top of the backend's own [`Caps::writable`].
///
/// **The grant belongs to the mount, not to the data behind it.** `ReadOnly` means "nothing written *through this mount*
/// changes anything"; it does not make the host directory read-only. If the embedder also mounts the same directory, or
/// one inside it, read-write somewhere else, or another process writes it, what this mount reads changes. The Kit
/// enforces the grant per mount and the embedder chooses the host directories, so choose them to be disjoint. The one
/// overlap the Kit can see, the *same* directory mounted twice, is refused at `build()`
/// (`InvalidInput(DuplicateRoot)`); a directory mounted together with one of its ancestors or descendants is not
/// detected, because the Kit holds no host paths by design (see [`Backend::root_identity`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Access {
    /// Reads and watches only; every write is `PermissionDenied`.
    ReadOnly,
    /// Reads, watches and writes.
    ReadWrite,
}

/// A mount: a file tree behind one root, addressed by path.
///
/// Implementations must enforce the portable name grammar (it comes for free from [`NsPath`], and any name read back
/// from the backing store goes through [`validate_name`](super::validate_name)), must refuse to create a name that
/// case-folds to an existing sibling (`CaseCollision`), and must return `Unsupported` for anything their [`Caps`] say
/// they cannot do. The [`conformance`](super::conformance) suite checks all of it.
///
/// **This trait is not frozen** (see the [module docs](super)). New methods arrive with a default body, so an existing
/// implementation keeps compiling and behaves as if the new capability were absent; [`Backend::root_identity`] was added
/// that way. A method without a default would be a breaking change and a minor bump while pre-1.0.
pub trait Backend: Send + Sync {
    /// What this mount can do. Cheap; may be called often.
    fn caps(&self) -> Caps;

    /// Which host directory this mount is rooted at, as `(device, inode)` (Windows: volume serial number and file
    /// index), or `None` if the backend is not over a host directory or cannot tell. **Default `None`.**
    ///
    /// [`NamespaceBuilder::build`](super::NamespaceBuilder::build) uses it for one check: two mounts that report the
    /// same identity are refused (`InvalidInput(DuplicateRoot)`), because access is enforced per mount and two mounts of
    /// one directory would let a write through one change what the other, perhaps read-only, mount reads.
    ///
    /// What this does **not** detect: a directory mounted together with an ancestor or a descendant of it (it needs
    /// host paths, which the Kit does not keep), two mounts of a backend that returns `None`, or an identity that
    /// differs because the same directory was reached through two different hard-linked or bind-mounted views. Only a
    /// backend over a real host directory should return `Some`; its value must not change for the life of the backend.
    fn root_identity(&self) -> Option<(u64, u64)> {
        None
    }

    /// List a directory, **sorted by name in UTF-8 byte order** (so `B` sorts before `a`, and `z` before `é`), the whole
    /// directory at once. Only entries that are addressable are listed: names outside the grammar, temporary files, and
    /// anything that is neither a regular file nor a directory are omitted.
    ///
    /// The order is part of the contract (a caller may merge two listings, or page through one by name). Paging of `walk`
    /// itself (a cursor, a page size) is **deferred** until a read-only content-addressed mount has exercised the trait;
    /// it will be added as a separate, additive call.
    fn walk(&self, path: &NsPath) -> NsResult<Vec<Entry>>;

    /// Read a whole file. If it is larger than `max` bytes the result is `TooLarge` and nothing is returned; the
    /// backend reads at most `max + 1` bytes to find that out.
    fn read(&self, path: &NsPath, max: u64) -> NsResult<(Vec<u8>, Version)>;

    /// The `manifest` verb. Works on files and directories (and on `/`).
    fn stat(&self, path: &NsPath) -> NsResult<Stat>;

    /// Apply one [`WriteOp`]. `if_version`: if `Some`, the target must exist (`NotFound` otherwise) and its current
    /// version must equal it (`VersionMismatch` otherwise); it is meaningless for `CreateExclusive` and `MakeDir`
    /// (`InvalidInput`). Exact where [`Caps::exact_if_version`], otherwise check-then-act.
    ///
    /// Returns the version of the entry after the op (for `Remove`, the version it had).
    fn write(
        &self,
        path: &NsPath,
        op: WriteOp,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version>;

    /// Watch a **directory**. A file is `NotADirectory`. See [`Watch`].
    fn watch(&self, path: &NsPath, opts: WatchOpts) -> NsResult<Watch>;
}
