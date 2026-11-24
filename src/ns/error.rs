//! [`NsError`]: the one error type of the namespace layer.
//!
//! **No host path ever appears in an error.** Not in `Display`, not in `Debug`, not in a `source()` chain (there is
//! none). An error carries a [`NsErrorKind`] and, where it helps, the *namespace* path. The underlying OS error is
//! reduced to its `std::io::ErrorKind`: the OS error text, and some libraries' errors, can embed the host path, and a
//! namespace's whole job is that an app never learns where its tree lives on disk.

use std::fmt;
use std::io;

use super::path::{NsPath, PathReason};

/// Why an argument (not the path) was refused. A closed set of typed reasons, so an error can be carried over a wire
/// and rebuilt on the far side without free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InputReason {
    /// Data was given to an operation that takes none (`Remove`, `MakeDir`, `RenameWithinMount`).
    UnexpectedData,
    /// `if_version` was given to an operation that creates (`CreateExclusive`, `MakeDir`): there is nothing to compare.
    VersionOnCreate,
    /// The mount root has no parent: it cannot be removed, renamed, or be the destination of a rename.
    MountRoot,
    /// A directory cannot be moved into itself.
    MoveIntoSelf,
    /// A `ReadOnly` mount nested under a `ReadWrite` one: the parent mount could rename the directory the nested mount
    /// is meant to protect, and write through the new name. Mount read-only trees outside any writable mount.
    ReadOnlyUnderReadWrite,
}

impl InputReason {
    fn describe(self) -> &'static str {
        match self {
            InputReason::UnexpectedData => "this operation takes no data",
            InputReason::VersionOnCreate => "if_version is meaningless for an operation that creates",
            InputReason::MountRoot => "the mount root has no parent and cannot be the target of this operation",
            InputReason::MoveIntoSelf => "a directory cannot be moved into itself",
            InputReason::ReadOnlyUnderReadWrite => {
                "a ReadOnly mount cannot be nested under a ReadWrite mount (the parent could move it and write through the new name)"
            }
        }
    }
}

/// What a backend declared it cannot do. A closed set, like [`InputReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Feature {
    /// `write` at all (the backend is not [`Caps::writable`](super::Caps::writable)).
    Write,
    /// `WriteOp::Replace` (the backend is not [`Caps::atomic_replace`](super::Caps::atomic_replace)).
    AtomicReplace,
    /// `watch` (the backend's watch kind is `None`).
    Watch,
    /// `watch` on a directory that exists only as a mount ancestor: watch the mounts below it.
    WatchOnMountAncestor,
}

impl Feature {
    fn describe(self) -> &'static str {
        match self {
            Feature::Write => "write",
            Feature::AtomicReplace => "atomic replace",
            Feature::Watch => "watch",
            Feature::WatchOnMountAncestor => "watch on a directory that is only a mount ancestor",
        }
    }
}

/// What went wrong, as a value a caller can `match` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NsErrorKind {
    /// The path violates the portable name grammar; the reason says which rule.
    InvalidPath(PathReason),
    /// An argument (not the path) is wrong, e.g. data given to an operation that takes none, or `if_version` given to a
    /// create. The text says which.
    InvalidInput(InputReason),
    /// Nothing is at the path.
    NotFound,
    /// Something is already at the path (or, for a rename, at the destination).
    AlreadyExists,
    /// A directory was needed and a file was found (or a path component is a file).
    NotADirectory,
    /// A file was needed and a directory was found.
    IsADirectory,
    /// A directory could not be removed because it still has entries.
    NotEmpty,
    /// The mount is read-only, the OS refused, or the path is not under a writable mount.
    PermissionDenied,
    /// The entry is not a regular file or a directory (a device, FIFO or socket). The namespace never opens one.
    NotRegular,
    /// The file has more than one hard link, so writing it could change another name's contents. Refused.
    HardLinked,
    /// A symbolic link or reparse point was met. The namespace never follows one; mount the target as its own root if
    /// it is meant to be reachable.
    Escapes,
    /// The name differs only by case from an existing sibling. Refused on every backend: the grammar is portable.
    CaseCollision,
    /// A read was larger than the caller's `max`. Nothing is truncated.
    TooLarge,
    /// `if_version` did not match the current version: someone else changed the entry. Re-read and retry.
    VersionMismatch,
    /// The backend declared this capability false in its [`Caps`](super::Caps).
    Unsupported(Feature),
    /// A rename between two mounts. Do a copy then a remove; it cannot be atomic and the Kit does not pretend it is.
    CrossMount,
    /// Any other I/O failure, reduced to its kind. The detail is deliberately dropped (see the module docs).
    Io(io::ErrorKind),
}

/// An error from a namespace operation. See the [module docs](self) for what it will and will not contain.
#[derive(Clone, PartialEq, Eq)]
pub struct NsError {
    kind: NsErrorKind,
    path: Option<NsPath>,
}

impl NsError {
    /// An error with no path (e.g. one produced while parsing a path).
    pub fn new(kind: NsErrorKind) -> Self {
        NsError { kind, path: None }
    }

    /// An error about `path`, a namespace path.
    pub fn at(kind: NsErrorKind, path: &NsPath) -> Self {
        NsError {
            kind,
            path: Some(path.clone()),
        }
    }

    /// What went wrong.
    pub fn kind(&self) -> NsErrorKind {
        self.kind
    }

    /// The namespace path this is about, if any.
    pub fn path(&self) -> Option<&NsPath> {
        self.path.as_ref()
    }

    /// Attach `path` unless the error already has one.
    #[must_use]
    pub fn or_at(mut self, path: &NsPath) -> Self {
        if self.path.is_none() {
            self.path = Some(path.clone());
        }
        self
    }

    /// Re-root a mount-relative error path under `mount`, so what leaves the `Namespace` is a namespace path.
    #[must_use]
    pub(crate) fn rebased(mut self, mount: &NsPath) -> Self {
        self.path = self.path.and_then(|p| p.rebase(mount).ok());
        self
    }

    /// Reduce a `std::io::Error` to its kind, dropping the message (which can carry a host path).
    pub(crate) fn from_io(err: &io::Error, path: &NsPath) -> Self {
        NsError::at(kind_from_io(err), path)
    }

    /// As [`NsError::from_io`] for a failure that is not about a namespace path (e.g. opening the root).
    pub(crate) fn from_io_nopath(err: &io::Error) -> Self {
        NsError::new(kind_from_io(err))
    }
}

pub(crate) fn kind_from_io(err: &io::Error) -> NsErrorKind {
    use io::ErrorKind as K;
    match err.kind() {
        K::NotFound => NsErrorKind::NotFound,
        K::AlreadyExists => NsErrorKind::AlreadyExists,
        K::PermissionDenied => NsErrorKind::PermissionDenied,
        K::NotADirectory => NsErrorKind::NotADirectory,
        K::IsADirectory => NsErrorKind::IsADirectory,
        K::DirectoryNotEmpty => NsErrorKind::NotEmpty,
        other => NsErrorKind::Io(other),
    }
}

impl fmt::Display for NsErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NsErrorKind::InvalidPath(r) => write!(f, "invalid path: {}", r.describe()),
            NsErrorKind::InvalidInput(why) => write!(f, "invalid argument: {}", why.describe()),
            NsErrorKind::NotFound => f.write_str("not found"),
            NsErrorKind::AlreadyExists => f.write_str("already exists"),
            NsErrorKind::NotADirectory => f.write_str("not a directory"),
            NsErrorKind::IsADirectory => f.write_str("is a directory"),
            NsErrorKind::NotEmpty => f.write_str("directory not empty (remove its entries first)"),
            NsErrorKind::PermissionDenied => f.write_str("permission denied (read-only mount or no grant)"),
            NsErrorKind::NotRegular => {
                f.write_str("not a regular file or directory (a device, FIFO or socket is never opened)")
            }
            NsErrorKind::HardLinked => {
                f.write_str("file has more than one hard link (refused: a write could change another name)")
            }
            NsErrorKind::Escapes => f.write_str(
                "a symbolic link or reparse point was met (never followed; mount its target as its own root instead)",
            ),
            NsErrorKind::CaseCollision => {
                f.write_str("name differs only by case from an existing sibling (pick a distinct name)")
            }
            NsErrorKind::TooLarge => f.write_str("larger than the requested maximum (raise `max` or stream elsewhere)"),
            NsErrorKind::VersionMismatch => {
                f.write_str("version mismatch: the entry changed since it was read (re-read and retry)")
            }
            NsErrorKind::Unsupported(what) => write!(f, "unsupported by this backend: {}", what.describe()),
            NsErrorKind::CrossMount => {
                f.write_str("rename across mounts is not atomic and not done (copy, then remove)")
            }
            NsErrorKind::Io(k) => write!(f, "I/O error ({k})"),
        }
    }
}

impl fmt::Display for NsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(p) => write!(f, "{}: {}", p, self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

impl fmt::Debug for NsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NsError")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .finish()
    }
}

impl std::error::Error for NsError {}

/// Shorthand used across the layer.
pub type NsResult<T> = Result<T, NsError>;
