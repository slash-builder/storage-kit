//! [`HostDir`]: a mount over an operating-system directory, confined with `cap-std`.
//!
//! # The confinement model: open once, check the handle, never the path
//!
//! `HostDir` holds **one** directory handle, opened once from an ambient path ([`HostDir::open_ambient`]) or handed in
//! ([`HostDir::from_dir`]). Every later operation walks from that handle one component at a time with
//! `openat`-style calls that do **not** follow a final symlink (`O_NOFOLLOW`), and `cap-std` independently refuses any
//! resolution that would leave the root. The host path of the root is never stored, so it cannot be echoed back.
//!
//! What that gives, on **Linux and macOS** (tested on Linux; macOS is compile-checked only so far):
//!
//! - **No symlink is followed, anywhere on the way.** A symlink met as an intermediate directory or as the final entry
//!   is refused with `Escapes`, whether it points outside the root or inside it. The check is the atomic `open`
//!   itself, not a `lstat` beforehand, so swapping a symlink in between a check and a use does not help an attacker:
//!   the worst outcome is an error. (`lstat` is used only afterwards, to choose the *error kind*.)
//! - **Only regular files and directories are ever opened.** A FIFO, socket or device is classified with `lstat`
//!   first and never opened (opening a FIFO can block forever); the open itself is also non-blocking, and the opened
//!   handle's `fstat` is checked again. A hostile swap to a FIFO between the two steps cannot hang a read.
//! - **A write to a file with more than one hard link is refused** (`HardLinked`), as is a `Replace` of one. Today
//!   this is a *belt*: `Replace` renames a new file over the name, so another name for the same inode keeps the old
//!   content either way. The guard is kept for the day an in-place write (`append`, `at_offset`) exists, when it
//!   becomes the thing that stops a write through one name from changing a file reachable by another.
//! - **Names are checked against the portable grammar** and creating a name that case-folds to an existing sibling is
//!   refused (`CaseCollision`) even on a case-sensitive volume. The decision is made on a **listing of the directory**,
//!   comparing the names as stored: an exact match is `AlreadyExists`, a match that differs only by case or by Unicode
//!   normalisation form is `CaseCollision`. `lstat` is never used for it, because on a case-insensitive volume (the
//!   macOS and Windows default) `lstat` answers "exists" to any spelling. Costs one directory listing per create,
//!   replace and rename. A rename that only respells its own entry (`a` to `A`) is allowed; a rename onto itself is not.
//!   Entries whose names are outside the grammar are not listed, so they cannot be named.
//! - Files are created `0600` and directories `0700`.
//!
//! # What it does not guarantee (read before relying on it)
//!
//! - **The root itself.** `open_ambient` follows whatever the OS resolves the given path to, including a symlink in
//!   its last component. Which host directories may be mounted is the embedder's policy and the embedder's resolver;
//!   the Kit confines to the root it is given and has no opinion on whether that root was a good choice. Pass a
//!   canonical path.
//! - **Version checks are best effort.** `if_version` on `HostDir` is check-then-act ([`Caps::exact_if_version`] is
//!   `false`): another process can change the file between the check and the rename. A stale version is caught when
//!   the change happened before the check; a change *during* the window is not.
//! - **`RenameWithinMount`'s "destination must not exist"** is likewise a check followed by a rename, and the rename
//!   replaces a destination that appeared in the window.
//! - **Rights of whoever else can write the directory.** A process that can already write inside the root can cause
//!   `Io` errors and denial of service (for example by filling the disk), and can race the best-effort checks above.
//!   It cannot make the namespace read or write outside the root. It *can* (it is the same user, or has write access)
//!   rename or replace a directory, including one the Kit holds a handle to or one a mount point hangs from, so what a
//!   path names can change between two calls, and a rename of the mount's own root directory by someone outside the
//!   Kit leaves the held handle pointing at the moved directory. That gives them nothing they did not already have, but
//!   the Kit does not defend against it: confinement is "never outside the handle it holds", not "the directory stays
//!   where it was".
//! - **Polling watch** sees a change only on the poll after it happens, and fingerprints `(name, kind, len, mtime,
//!   inode)`: two in-place writes of the same length inside one filesystem timestamp tick can be missed. A watched
//!   tree is held in memory, bounded by [`WatchOpts::max_tracked`](super::WatchOpts::max_tracked) (a bigger tree is
//!   refused at the start, and degrades to a single `rescan` if it grows past it). A recursive scan walks depth first and
//!   opens each subdirectory from its parent's handle (so a scan costs one open per directory, not one per directory per
//!   level), holding one handle per level on the way down: at most [`WatchOpts::max_depth`](super::WatchOpts::max_depth)
//!   plus one (default 64) however wide the tree is. A tree deeper than that is an incomplete scan, handled like
//!   `max_tracked`: refused at the start, one `rescan` if it grows past it. A scan that cannot finish (depth, entries,
//!   descriptors, I/O error) is reported as one `rescan`, not compared as a partial picture.
//! - **Hard-link and alias writes through other names** are only caught by the link count at the moment of the call.
//! - **Access is the mount's, not the directory's.** `HostDir` itself is always writable; whether a mount may write is
//!   the grant the [`Namespace`](super::Namespace) holds ([`Access`](super::Access)), enforced per mount. Two mounts
//!   over directories that overlap share files: a write through a `ReadWrite` mount of `D` changes what a `ReadOnly`
//!   mount of `D/locked` (or of `D` itself) reads, and so does any other process. The embedder chooses the directories
//!   and must keep them disjoint. [`Backend::root_identity`] lets `build()` refuse the same directory mounted twice
//!   (device and inode of the root handle); it **cannot** see an ancestor and a descendant, because the Kit keeps no
//!   host path to compare.
//! - **A recursive watch stops at another filesystem (Unix).** Reads, writes and `walk` through a mount are not
//!   confined to the root's device: a filesystem mounted *inside* the directory is reachable like any subdirectory. The
//!   polling scan is different, by choice. A directory on a different device than the watched one (found by comparing
//!   `st_dev` on the opened handle) is listed as an entry, so a mount appearing or disappearing at that name is
//!   reported as a change to it, but it is **not entered**: nothing beneath it is tracked or reported. Descending into
//!   it would make the scan's cost and memory depend on a filesystem the embedder did not mean to watch (a network or
//!   pseudo filesystem), and its tree can change without the root's mtime moving. A bind mount of the same filesystem
//!   has the same device and is followed like a directory. Windows does not check this (a volume mount point is a
//!   reparse point, refused as far as `std` reports it as a symlink).
//!
//! ## Windows is the weakest platform, and says so
//!
//! It compiles, and it is as strict as `cap-std` and `std` allow, but [`Caps::strict_confinement`] is `false` there and
//! the following are **not** guaranteed:
//!
//! - **Hard links and file identity** come from the by-handle information `cap-std` reads when it opens a file to stat it
//!   (volume serial number, file index, link count), so the hard-link refusal and the identity part of versions work.
//!   This is the least-tested path (it is exercised by CI on Windows and by nothing else); the cheap directory-entry
//!   metadata the watch scan uses carries no identity, so on Windows a polling watch cannot see an atomic replace that
//!   keeps the same size and timestamp.
//! - **Alternate data streams** (`name:stream`): `:` is refused in names, which blocks naming one through this API, but
//!   a stream already on a file is not detected.
//! - **Case-insensitive volumes**: the default NTFS volume is case-insensitive; collisions are still refused by the
//!   grammar, but the volume itself will treat `A` and `a` as one name.
//! - **Reparse points**: symlinks and junctions are refused as far as `std` classifies them as symlinks; other reparse
//!   kinds (cloud placeholders, dedup) are not distinguished.
//! - **Versions** are mtime, size, file index and volume serial number. File timestamps tick coarsely (on the order of
//!   10 ms), so an edit in place that keeps the size and lands in the same tick as the previous one is not told apart;
//!   a replaced *file* (new file index) is. Ownership and mode are not reported. **A matching version can be wrong on
//!   some volumes**, which is why `if_version` is best effort ([`Caps::exact_if_version`] is `false`): **FAT** reuses file
//!   indexes (they come from where the directory entry sits, so a new file can inherit a deleted one's) and stores
//!   timestamps to 2 seconds; **ReFS** file ids are 128 bits and the file index is 64, so two files can share an index.
//!   On those a replaced file of the same size can compare equal and a stale `if_version` be accepted. Directory `fsync` is not available, so
//!   `Replace` is atomic but its durability across a power loss is the OS's.
//!
//! Treat a Windows `HostDir` as "no escape through a path, no more".

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, File, Metadata, OpenOptions};

use super::backend::{Backend, Caps, Entry, Kind, Stat, Version, WatchKind, WriteOp};
use super::error::{InputReason, NsError, NsErrorKind, NsResult};
use super::path::{case_fold_key, validate_name, NsPath, TEMP_PREFIX};
use super::watch::{spawn_poller, Fingerprint, ScanOutcome, Snapshot, Watch, WatchOpts};

#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, OpenOptionsExt};

/// `O_NONBLOCK`, so opening a FIFO that was swapped in after the `lstat` cannot hang. Spelled out because the crate
/// takes no `libc` dependency; only targets whose value is certain are listed, the rest get 0 (no flag), which leaves
/// that one swap race as a hang of a single read rather than a confinement problem.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "s390x",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;
#[cfg(all(
    unix,
    not(any(
        all(
            target_os = "linux",
            any(
                target_arch = "x86",
                target_arch = "x86_64",
                target_arch = "arm",
                target_arch = "aarch64",
                target_arch = "riscv32",
                target_arch = "riscv64",
                target_arch = "loongarch64",
                target_arch = "s390x",
                target_arch = "powerpc",
                target_arch = "powerpc64"
            )
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
const O_NONBLOCK: i32 = 0;

/// Per-platform facts about a file that `std` exposes on Unix only (on stable Rust).
///
/// Every accessor here is total: where the platform cannot say, it answers `None` rather than panicking.
#[cfg(unix)]
mod sys {
    use cap_std::fs::{Dir, Metadata, MetadataExt};

    /// `(device, inode)`: what makes two handles "the same file" on this platform.
    pub fn identity(md: &Metadata) -> Option<(u64, u64)> {
        Some((md.dev(), md.ino()))
    }
    pub fn links(md: &Metadata) -> Option<u64> {
        Some(md.nlink())
    }
    pub fn owner(md: &Metadata) -> Option<u32> {
        Some(md.uid())
    }
    pub fn mode(md: &Metadata) -> Option<u32> {
        Some(md.mode() & 0o7777)
    }
    pub fn scan_inode(md: &Metadata) -> u64 {
        md.ino()
    }
    /// The device (filesystem) an open directory lives on; the recursive scan stops where it changes.
    pub fn device_of(dir: &Dir) -> Option<u64> {
        dir.dir_metadata().ok().map(|md| md.dev())
    }
}

/// Windows: file identity and link count are the by-handle information `cap-std` reads when it opens a file to stat it
/// (volume serial number, file index, link count). A `Metadata` that did **not** come from an open handle (the cheap
/// `DirEntry::metadata` the watch scan uses) does not carry it. `cap-fs-ext`'s `MetadataExt` accessors `expect()` it and
/// panic on such metadata, so they are not used: these go through the `Option` accessors, and "not there" is `None`.
/// A later change that hands the wrong kind of metadata to any of them gets a missing identity, not a crash.
#[cfg(not(unix))]
mod sys {
    use cap_primitives::fs::_WindowsByHandle;
    use cap_std::fs::{Dir, Metadata};

    /// `(volume serial number, file index)`. The file index is 64 bits: on `ReFS`, whose file ids are 128 bits, it is a
    /// truncation and may not be unique (see the module docs).
    pub fn identity(md: &Metadata) -> Option<(u64, u64)> {
        Some((u64::from(md.volume_serial_number()?), md.file_index()?))
    }
    pub fn links(md: &Metadata) -> Option<u64> {
        md.number_of_links().map(u64::from)
    }
    pub fn owner(_: &Metadata) -> Option<u32> {
        None
    }
    pub fn mode(_: &Metadata) -> Option<u32> {
        None
    }
    /// For metadata that may not carry by-handle information (a directory entry's): no identity on Windows.
    pub fn scan_inode(_: &Metadata) -> u64 {
        0
    }
    /// No device boundary is checked on Windows (see the module docs).
    pub fn device_of(_: &Dir) -> Option<u64> {
        None
    }
}

/// A mount over an OS directory. See the [module docs](self) for the guarantees and, as important, the limits.
///
/// ```no_run
/// # #[cfg(feature = "ns")] {
/// use storage_kit::ns::{Backend, HostDir, NsPath, WriteOp};
/// let dir = HostDir::open_ambient("/home/me/.config/myapp")?;
/// let path = NsPath::parse("/apps.toml")?;
/// let v = dir.write(&path, WriteOp::Replace, b"x = 1\n", None)?;
/// let (bytes, _) = dir.read(&path, 1 << 20)?;
/// assert_eq!(bytes, b"x = 1\n");
/// # let _ = v;
/// # }
/// # Ok::<(), storage_kit::ns::NsError>(())
/// ```
pub struct HostDir {
    root: Dir,
    caps: Caps,
    /// `(device, inode)` of the root, read from the handle when it was opened. See [`Backend::root_identity`].
    identity: Option<(u64, u64)>,
}

impl std::fmt::Debug for HostDir {
    // The root's host path is not stored; the capabilities are all there is to show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostDir").field("caps", &self.caps).finish()
    }
}

impl HostDir {
    /// Open `path` as the root. This is the **one** ambient (path-based) open; everything afterwards is relative to the
    /// resulting handle. See the module docs: the OS resolves `path` as it likes (including a final symlink), so the
    /// embedder must give a path it has already decided to trust.
    pub fn open_ambient(path: impl AsRef<Path>) -> NsResult<Self> {
        let dir = Dir::open_ambient_dir(path.as_ref(), ambient_authority())
            .map_err(|e| NsError::from_io_nopath(&e))?;
        Self::checked(dir)
    }

    /// Use an already-open directory as the root (the embedder opened it, e.g. from a granted handle).
    pub fn from_dir(dir: Dir) -> NsResult<Self> {
        Self::checked(dir)
    }

    fn checked(dir: Dir) -> NsResult<Self> {
        // Check the handle, not the path it came from.
        let md = dir
            .dir_metadata()
            .map_err(|e| NsError::from_io_nopath(&e))?;
        if !md.is_dir() {
            return Err(NsError::new(NsErrorKind::NotADirectory));
        }
        let caps = Caps {
            writable: true,
            atomic_replace: true,
            // Best effort, and on Windows weaker than it looks (see "Windows" in the module docs): a file's identity
            // there is its volume serial number and 64-bit file index, and a match can be wrong. FAT reuses file
            // indexes (they derive from the directory entry's position) and keeps 2-second timestamps, so a file
            // replaced by another of the same size can compare equal; ReFS file ids are 128 bits and are truncated to
            // 64, so two files can share an index.
            exact_if_version: false,
            watch: WatchKind::Polling,
            owner_mode: cfg!(unix),
            case_sensitive: probe_case_sensitive(&dir),
            strict_confinement: cfg!(unix),
        };
        let identity = sys::identity(&md);
        Ok(HostDir {
            root: dir,
            caps,
            identity,
        })
    }
}

/// Is the volume under `root` case-sensitive? Looks for an existing entry with a letter in its name and asks for the
/// same entry under swapped case; falls back to the platform's usual default when there is nothing to learn from.
fn probe_case_sensitive(root: &Dir) -> bool {
    let default = cfg!(target_os = "linux");
    let Ok(entries) = root.entries() else {
        return default;
    };
    for entry in entries.flatten().take(64) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let swapped: String = name
            .chars()
            .map(|c| {
                if c.is_lowercase() {
                    c.to_uppercase().next().unwrap_or(c)
                } else if c.is_uppercase() {
                    c.to_lowercase().next().unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();
        if swapped == name {
            continue;
        }
        let Ok(original) = root.symlink_metadata(name) else {
            continue;
        };
        return match root.symlink_metadata(&swapped) {
            // The swapped name resolves to the very same entry: case-insensitive.
            Ok(other) => match (sys::identity(&other), sys::identity(&original)) {
                (Some(a), Some(b)) => a != b,
                // No identity to compare: this entry cannot tell, try another.
                _ => continue,
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(_) => continue,
        };
    }
    default
}

// ---------------------------------------------------------------------------------------------------------------
// Resolution: walk from the root handle, never from a path string.
// ---------------------------------------------------------------------------------------------------------------

/// What the caller wanted at the end of a resolution; only used to pick an error kind after a failure.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Dir,
    File,
}

/// Turn a failed no-follow open into the most useful error kind. This runs *after* the security decision (the open
/// already refused), so a race here can only change which error is reported, never what was opened.
fn explain_open_failure(
    parent: &Dir,
    name: &str,
    err: &io::Error,
    path: &NsPath,
    want: Want,
) -> NsError {
    match parent.symlink_metadata(name) {
        Ok(md) => {
            let ft = md.file_type();
            if ft.is_symlink() {
                NsError::at(NsErrorKind::Escapes, path)
            } else if ft.is_dir() {
                match want {
                    Want::Dir => NsError::from_io(err, path),
                    Want::File => NsError::at(NsErrorKind::IsADirectory, path),
                }
            } else if ft.is_file() {
                match want {
                    Want::Dir => NsError::at(NsErrorKind::NotADirectory, path),
                    Want::File => NsError::from_io(err, path),
                }
            } else {
                NsError::at(NsErrorKind::NotRegular, path)
            }
        }
        Err(_) => NsError::from_io(err, path),
    }
}

/// Open the directory at `path` by walking every component with no-follow opens.
fn open_dir_at(root: &Dir, path: &NsPath) -> NsResult<Dir> {
    let mut current = root.try_clone().map_err(|e| NsError::from_io(&e, path))?;
    for name in path.components() {
        let next = match current.open_dir_nofollow(name) {
            Ok(d) => d,
            Err(e) => return Err(explain_open_failure(&current, name, &e, path, Want::Dir)),
        };
        current = next;
    }
    Ok(current)
}

/// Are these two open handles the same directory? Unknown (no identity on this platform) is "no": the callers treat a
/// different directory as the stricter case.
fn same_directory(a: &Dir, b: &Dir) -> bool {
    match (a.dir_metadata(), b.dir_metadata()) {
        (Ok(x), Ok(y)) => match (sys::identity(&x), sys::identity(&y)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
        _ => false,
    }
}

/// The parent directory handle and final name of `path`. The root has no parent: callers handle it first.
fn open_parent<'p>(root: &Dir, path: &'p NsPath) -> NsResult<(Dir, &'p str)> {
    let name = path
        .file_name()
        .ok_or_else(|| NsError::at(NsErrorKind::InvalidInput(InputReason::MountRoot), path))?;
    let parent = path.parent().unwrap_or_else(NsPath::root);
    Ok((open_dir_at(root, &parent)?, name))
}

/// Classify what `lstat` found. Symlinks are `Escapes`, anything but a file or directory is `NotRegular`.
fn kind_of(md: &Metadata, path: &NsPath) -> NsResult<Kind> {
    let ft = md.file_type();
    if ft.is_symlink() {
        Err(NsError::at(NsErrorKind::Escapes, path))
    } else if ft.is_dir() {
        Ok(Kind::Dir)
    } else if ft.is_file() {
        Ok(Kind::File)
    } else {
        Err(NsError::at(NsErrorKind::NotRegular, path))
    }
}

/// `lstat` the final component. `Ok(None)` if absent.
fn lookup(parent: &Dir, name: &str, path: &NsPath) -> NsResult<Option<(Kind, Metadata)>> {
    match parent.symlink_metadata(name) {
        Ok(md) => Ok(Some((kind_of(&md, path)?, md))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(NsError::from_io(&e, path)),
    }
}

/// Does *anything* exist under this name (a symlink or FIFO counts)?
fn exists_raw(parent: &Dir, name: &str, path: &NsPath) -> NsResult<bool> {
    match parent.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(NsError::from_io(&e, path)),
    }
}

/// Open a regular file for reading, atomically refusing a symlink, and check the handle afterwards.
fn open_regular(parent: &Dir, name: &str, path: &NsPath) -> NsResult<(File, Metadata)> {
    // Classify first (cheap, and keeps a FIFO from ever being opened) ...
    match lookup(parent, name, path)? {
        None => return Err(NsError::at(NsErrorKind::NotFound, path)),
        Some((Kind::Dir, _)) => return Err(NsError::at(NsErrorKind::IsADirectory, path)),
        Some((Kind::File, _)) => {}
    }
    // ... then the open that actually decides, atomic and non-following ...
    let mut opts = OpenOptions::new();
    opts.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    opts.custom_flags(O_NONBLOCK);
    let file = parent
        .open_with(name, &opts)
        .map_err(|e| explain_open_failure(parent, name, &e, path, Want::File))?;
    // ... then check what we actually hold.
    let md = file.metadata().map_err(|e| NsError::from_io(&e, path))?;
    if md.is_dir() {
        return Err(NsError::at(NsErrorKind::IsADirectory, path));
    }
    if !md.is_file() {
        return Err(NsError::at(NsErrorKind::NotRegular, path));
    }
    Ok((file, md))
}

// ---------------------------------------------------------------------------------------------------------------
// Versions and stats
// ---------------------------------------------------------------------------------------------------------------

fn mtime_ns(md: &Metadata) -> u128 {
    md.modified()
        .ok()
        .map(|t| t.into_std())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

fn version_of(md: &Metadata) -> Version {
    let mut bytes = Vec::with_capacity(2 + 16 + 24);
    bytes.extend_from_slice(b"h1");
    bytes.extend_from_slice(&mtime_ns(md).to_le_bytes());
    bytes.extend_from_slice(&md.len().to_le_bytes());
    // Identity is absent only for metadata that did not come from a handle; it then contributes nothing.
    let (device, inode) = sys::identity(md).unwrap_or((0, 0));
    bytes.extend_from_slice(&inode.to_le_bytes());
    bytes.extend_from_slice(&device.to_le_bytes());
    Version::from_bytes(&bytes)
}

fn stat_of(md: &Metadata, kind: Kind) -> Stat {
    Stat {
        kind,
        size: if kind == Kind::File { md.len() } else { 0 },
        version: version_of(md),
        owner: sys::owner(md),
        mode: sys::mode(md),
        links: sys::links(md),
        modified: md.modified().ok().map(|t| t.into_std()),
    }
}

fn check_version(md: &Metadata, if_version: Option<&Version>, path: &NsPath) -> NsResult<()> {
    match if_version {
        Some(v) if *v != version_of(md) => Err(NsError::at(NsErrorKind::VersionMismatch, path)),
        _ => Ok(()),
    }
}

fn refuse_hard_linked(md: &Metadata, path: &NsPath) -> NsResult<()> {
    match sys::links(md) {
        Some(n) if n > 1 => Err(NsError::at(NsErrorKind::HardLinked, path)),
        _ => Ok(()),
    }
}

fn no_data(data: &[u8], path: &NsPath) -> NsResult<()> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(NsError::at(
            NsErrorKind::InvalidInput(InputReason::UnexpectedData),
            path,
        ))
    }
}

fn no_version(if_version: Option<&Version>, path: &NsPath) -> NsResult<()> {
    if if_version.is_none() {
        Ok(())
    } else {
        Err(NsError::at(
            NsErrorKind::InvalidInput(InputReason::VersionOnCreate),
            path,
        ))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Names in a directory
// ---------------------------------------------------------------------------------------------------------------

enum Conflict {
    /// A sibling with exactly this name.
    Same,
    /// A sibling that differs only by case or normalisation form.
    Fold,
}

/// The names in `dir`, as UTF-8 (a name that is not UTF-8 cannot collide with a namespace name). Every kind of entry
/// counts, symlinks and FIFOs included: they occupy the name.
///
/// The collision decision is made on this listing and nowhere else. `lstat` is not used for it: on a case-insensitive
/// volume (the default on macOS and Windows) it answers "exists" for a differently-cased spelling, which would turn a
/// `CaseCollision` into an `AlreadyExists`. The listing carries the names as stored, so exact equality and
/// case-fold equality can be told apart on every platform.
fn list_names(dir: &Dir, path: &NsPath) -> NsResult<Vec<String>> {
    let entries = dir.entries().map_err(|e| NsError::from_io(&e, path))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| NsError::from_io(&e, path))?;
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

/// Look through `names` for a sibling that is, or folds to, `name`. `ignore` is the stored name of the entry being
/// renamed (it does not conflict with itself).
fn conflict_in(names: &[String], name: &str, ignore: Option<&str>) -> Option<Conflict> {
    let key = case_fold_key(name);
    let mut fold = false;
    for existing in names {
        if Some(existing.as_str()) == ignore {
            continue;
        }
        if existing == name {
            return Some(Conflict::Same);
        }
        if case_fold_key(existing) == key {
            fold = true;
        }
    }
    fold.then_some(Conflict::Fold)
}

/// The stored name of the entry that `name` refers to: the exact match if there is one, otherwise the single entry
/// with the same fold key (a case-insensitive volume answering to a different spelling).
fn stored_name<'a>(names: &'a [String], name: &str) -> Option<&'a str> {
    names
        .iter()
        .find(|n| n.as_str() == name)
        .or_else(|| {
            let key = case_fold_key(name);
            names.iter().find(|n| case_fold_key(n) == key)
        })
        .map(String::as_str)
}

fn conflict_error(c: Conflict, path: &NsPath) -> NsError {
    match c {
        Conflict::Same => NsError::at(NsErrorKind::AlreadyExists, path),
        Conflict::Fold => NsError::at(NsErrorKind::CaseCollision, path),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------------------------

fn sync_dir(dir: &Dir) -> io::Result<()> {
    #[cfg(unix)]
    {
        // Not `Dir::into_std_file`: cap-std opens directory handles with O_PATH where it can, and fsync on an O_PATH
        // descriptor is EBADF. Re-opening "." relative to the handle gives a descriptor fsync accepts, and cannot leave
        // the directory.
        dir.open(".")?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Windows cannot open a directory for fsync through std; see the module docs.
        let _ = dir;
        Ok(())
    }
}

fn temp_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("{TEMP_PREFIX}{:x}-{:x}-{:x}", std::process::id(), n, nanos)
}

fn create_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    opts.mode(0o600);
    opts
}

/// Create `name` exclusively, fill it, sync it. On any failure the half-written file is removed.
fn create_filled(parent: &Dir, name: &str, data: &[u8], path: &NsPath) -> NsResult<Metadata> {
    let mut file = parent
        .open_with(name, &create_options())
        .map_err(|e| NsError::from_io(&e, path))?;
    let result = file
        .write_all(data)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.metadata());
    match result {
        Ok(md) => Ok(md),
        Err(e) => {
            drop(file);
            let _ = parent.remove_file(name);
            Err(NsError::from_io(&e, path))
        }
    }
}

impl HostDir {
    fn create_exclusive(
        &self,
        path: &NsPath,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        no_version(if_version, path)?;
        let (parent, name) = open_parent(&self.root, path)?;
        if let Some(c) = conflict_in(&list_names(&parent, path)?, name, None) {
            return Err(conflict_error(c, path));
        }
        // Not in the listing but present anyway (a name the listing could not show): still taken.
        if exists_raw(&parent, name, path)? {
            return Err(NsError::at(NsErrorKind::AlreadyExists, path));
        }
        let md = create_filled(&parent, name, data, path)?;
        sync_dir(&parent).map_err(|e| NsError::from_io(&e, path))?;
        Ok(version_of(&md))
    }

    fn replace(
        &self,
        path: &NsPath,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        let (parent, name) = open_parent(&self.root, path)?;
        // The listing decides case and normalisation clashes (see `list_names`); an exact match is the file we replace.
        if let Some(Conflict::Fold) = conflict_in(&list_names(&parent, path)?, name, None) {
            return Err(NsError::at(NsErrorKind::CaseCollision, path));
        }
        match lookup(&parent, name, path)? {
            Some((Kind::Dir, _)) => return Err(NsError::at(NsErrorKind::IsADirectory, path)),
            Some((Kind::File, md)) => {
                refuse_hard_linked(&md, path)?;
                check_version(&md, if_version, path)?;
            }
            None => {
                if if_version.is_some() {
                    return Err(NsError::at(NsErrorKind::NotFound, path));
                }
            }
        }

        // Temp file in the SAME directory (so the rename cannot cross a filesystem), fsync, rename, fsync the directory.
        let tmp = temp_name();
        let md = create_filled(&parent, &tmp, data, path)?;
        if let Err(e) = parent.rename(&tmp, &parent, name) {
            let _ = parent.remove_file(&tmp);
            return Err(NsError::from_io(&e, path));
        }
        sync_dir(&parent).map_err(|e| NsError::from_io(&e, path))?;
        Ok(version_of(&md))
    }

    fn remove(&self, path: &NsPath, if_version: Option<&Version>) -> NsResult<Version> {
        let (parent, name) = open_parent(&self.root, path)?;
        let Some((kind, md)) = lookup(&parent, name, path)? else {
            return Err(NsError::at(NsErrorKind::NotFound, path));
        };
        check_version(&md, if_version, path)?;
        let result = match kind {
            Kind::File => parent.remove_file(name),
            Kind::Dir => parent.remove_dir(name),
        };
        result.map_err(|e| NsError::from_io(&e, path))?;
        sync_dir(&parent).map_err(|e| NsError::from_io(&e, path))?;
        Ok(version_of(&md))
    }

    fn rename(
        &self,
        from: &NsPath,
        to: &NsPath,
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        if to != from && to.starts_with(from) {
            return Err(NsError::at(
                NsErrorKind::InvalidInput(InputReason::MoveIntoSelf),
                to,
            ));
        }
        let (from_dir, from_name) = open_parent(&self.root, from)?;
        let (to_dir, to_name) = open_parent(&self.root, to)?;
        let Some((_, md)) = lookup(&from_dir, from_name, from)? else {
            return Err(NsError::at(NsErrorKind::NotFound, from));
        };
        check_version(&md, if_version, from)?;
        // A rename onto itself is not a no-op: the name is taken. Only a rename that changes the spelling of its own
        // name (case or normalisation form) may "collide" with the entry being renamed.
        if from == to {
            return Err(NsError::at(NsErrorKind::AlreadyExists, to));
        }
        // The same directory is decided on the two open handles, not on the spelling of their paths. Comparing paths
        // is wrong both ways: on a case-insensitive volume `/A/x` and `/a/X` are one directory (comparing exactly
        // would refuse a respelling as a collision), and on a case-sensitive one `/A` and `/a` can be two (comparing
        // folded would skip the collision check against the other directory's entries and replace one of them).
        let same_dir = same_directory(&from_dir, &to_dir);
        let names = list_names(&to_dir, to)?;
        let ignore = if same_dir {
            stored_name(&names, from_name)
        } else {
            None
        };
        if let Some(c) = conflict_in(&names, to_name, ignore) {
            return Err(conflict_error(c, to));
        }
        from_dir
            .rename(from_name, &to_dir, to_name)
            .map_err(|e| NsError::from_io(&e, to))?;
        sync_dir(&to_dir).map_err(|e| NsError::from_io(&e, to))?;
        if !same_dir {
            sync_dir(&from_dir).map_err(|e| NsError::from_io(&e, from))?;
        }
        match lookup(&to_dir, to_name, to)? {
            Some((_, md)) => Ok(version_of(&md)),
            None => Ok(version_of(&md)),
        }
    }

    fn make_dir(&self, path: &NsPath, if_version: Option<&Version>) -> NsResult<Version> {
        no_version(if_version, path)?;
        let (parent, name) = open_parent(&self.root, path)?;
        if let Some(c) = conflict_in(&list_names(&parent, path)?, name, None) {
            return Err(conflict_error(c, path));
        }
        if exists_raw(&parent, name, path)? {
            return Err(NsError::at(NsErrorKind::AlreadyExists, path));
        }
        #[cfg(unix)]
        let builder = {
            let mut b = DirBuilder::new();
            b.mode(0o700);
            b
        };
        #[cfg(not(unix))]
        let builder = DirBuilder::new();
        parent
            .create_dir_with(name, &builder)
            .map_err(|e| NsError::from_io(&e, path))?;
        sync_dir(&parent).map_err(|e| NsError::from_io(&e, path))?;
        match lookup(&parent, name, path)? {
            Some((_, md)) => Ok(version_of(&md)),
            None => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Polling snapshot
// ---------------------------------------------------------------------------------------------------------------

/// Fingerprint the directory at `path` (and below, if `recursive`).
///
/// The walk is depth first and descends **from the handle it already holds**: a subdirectory is opened with a
/// no-follow open relative to its parent's handle, so reaching a directory `n` levels down costs one open, not `n`
/// (reopening each pending directory from the root made a scan quadratic in depth). The handles of the directories on
/// the way down stay open until the walk returns past them, so a scan holds at most `max_depth + 1` directory handles
/// however wide the tree is (plus the one being listed).
///
/// What ends a scan early, and how:
///
/// - **Deeper than `max_depth`**, or more than `max_tracked` entries, or a failure that is about *us* (descriptors
///   exhausted, an I/O error): [`ScanOutcome::Incomplete`], so no half-picture is compared against the last good one.
///   Never an error, and never a silent skip.
/// - **A subdirectory that has vanished, became a link, or is unreadable** is simply not there (its entries show up as
///   removed).
/// - **Another filesystem** (Unix): a directory on a different device than the watched one is listed as an entry but
///   not entered. See [`WatchOpts::max_depth`](super::WatchOpts::max_depth) and the module docs.
fn scan(
    root: &Dir,
    path: &NsPath,
    recursive: bool,
    max_tracked: usize,
    max_depth: usize,
) -> ScanOutcome {
    let Ok(top) = open_dir_at(root, path) else {
        return ScanOutcome::Unavailable;
    };
    let top_dev = sys::device_of(&top);
    if cfg!(unix) && top_dev.is_none() {
        return ScanOutcome::Unavailable;
    }
    let mut snapshot = Snapshot::new();
    let subdirs = match read_level(&top, path, true, recursive, max_tracked, &mut snapshot) {
        Ok(subdirs) => subdirs,
        Err(outcome) => return outcome,
    };
    // One frame per directory on the way down: its handle, its path, and the subdirectories not yet visited.
    // `stack.len()` is the depth of the directory a frame's child would be (the watched directory is depth 0).
    struct Frame {
        dir: Dir,
        path: NsPath,
        subdirs: Vec<String>,
    }
    let mut stack = vec![Frame {
        dir: top,
        path: path.clone(),
        subdirs,
    }];
    loop {
        let depth = stack.len();
        let Some(frame) = stack.last_mut() else {
            break;
        };
        let Some(name) = frame.subdirs.pop() else {
            stack.pop();
            continue;
        };
        if depth > max_depth {
            return ScanOutcome::Incomplete;
        }
        let Some(child_path) = frame.path.child(&name) else {
            continue;
        };
        let child = match frame.dir.open_dir_nofollow(&name) {
            Ok(d) => d,
            Err(e) => {
                match explain_open_failure(&frame.dir, &name, &e, &child_path, Want::Dir).kind() {
                    NsErrorKind::NotFound
                    | NsErrorKind::NotADirectory
                    | NsErrorKind::Escapes
                    | NsErrorKind::PermissionDenied => continue,
                    _ => return ScanOutcome::Incomplete,
                }
            }
        };
        if let Some(top_dev) = top_dev {
            match sys::device_of(&child) {
                Some(dev) if dev == top_dev => {}
                // Another filesystem is mounted here: the entry is in the snapshot, its contents are not.
                Some(_) => continue,
                None => return ScanOutcome::Incomplete,
            }
        }
        match read_level(
            &child,
            &child_path,
            false,
            recursive,
            max_tracked,
            &mut snapshot,
        ) {
            Ok(subdirs) => stack.push(Frame {
                dir: child,
                path: child_path,
                subdirs,
            }),
            Err(outcome) => return outcome,
        }
    }
    ScanOutcome::Complete(snapshot)
}

/// List one directory into `snapshot` and return the names of its subdirectories (empty unless `recursive`). The
/// listing handle is dropped before this returns, so only `dir` itself stays open.
///
/// For the watched directory (`is_top`) an unreadable listing is `Unavailable`; for a subdirectory that is unreadable
/// or has vanished it is an empty directory (its entries show up as removed).
fn read_level(
    dir: &Dir,
    dir_path: &NsPath,
    is_top: bool,
    recursive: bool,
    max_tracked: usize,
    snapshot: &mut Snapshot,
) -> Result<Vec<String>, ScanOutcome> {
    let entries = match dir.entries() {
        Ok(e) => e,
        Err(_) if is_top => return Err(ScanOutcome::Unavailable),
        Err(e)
            if e.kind() == io::ErrorKind::PermissionDenied
                || e.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(Vec::new());
        }
        Err(_) => return Err(ScanOutcome::Incomplete),
    };
    let mut subdirs = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return Err(ScanOutcome::Incomplete);
        };
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if validate_name(name).is_err() {
            continue;
        }
        let Some(child) = dir_path.child(name) else {
            continue;
        };
        let Ok(md) = entry.metadata() else { continue };
        let kind = if md.file_type().is_dir() {
            Kind::Dir
        } else if md.file_type().is_file() {
            Kind::File
        } else {
            // Symlinks (a loop included), FIFOs, sockets, devices: not part of the namespace, never followed.
            continue;
        };
        if snapshot.len() >= max_tracked {
            return Err(ScanOutcome::Incomplete);
        }
        snapshot.insert(
            child,
            Fingerprint {
                kind,
                len: if kind == Kind::File { md.len() } else { 0 },
                mtime_ns: mtime_ns(&md),
                inode: sys::scan_inode(&md),
            },
        );
        if recursive && kind == Kind::Dir {
            subdirs.push(name.to_string());
        }
    }
    Ok(subdirs)
}

// ---------------------------------------------------------------------------------------------------------------
// The Backend impl
// ---------------------------------------------------------------------------------------------------------------

impl Backend for HostDir {
    fn caps(&self) -> Caps {
        self.caps
    }

    fn root_identity(&self) -> Option<(u64, u64)> {
        self.identity
    }

    fn walk(&self, path: &NsPath) -> NsResult<Vec<Entry>> {
        let dir = open_dir_at(&self.root, path)?;
        let entries = dir.entries().map_err(|e| NsError::from_io(&e, path))?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| NsError::from_io(&e, path))?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if validate_name(name).is_err() {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            let kind = if ft.is_dir() {
                Kind::Dir
            } else if ft.is_file() {
                Kind::File
            } else {
                // Symlinks, FIFOs, sockets, devices: not addressable, so not listed.
                continue;
            };
            out.push(Entry {
                name: name.to_string(),
                kind,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn read(&self, path: &NsPath, max: u64) -> NsResult<(Vec<u8>, Version)> {
        if path.is_root() {
            return Err(NsError::at(NsErrorKind::IsADirectory, path));
        }
        let (parent, name) = open_parent(&self.root, path)?;
        let (mut file, md) = open_regular(&parent, name, path)?;
        let version = version_of(&md);
        if md.len() > max {
            return Err(NsError::at(NsErrorKind::TooLarge, path));
        }
        // Read at most max + 1 bytes: enough to know it was too large, never an unbounded read of a growing file.
        let mut buf = Vec::new();
        (&mut file)
            .take(max.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| NsError::from_io(&e, path))?;
        if buf.len() as u64 > max {
            return Err(NsError::at(NsErrorKind::TooLarge, path));
        }
        Ok((buf, version))
    }

    fn stat(&self, path: &NsPath) -> NsResult<Stat> {
        if path.is_root() {
            let md = self
                .root
                .dir_metadata()
                .map_err(|e| NsError::from_io(&e, path))?;
            return Ok(stat_of(&md, Kind::Dir));
        }
        let (parent, name) = open_parent(&self.root, path)?;
        match lookup(&parent, name, path)? {
            Some((kind, md)) => Ok(stat_of(&md, kind)),
            None => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }

    fn write(
        &self,
        path: &NsPath,
        op: WriteOp,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        match op {
            WriteOp::CreateExclusive => {
                if path.is_root() {
                    return Err(NsError::at(NsErrorKind::AlreadyExists, path));
                }
                self.create_exclusive(path, data, if_version)
            }
            WriteOp::Replace => {
                if path.is_root() {
                    return Err(NsError::at(NsErrorKind::IsADirectory, path));
                }
                self.replace(path, data, if_version)
            }
            WriteOp::Remove => {
                no_data(data, path)?;
                self.remove(path, if_version)
            }
            WriteOp::RenameWithinMount { to } => {
                no_data(data, path)?;
                self.rename(path, &to, if_version)
            }
            WriteOp::MakeDir => {
                no_data(data, path)?;
                if path.is_root() {
                    return Err(NsError::at(NsErrorKind::AlreadyExists, path));
                }
                self.make_dir(path, if_version)
            }
        }
    }

    fn watch(&self, path: &NsPath, opts: WatchOpts) -> NsResult<Watch> {
        // Validate now, synchronously, so a bad path is an error here and not a thread that quietly reports nothing.
        drop(open_dir_at(&self.root, path)?);
        let (recursive, max_tracked, max_depth) =
            (opts.recursive, opts.max_tracked, opts.max_depth);
        let baseline = match scan(&self.root, path, recursive, max_tracked, max_depth) {
            ScanOutcome::Complete(s) => s,
            ScanOutcome::Unavailable => return Err(NsError::at(NsErrorKind::NotFound, path)),
            // Too many entries or too deep to track (or the scan could not finish): refuse rather than watch half a
            // tree.
            ScanOutcome::Incomplete => return Err(NsError::at(NsErrorKind::TooLarge, path)),
        };
        let root = self
            .root
            .try_clone()
            .map_err(|e| NsError::from_io(&e, path))?;
        let watched = path.clone();
        spawn_poller(
            baseline,
            move || scan(&root, &watched, recursive, max_tracked, max_depth),
            &opts,
        )
        .map_err(|e| NsError::from_io(&e, path))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    use super::*;

    fn p(s: &str) -> NsPath {
        NsPath::parse(s).unwrap()
    }

    fn open(path: &Path) -> Dir {
        Dir::open_ambient_dir(path, ambient_authority()).unwrap()
    }

    /// `/d/d/d/...`, `depth` levels, one directory per level, built through open handles (a path this long would not be
    /// accepted by the OS), with a file at the bottom. Returns nothing: the tree is the point.
    fn chain(root: &Dir, depth: usize) {
        let mut cur = root.try_clone().unwrap();
        for _ in 0..depth {
            cur.create_dir("d").unwrap();
            cur = cur.open_dir("d").unwrap();
        }
        cur.write("leaf", b"x").unwrap();
    }

    fn complete(outcome: ScanOutcome) -> Snapshot {
        match outcome {
            ScanOutcome::Complete(s) => s,
            ScanOutcome::Incomplete => panic!("expected a complete scan, got Incomplete"),
            ScanOutcome::Unavailable => panic!("expected a complete scan, got Unavailable"),
        }
    }

    fn is_incomplete(outcome: &ScanOutcome) -> bool {
        matches!(outcome, ScanOutcome::Incomplete)
    }

    /// The identity accessors must answer for a `Metadata` that did not come from an open handle (a directory entry's),
    /// not panic. On Windows that metadata has no by-handle information and the `cap-fs-ext` accessors used to
    /// `expect()` it; on Unix every answer is `Some`. Either way, nothing here may panic, including the version a
    /// careless caller would derive from it.
    #[test]
    fn identity_accessors_never_panic_on_metadata_that_did_not_come_from_a_handle() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"x").unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let dir = open(tmp.path());
        let mut seen = 0;
        for entry in dir.entries().unwrap() {
            let md = entry.unwrap().metadata().unwrap();
            let identity = sys::identity(&md);
            let links = sys::links(&md);
            let _ = (sys::owner(&md), sys::mode(&md), sys::scan_inode(&md));
            let _ = version_of(&md);
            let _ = stat_of(&md, Kind::File);
            #[cfg(unix)]
            {
                assert!(identity.is_some() && links.is_some());
            }
            #[cfg(not(unix))]
            {
                let _ = (identity, links);
            }
            seen += 1;
        }
        assert_eq!(seen, 2);

        // And from handles, which is where identity is promised.
        let md = dir.dir_metadata().unwrap();
        assert!(
            sys::identity(&md).is_some(),
            "a directory handle has an identity"
        );
        let md = dir.symlink_metadata("f").unwrap();
        assert!(sys::identity(&md).is_some() && sys::links(&md) == Some(1));
        let a = HostDir::open_ambient(tmp.path()).unwrap();
        let b = HostDir::from_dir(dir).unwrap();
        assert!(
            a.root_identity().is_some(),
            "a host directory has an identity"
        );
        assert_eq!(
            a.root_identity(),
            b.root_identity(),
            "two handles on one directory report one identity"
        );
    }

    #[test]
    fn a_scan_stops_at_the_depth_cap_with_incomplete_not_a_partial_picture() {
        let tmp = tempfile::tempdir().unwrap();
        let root = open(tmp.path());
        chain(&root, 200);
        // 200 levels fit a cap of 256 and are all there: 200 directories and the leaf.
        let all = complete(scan(&root, &NsPath::root(), true, 1 << 20, 256));
        assert_eq!(all.len(), 201);
        // A cap of 64 is exceeded: no snapshot at all, not the first 64 levels.
        assert!(is_incomplete(&scan(
            &root,
            &NsPath::root(),
            true,
            1 << 20,
            64
        )));
    }

    #[test]
    fn the_cap_counts_levels_below_the_watched_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = open(tmp.path());
        chain(&root, 3); // /d, /d/d, /d/d/d, and /d/d/d/leaf
        for (cap, fits) in [(0, false), (2, false), (3, true), (4, true)] {
            let out = scan(&root, &NsPath::root(), true, 1 << 20, cap);
            assert_eq!(!is_incomplete(&out), fits, "cap {cap}");
            if fits {
                assert_eq!(complete(out).len(), 4, "cap {cap}");
            }
        }
        // The watched directory is level 0 wherever it sits in the mount: from /d, the same tree is two levels deep.
        let from_d = scan(&root, &p("/d"), true, 1 << 20, 2);
        assert_eq!(complete(from_d).len(), 3);
        // A flat watch never looks at depth.
        assert_eq!(
            complete(scan(&root, &NsPath::root(), false, 1 << 20, 0)).len(),
            1
        );
        // An empty tree under cap 0 is complete.
        let empty = tempfile::tempdir().unwrap();
        assert!(complete(scan(&open(empty.path()), &NsPath::root(), true, 1 << 20, 0)).is_empty());
    }

    /// The scan that used to reopen every pending directory from the root took 48 s on a 2,047-level chain (debug).
    /// Unix only: the chain's host path is far past what Windows path APIs accept and its teardown is not the point.
    #[cfg(unix)]
    #[test]
    fn a_chain_two_thousand_levels_deep_is_one_quick_incomplete_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = open(tmp.path());
        chain(&root, 2000);
        let started = Instant::now();
        let out = scan(&root, &NsPath::root(), true, 262_144, 64);
        let took = started.elapsed();
        assert!(
            is_incomplete(&out),
            "deeper than the cap must be Incomplete"
        );
        assert!(
            took < Duration::from_millis(500),
            "a scan of a too-deep tree took {took:?}"
        );
    }

    #[test]
    fn the_scan_holds_one_handle_per_level_and_a_tree_within_the_cap_is_fully_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let root = open(tmp.path());
        // A bushy tree 5 levels deep: every directory has two subdirectories and a file.
        fn grow(dir: &Dir, levels: usize) {
            dir.write("f", b"x").unwrap();
            if levels > 0 {
                for n in ["a", "b"] {
                    dir.create_dir(n).unwrap();
                    grow(&dir.open_dir(n).unwrap(), levels - 1);
                }
            }
        }
        grow(&root, 5);
        let snap = complete(scan(&root, &NsPath::root(), true, 1 << 20, 5));
        // 1 + 2 + 4 + 8 + 16 + 32 files, and 2 + 4 + 8 + 16 + 32 directories.
        assert_eq!(snap.len(), 63 + 62);
        assert!(snap.contains_key(&p("/b/a/b/a/b/f")));
        assert!(is_incomplete(&scan(
            &root,
            &NsPath::root(),
            true,
            1 << 20,
            4
        )));
    }

    /// The scan does not cross onto another filesystem. `/dev/shm` is a tmpfs under `/dev` (a devtmpfs) on every
    /// ordinary Linux; where it is not a separate device the premise is missing and the test says so and passes.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_recursive_scan_does_not_descend_into_another_filesystem() {
        use std::os::unix::fs::MetadataExt;
        let (Ok(dev), Ok(shm)) = (std::fs::metadata("/dev"), std::fs::metadata("/dev/shm")) else {
            eprintln!("skipped: /dev or /dev/shm is not there");
            return;
        };
        if dev.dev() == shm.dev() {
            eprintln!("skipped: /dev/shm is not a separate filesystem here");
            return;
        }
        let Ok(inside) = tempfile::Builder::new()
            .prefix("skns-dev-")
            .tempdir_in("/dev/shm")
        else {
            eprintln!("skipped: /dev/shm is not writable here");
            return;
        };
        std::fs::write(inside.path().join("deep"), b"x").unwrap();
        let name = inside
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let root = open(Path::new("/dev"));
        let ScanOutcome::Complete(snap) = scan(&root, &NsPath::root(), true, 1 << 20, 64) else {
            eprintln!("skipped: /dev could not be scanned completely here");
            return;
        };
        assert_eq!(
            snap.get(&p("/shm")).map(|f| f.kind),
            Some(Kind::Dir),
            "the mount point is listed as a directory"
        );
        let below: Vec<_> = snap
            .keys()
            .filter(|k| k.as_str().starts_with("/shm/"))
            .collect();
        assert!(
            below.is_empty(),
            "the scan crossed into the tmpfs ({name}): {below:?}"
        );
        // Watching the tmpfs itself is fine: it is the watched directory, so its own device is the reference.
        let shm_root = open(Path::new("/dev/shm"));
        let ScanOutcome::Complete(inner) = scan(&shm_root, &NsPath::root(), true, 1 << 20, 64)
        else {
            panic!("/dev/shm itself must be scannable");
        };
        assert!(inner.contains_key(&p(&format!("/{name}/deep"))));
    }
}
