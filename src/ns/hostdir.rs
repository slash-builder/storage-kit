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
//!   refused at the start, and degrades to a single `rescan` if it grows past it). A recursive scan keeps directory
//!   *paths* and opens one directory at a time, so it holds a handful of file descriptors however wide the tree is; a
//!   scan that cannot finish (descriptors, I/O error) is reported as one `rescan`, not compared as a partial picture.
//! - **Hard-link and alias writes through other names** are only caught by the link count at the moment of the call.
//!
//! ## Windows is the weakest platform, and says so
//!
//! It compiles, and it is as strict as `cap-std` and `std` allow, but [`Caps::strict_confinement`] is `false` there and
//! the following are **not** guaranteed:
//!
//! - **Hard links**: the link count is not available on stable Rust for Windows, so the hard-link refusal does not
//!   happen. `Stat::links` is `None`.
//! - **Alternate data streams** (`name:stream`): `:` is refused in names, which blocks naming one through this API, but
//!   a stream already on a file is not detected.
//! - **Case-insensitive volumes**: the default NTFS volume is case-insensitive; collisions are still refused by the
//!   grammar, but the volume itself will treat `A` and `a` as one name.
//! - **Reparse points**: symlinks and junctions are refused as far as `std` classifies them as symlinks; other reparse
//!   kinds (cloud placeholders, dedup) are not distinguished.
//! - **Versions** use mtime and size only (no file identity), so a replaced file of the same size and timestamp is not
//!   told apart. Ownership and mode are not reported. Directory `fsync` is not available, so `Replace` is atomic but its
//!   durability across a power loss is the OS's.
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
#[cfg(unix)]
mod sys {
    use cap_std::fs::{Metadata, MetadataExt};

    pub fn inode(md: &Metadata) -> u64 {
        md.ino()
    }
    pub fn device(md: &Metadata) -> u64 {
        md.dev()
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
}

#[cfg(not(unix))]
mod sys {
    use cap_std::fs::Metadata;

    pub fn inode(_: &Metadata) -> u64 {
        0
    }
    pub fn device(_: &Metadata) -> u64 {
        0
    }
    pub fn links(_: &Metadata) -> Option<u64> {
        None
    }
    pub fn owner(_: &Metadata) -> Option<u32> {
        None
    }
    pub fn mode(_: &Metadata) -> Option<u32> {
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
            exact_if_version: false,
            watch: WatchKind::Polling,
            owner_mode: cfg!(unix),
            case_sensitive: probe_case_sensitive(&dir),
            strict_confinement: cfg!(unix),
        };
        Ok(HostDir { root: dir, caps })
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
            Ok(other) => {
                !(sys::inode(&other) == sys::inode(&original)
                    && sys::device(&other) == sys::device(&original))
            }
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
    bytes.extend_from_slice(&sys::inode(md).to_le_bytes());
    bytes.extend_from_slice(&sys::device(md).to_le_bytes());
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
        let same_dir = from.parent() == to.parent();
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
/// Directories still to visit are kept as *paths* and opened one at a time when their turn comes, so the scan holds a
/// bounded number of file descriptors (a few) however wide or deep the tree is. A subdirectory that has vanished or
/// became a link or is unreadable is simply not there (its entries show up as removed); a failure that is about *us*
/// (descriptors exhausted, an I/O error, more than `max_tracked` entries) makes the whole scan [`ScanOutcome::Incomplete`]
/// so no half-picture is compared against the last good one.
fn scan(root: &Dir, path: &NsPath, recursive: bool, max_tracked: usize) -> ScanOutcome {
    let Ok(top) = open_dir_at(root, path) else {
        return ScanOutcome::Unavailable;
    };
    let mut top = Some(top);
    let mut snapshot = Snapshot::new();
    let mut pending = vec![path.clone()];
    while let Some(dir_path) = pending.pop() {
        let is_top = top.is_some();
        let dir = match top.take() {
            Some(d) => d,
            None => match open_dir_at(root, &dir_path) {
                Ok(d) => d,
                Err(e) => match e.kind() {
                    NsErrorKind::NotFound
                    | NsErrorKind::NotADirectory
                    | NsErrorKind::Escapes
                    | NsErrorKind::PermissionDenied => continue,
                    _ => return ScanOutcome::Incomplete,
                },
            },
        };
        let entries = match dir.entries() {
            Ok(e) => e,
            Err(_) if is_top => return ScanOutcome::Unavailable,
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    || e.kind() == io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(_) => return ScanOutcome::Incomplete,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return ScanOutcome::Incomplete;
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
                return ScanOutcome::Incomplete;
            }
            snapshot.insert(
                child.clone(),
                Fingerprint {
                    kind,
                    len: if kind == Kind::File { md.len() } else { 0 },
                    mtime_ns: mtime_ns(&md),
                    inode: sys::inode(&md),
                },
            );
            if recursive && kind == Kind::Dir {
                pending.push(child);
            }
        }
    }
    ScanOutcome::Complete(snapshot)
}

// ---------------------------------------------------------------------------------------------------------------
// The Backend impl
// ---------------------------------------------------------------------------------------------------------------

impl Backend for HostDir {
    fn caps(&self) -> Caps {
        self.caps
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
        let (recursive, max_tracked) = (opts.recursive, opts.max_tracked);
        let baseline = match scan(&self.root, path, recursive, max_tracked) {
            ScanOutcome::Complete(s) => s,
            ScanOutcome::Unavailable => return Err(NsError::at(NsErrorKind::NotFound, path)),
            // Too many entries to track (or the scan could not finish): refuse rather than watch half a tree.
            ScanOutcome::Incomplete => return Err(NsError::at(NsErrorKind::TooLarge, path)),
        };
        let root = self
            .root
            .try_clone()
            .map_err(|e| NsError::from_io(&e, path))?;
        let watched = path.clone();
        spawn_poller(
            baseline,
            move || scan(&root, &watched, recursive, max_tracked),
            &opts,
        )
        .map_err(|e| NsError::from_io(&e, path))
    }
}
