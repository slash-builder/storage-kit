//! [`Namespace`]: one tree for the app, a table of mounts underneath.
//!
//! To a caller there is a single file structure rooted at `/`. Under it is a mount table; each mount is a [`Backend`]
//! at a namespace path. This is the Plan 9 composition (a namespace built from mounts) with the BeOS Storage Kit's
//! shape (entries, directories, node monitoring).
//!
//! - **Longest prefix wins.** With mounts at `/data` and `/data/x`, `/data/x/f` is `/data/x`'s `f`; `/data/y` is
//!   `/data`'s `y`. Mounts may nest. A path matched by no mount, and that no mount sits below, is `NotFound`.
//! - **Mount points match case-folded** (by [`case_fold_key`], component by component). A mount at
//!   `/Config` answers to `/config` and `/CONFIG`, so spelling a path differently can never route around a mount (on a
//!   case-insensitive volume the host would otherwise answer to the other spelling and skip the mount's grant). Two
//!   mount points that fold equal are one mount point, and are refused as `AlreadyExists`.
//! - **A `ReadOnly` mount may not nest under a `ReadWrite` one** (`InvalidInput(ReadOnlyUnderReadWrite)`, at `build()`).
//!   The writable parent could rename the directory that holds the nested mount point and then write through the new
//!   name, which no nested mount covers. Mount read-only trees outside any writable mount (under a path that is only a
//!   synthesised ancestor); a `ReadWrite` mount under a `ReadOnly` one is fine.
//! - **Mount ancestors are synthesised.** With mounts at `/config` and `/data/x`, listing `/` gives `config` and `data`,
//!   and `/data` lists `x`. Such a directory exists only as a name: it cannot be written (`PermissionDenied`) or watched
//!   (`Unsupported(WatchOnMountAncestor)`).
//! - **A real entry wins over a mount point for what it *is*.** If the mount covering `/a` has a *file* `b` and another
//!   mount sits at `/a/b/c`, `walk(/a)` lists `b` as a file, `stat(/a/b)` says file and `read(/a/b)` returns its bytes: the
//!   backend's entry decides the kind, the same for every verb. The nested mount is the thing that is refused: any verb
//!   through `/a/b/c` answers `NotADirectory` (naming `/a/b`) while that file is in the way, because a mount point cannot
//!   hang off a file. If the entry is a directory (or nothing is there, which is the synthetic case) the mount works and
//!   the listing shows the name once. Costs one `stat` of the mount point's parent per call through a mount nested more
//!   than one level below another.
//! - **`Access::ReadOnly` is enforced here**, whatever the backend says, with `PermissionDenied`; a backend that is not
//!   [`Caps::writable`] is refused as `Unsupported(Feature::Write)` even under `ReadWrite`.
//! - **A rename across two mounts is `CrossMount`.** The caller copies, then removes; the Kit does not dress that up as
//!   atomic. A rename whose destination is in *no* mount is `NotFound`.
//! - **Errors and events carry namespace paths**, never a mount-relative one and never a host one.
//! - **`walk` is sorted by name in UTF-8 byte order**, and is not paged yet (a directory is returned whole). Paging is
//!   deferred until a read-only content-addressed mount has exercised the trait; adding it will be additive.
//!
//! What the Namespace does **not** do is decide *which* host directories may be mounted, or who may mount what. That is
//! policy, and policy (and the resolver that turns a role like "this app's config directory" into a real directory) is the
//! embedder's. The Kit confines to the roots it is handed.
//!
//! A mount table is fixed at `build()`. Mount points are not protected from being renamed away inside a *writable*
//! parent mount (that is why a `ReadOnly` mount cannot sit there): the namespace is a table of names, not a filesystem
//! that tracks its own mount points.

use std::fmt;
use std::sync::Arc;

use super::backend::{Access, Backend, Caps, Entry, Kind, Stat, Version, WriteOp};
use super::error::{Feature, InputReason, NsError, NsErrorKind, NsResult};
use super::path::{case_fold_key, NsPath};
use super::watch::{Watch, WatchOpts};

#[derive(Clone)]
struct Mount {
    point: NsPath,
    /// `point`'s components as case-fold keys: what a request path is matched against.
    key: Vec<String>,
    backend: Arc<dyn Backend>,
    access: Access,
}

/// Builds a [`Namespace`]. Obtain with [`Namespace::builder`].
#[derive(Default)]
pub struct NamespaceBuilder {
    mounts: Vec<Mount>,
}

impl NamespaceBuilder {
    /// Add a mount of `backend` at `point` with the given grant.
    #[must_use]
    pub fn mount(mut self, point: NsPath, backend: Arc<dyn Backend>, access: Access) -> Self {
        self.mounts.push(Mount {
            key: point.fold_components(),
            point,
            backend,
            access,
        });
        self
    }

    /// Finish. Refused: two mounts at the same (case-folded) path (`AlreadyExists`), and a `ReadOnly` mount nested under
    /// a `ReadWrite` one (`InvalidInput(ReadOnlyUnderReadWrite)`).
    pub fn build(self) -> NsResult<Namespace> {
        for (i, m) in self.mounts.iter().enumerate() {
            for other in &self.mounts[..i] {
                if other.key == m.key {
                    return Err(NsError::at(NsErrorKind::AlreadyExists, &m.point));
                }
            }
        }
        for m in &self.mounts {
            if m.access != Access::ReadOnly {
                continue;
            }
            let under_writable = self.mounts.iter().any(|a| {
                a.access == Access::ReadWrite
                    && a.key.len() < m.key.len()
                    && m.key.starts_with(&a.key)
            });
            if under_writable {
                return Err(NsError::at(
                    NsErrorKind::InvalidInput(InputReason::ReadOnlyUnderReadWrite),
                    &m.point,
                ));
            }
        }
        Ok(Namespace {
            mounts: self.mounts,
        })
    }
}

/// A mount table and the five verbs over it: `walk`, `read`, `stat` (the `manifest` verb), `write` and `watch`.
///
/// Cheap to clone (the backends are shared).
#[derive(Clone)]
pub struct Namespace {
    mounts: Vec<Mount>,
}

impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for m in &self.mounts {
            list.entry(&format_args!("{} ({:?})", m.point, m.access));
        }
        list.finish()
    }
}

enum Resolved<'a> {
    /// Covered by a mount; `rel` is the path inside it.
    Mount {
        mount: &'a Mount,
        index: usize,
        rel: NsPath,
    },
    /// Not covered by any mount, but at least one mount sits below it. Contains these child names.
    Ancestor { children: Vec<String> },
    /// Nothing here.
    Nothing,
}

impl Namespace {
    /// Start a mount table.
    pub fn builder() -> NamespaceBuilder {
        NamespaceBuilder::default()
    }

    /// The mount points, with their grants and the capabilities their backends declare.
    pub fn mounts(&self) -> impl Iterator<Item = (&NsPath, Access, Caps)> + '_ {
        self.mounts
            .iter()
            .map(|m| (&m.point, m.access, m.backend.caps()))
    }

    /// Names of the next component of every mount strictly below `path`, one per fold key, sorted.
    fn child_mount_names(&self, path: &NsPath) -> Vec<String> {
        let key = path.fold_components();
        let depth = key.len();
        let mut names: Vec<(String, String)> = self
            .mounts
            .iter()
            .filter(|m| m.key.len() > depth && m.key.starts_with(&key))
            .filter_map(|m| {
                m.point
                    .components()
                    .nth(depth)
                    .map(|c| (m.key[depth].clone(), c.to_string()))
            })
            .collect();
        names.sort();
        names.dedup_by(|a, b| a.0 == b.0);
        names.into_iter().map(|(_, name)| name).collect()
    }

    fn resolve(&self, path: &NsPath) -> Resolved<'_> {
        let key = path.fold_components();
        let best = self
            .mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| key.starts_with(&m.key))
            .max_by_key(|(_, m)| m.key.len());
        if let Some((index, mount)) = best {
            let rel = path.tail_after(mount.key.len());
            return Resolved::Mount { mount, index, rel };
        }
        let children = self.child_mount_names(path);
        if children.is_empty() {
            Resolved::Nothing
        } else {
            Resolved::Ancestor { children }
        }
    }

    /// A mount point cannot hang off a file. If this mount is nested below another and the entry its point hangs from is
    /// a file in that other mount, refuse (`NotADirectory`, naming the file). A directory, or nothing (the synthetic
    /// case), is fine.
    fn guard_nested(&self, index: usize) -> NsResult<()> {
        let m = &self.mounts[index];
        let Some(outer) = self
            .mounts
            .iter()
            .filter(|o| o.key.len() < m.key.len() && m.key.starts_with(&o.key))
            .max_by_key(|o| o.key.len())
        else {
            return Ok(());
        };
        if m.key.len() - outer.key.len() < 2 {
            return Ok(()); // the mount point's parent is the outer mount's own root, which is a directory
        }
        let Some(parent) = m.point.parent() else {
            return Ok(());
        };
        let rel = parent.tail_after(outer.key.len());
        match outer.backend.stat(&rel) {
            Ok(st) if st.kind == Kind::File => {
                Err(NsError::at(NsErrorKind::NotADirectory, &parent))
            }
            Err(e) if e.kind() == NsErrorKind::NotADirectory => {
                Err(NsError::at(NsErrorKind::NotADirectory, &parent))
            }
            _ => Ok(()),
        }
    }

    /// List a directory. See the [module docs](self) for how mount ancestors and shadowing are handled.
    pub fn walk(&self, path: &NsPath) -> NsResult<Vec<Entry>> {
        match self.resolve(path) {
            Resolved::Mount { mount, index, rel } => {
                self.guard_nested(index)?;
                let synthetic = self.child_mount_names(path);
                let mut entries = match mount.backend.walk(&rel) {
                    Ok(e) => e,
                    // The directory is not in this backend but mounts sit below it: it exists as a mount ancestor.
                    Err(e) if e.kind() == NsErrorKind::NotFound && !synthetic.is_empty() => {
                        Vec::new()
                    }
                    Err(e) => return Err(e.rebased(&mount.point).or_at(path)),
                };
                for name in synthetic {
                    // The backend's own entry (whatever its kind) wins; a mount name that folds equal to one is the same
                    // entry, listed once.
                    let key = case_fold_key(&name);
                    if !entries.iter().any(|e| case_fold_key(&e.name) == key) {
                        entries.push(Entry::new(name, Kind::Dir));
                    }
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            }
            Resolved::Ancestor { children } => Ok(children
                .into_iter()
                .map(|name| Entry::new(name, Kind::Dir))
                .collect()),
            Resolved::Nothing => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }

    /// Read a whole file, at most `max` bytes (`TooLarge` otherwise; nothing is truncated).
    pub fn read(&self, path: &NsPath, max: u64) -> NsResult<(Vec<u8>, Version)> {
        match self.resolve(path) {
            Resolved::Mount { mount, index, rel } => {
                self.guard_nested(index)?;
                mount
                    .backend
                    .read(&rel, max)
                    .map_err(|e| e.rebased(&mount.point).or_at(path))
            }
            Resolved::Ancestor { .. } => Err(NsError::at(NsErrorKind::IsADirectory, path)),
            Resolved::Nothing => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }

    /// The `manifest` verb: kind, size, version and, where the backend has them, owner, mode and link count.
    pub fn stat(&self, path: &NsPath) -> NsResult<Stat> {
        match self.resolve(path) {
            Resolved::Mount { mount, index, rel } => {
                self.guard_nested(index)?;
                match mount.backend.stat(&rel) {
                    Ok(s) => Ok(s),
                    Err(e)
                        if e.kind() == NsErrorKind::NotFound
                            && !self.child_mount_names(path).is_empty() =>
                    {
                        Ok(synthetic_stat())
                    }
                    Err(e) => Err(e.rebased(&mount.point).or_at(path)),
                }
            }
            Resolved::Ancestor { .. } => Ok(synthetic_stat()),
            Resolved::Nothing => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }

    /// Apply a [`WriteOp`]. The grant is checked first (`ReadOnly` is `PermissionDenied`), then the backend's
    /// capability. `if_version` is exact or best effort according to the backend's [`Caps::exact_if_version`].
    ///
    /// A `RenameWithinMount` whose destination is under a different mount is `CrossMount`.
    pub fn write(
        &self,
        path: &NsPath,
        op: WriteOp,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        let (mount, index, rel) = match self.resolve(path) {
            Resolved::Mount { mount, index, rel } => (mount, index, rel),
            Resolved::Ancestor { .. } => {
                return Err(NsError::at(NsErrorKind::PermissionDenied, path))
            }
            Resolved::Nothing => return Err(NsError::at(NsErrorKind::NotFound, path)),
        };
        if mount.access == Access::ReadOnly {
            return Err(NsError::at(NsErrorKind::PermissionDenied, path));
        }
        self.guard_nested(index)?;
        if !mount.backend.caps().writable {
            return Err(NsError::at(NsErrorKind::Unsupported(Feature::Write), path));
        }
        let op = match op {
            WriteOp::RenameWithinMount { to } => match self.resolve(&to) {
                Resolved::Mount {
                    index: to_index,
                    rel: to_rel,
                    ..
                } if to_index == index => WriteOp::RenameWithinMount { to: to_rel },
                // A different mount: copy, then remove.
                Resolved::Mount { .. } => return Err(NsError::at(NsErrorKind::CrossMount, path)),
                // No mount at all (nothing there, or only a synthesised ancestor): there is no destination.
                Resolved::Ancestor { .. } | Resolved::Nothing => {
                    return Err(NsError::at(NsErrorKind::NotFound, &to));
                }
            },
            other => other,
        };
        mount
            .backend
            .write(&rel, op, data, if_version)
            .map_err(|e| e.rebased(&mount.point).or_at(path))
    }

    /// Watch a directory. Batches carry namespace paths. The watch sees changes inside the mount that covers `path`; a
    /// recursive watch does not descend into mounts nested below it. A directory that exists only as a mount ancestor
    /// cannot be watched (`Unsupported`): watch the mounts.
    pub fn watch(&self, path: &NsPath, opts: WatchOpts) -> NsResult<Watch> {
        match self.resolve(path) {
            Resolved::Mount { mount, index, rel } => {
                self.guard_nested(index)?;
                let point = mount.point.clone();
                let watch = mount
                    .backend
                    .watch(&rel, opts)
                    .map_err(|e| e.rebased(&mount.point).or_at(path))?;
                Ok(watch.map_paths(move |p| p.rebase(&point).ok()))
            }
            Resolved::Ancestor { .. } => Err(NsError::at(
                NsErrorKind::Unsupported(Feature::WatchOnMountAncestor),
                path,
            )),
            Resolved::Nothing => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }
}

/// What `stat` says about a directory that exists only as a name in the mount table.
fn synthetic_stat() -> Stat {
    Stat {
        kind: Kind::Dir,
        size: 0,
        version: Version::from_bytes(b"ns:mount-ancestor"),
        owner: None,
        mode: None,
        links: None,
        modified: None,
    }
}
