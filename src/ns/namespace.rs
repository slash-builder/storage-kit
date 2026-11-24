//! [`Namespace`]: one tree for the app, a table of mounts underneath.
//!
//! To a caller there is a single file structure rooted at `/`. Under it is a mount table; each mount is a [`Backend`]
//! at a namespace path. This is the Plan 9 composition (a namespace built from mounts) with the BeOS Storage Kit's
//! shape (entries, directories, node monitoring).
//!
//! - **Longest prefix wins.** With mounts at `/data` and `/data/x`, `/data/x/f` is `/data/x`'s `f`; `/data/y` is
//!   `/data`'s `y`. Mounts may nest. A path matched by no mount, and that no mount sits below, is `NotFound`.
//! - **Two mounts at the same path is an error** (`AlreadyExists`), at `build()`.
//! - **Mount ancestors are synthesised.** With mounts at `/config` and `/data/x`, listing `/` gives `config` and `data`,
//!   and `/data` lists `x` (merged with whatever the mount covering `/data`, if any, lists; a mount shadows a same-named
//!   entry). Such a directory exists only as a name: it cannot be written (`PermissionDenied`) or watched
//!   (`Unsupported`).
//! - **`Access::ReadOnly` is enforced here**, whatever the backend says, with `PermissionDenied`; a backend that is not
//!   [`Caps::writable`] is refused as `Unsupported("write")` even under `ReadWrite`.
//! - **A rename across two mounts is `CrossMount`.** The caller copies, then removes; the Kit does not dress that up as
//!   atomic.
//! - **Errors and events carry namespace paths**, never a mount-relative one and never a host one.
//!
//! What the Namespace does **not** do is decide *which* host directories may be mounted, or who may mount what. That is
//! policy, and policy (and the resolver that turns a role like "this app's config directory" into a real directory) is the
//! embedder's. The Kit confines to the roots it is handed.
//!
//! A mount table is fixed at `build()`. Mount points are not protected from being renamed away inside a parent mount:
//! the namespace is a table of names, not a filesystem that tracks its own mount points.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::backend::{Access, Backend, Caps, Entry, Kind, Stat, Version, WriteOp};
use super::error::{NsError, NsErrorKind, NsResult};
use super::path::NsPath;
use super::watch::{Watch, WatchOpts};

#[derive(Clone)]
struct Mount {
    point: NsPath,
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
            point,
            backend,
            access,
        });
        self
    }

    /// Finish. Two mounts at the same path is `AlreadyExists`.
    pub fn build(self) -> NsResult<Namespace> {
        let mut seen: BTreeMap<&NsPath, ()> = BTreeMap::new();
        for m in &self.mounts {
            if seen.insert(&m.point, ()).is_some() {
                return Err(NsError::at(NsErrorKind::AlreadyExists, &m.point));
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

    /// Names of the next component of every mount strictly below `path`, sorted and unique.
    fn child_mount_names(&self, path: &NsPath) -> Vec<String> {
        let depth = path.depth();
        let mut names: Vec<String> = self
            .mounts
            .iter()
            .filter(|m| m.point != *path && m.point.starts_with(path))
            .filter_map(|m| m.point.components().nth(depth).map(str::to_string))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    fn resolve(&self, path: &NsPath) -> Resolved<'_> {
        let best = self
            .mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| path.starts_with(&m.point))
            .max_by_key(|(_, m)| m.point.depth());
        if let Some((index, mount)) = best {
            let rel = path.strip_prefix(&mount.point).unwrap_or_else(NsPath::root);
            return Resolved::Mount { mount, index, rel };
        }
        let children = self.child_mount_names(path);
        if children.is_empty() {
            Resolved::Nothing
        } else {
            Resolved::Ancestor { children }
        }
    }

    /// List a directory. See the [module docs](self) for how mount ancestors and shadowing are handled.
    pub fn walk(&self, path: &NsPath) -> NsResult<Vec<Entry>> {
        match self.resolve(path) {
            Resolved::Mount { mount, rel, .. } => {
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
                    match entries.iter_mut().find(|e| e.name == name) {
                        Some(existing) => existing.kind = Kind::Dir,
                        None => entries.push(Entry {
                            name,
                            kind: Kind::Dir,
                        }),
                    }
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            }
            Resolved::Ancestor { children } => Ok(children
                .into_iter()
                .map(|name| Entry {
                    name,
                    kind: Kind::Dir,
                })
                .collect()),
            Resolved::Nothing => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }

    /// Read a whole file, at most `max` bytes (`TooLarge` otherwise; nothing is truncated).
    pub fn read(&self, path: &NsPath, max: u64) -> NsResult<(Vec<u8>, Version)> {
        match self.resolve(path) {
            Resolved::Mount { mount, rel, .. } => mount
                .backend
                .read(&rel, max)
                .map_err(|e| e.rebased(&mount.point).or_at(path)),
            Resolved::Ancestor { .. } => Err(NsError::at(NsErrorKind::IsADirectory, path)),
            Resolved::Nothing => Err(NsError::at(NsErrorKind::NotFound, path)),
        }
    }

    /// The `manifest` verb: kind, size, version and, where the backend has them, owner, mode and link count.
    pub fn stat(&self, path: &NsPath) -> NsResult<Stat> {
        match self.resolve(path) {
            Resolved::Mount { mount, rel, .. } => match mount.backend.stat(&rel) {
                Ok(s) => Ok(s),
                Err(e)
                    if e.kind() == NsErrorKind::NotFound
                        && !self.child_mount_names(path).is_empty() =>
                {
                    Ok(synthetic_stat())
                }
                Err(e) => Err(e.rebased(&mount.point).or_at(path)),
            },
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
        if !mount.backend.caps().writable {
            return Err(NsError::at(NsErrorKind::Unsupported("write"), path));
        }
        let op = match op {
            WriteOp::RenameWithinMount { to } => match self.resolve(&to) {
                Resolved::Mount {
                    index: to_index,
                    rel: to_rel,
                    ..
                } if to_index == index => WriteOp::RenameWithinMount { to: to_rel },
                _ => return Err(NsError::at(NsErrorKind::CrossMount, path)),
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
            Resolved::Mount { mount, rel, .. } => {
                let point = mount.point.clone();
                let watch = mount
                    .backend
                    .watch(&rel, opts)
                    .map_err(|e| e.rebased(&mount.point).or_at(path))?;
                Ok(watch.map_paths(move |p| p.rebase(&point).ok()))
            }
            Resolved::Ancestor { .. } => Err(NsError::at(
                NsErrorKind::Unsupported("watch on a directory that is only a mount ancestor"),
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
