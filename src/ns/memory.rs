//! [`Memory`]: an in-memory mount with exact versions, for tests and scratch trees.
//!
//! It is also the reference for the conformance suite: where `HostDir` is best effort (versions, watch latency) `Memory`
//! is exact, so a behaviour difference between the two is either a declared [`Caps`] difference or a bug.
//!
//! - `if_version` is **exact**: the check and the change happen under one lock.
//! - `watch` is **immediate** ([`WatchKind::Native`]): the batch is queued before the writing call returns.
//! - Versions are a counter made unique **per instance** (an instance number and a random part in its high bits), so a
//!   version from one `Memory` never validates against another. A directory's version changes whenever an entry is
//!   added to, removed from or renamed in it (and may change more often).
//! - No ownership or mode (`owner_mode` is false), no hard links, no symlinks; nothing to escape from.
//!
//! [`MemoryOptions`] can switch capabilities off so the suite can prove a backend that declares a capability false
//! really returns `Unsupported` for it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use super::backend::{Backend, Caps, Entry, Kind, Stat, Version, WatchKind, WriteOp};
use super::error::{Feature, InputReason, NsError, NsErrorKind, NsResult};
use super::path::{case_fold_key, NsPath};
use super::watch::{new_epoch, BatchSender, Watch, WatchOpts};

/// Which optional capabilities a [`Memory`] provides. The default is all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryOptions {
    /// `write` is available. When false every `write` is `Unsupported(Feature::Write)`.
    pub writable: bool,
    /// `Replace` is available. When false it is `Unsupported(Feature::AtomicReplace)`.
    pub atomic_replace: bool,
    /// `watch` is available. When false it is `Unsupported(Feature::Watch)` and `caps().watch` is `WatchKind::None`.
    pub watch: bool,
}

impl MemoryOptions {
    /// Set [`MemoryOptions::writable`].
    #[must_use]
    pub fn writable(mut self, on: bool) -> Self {
        self.writable = on;
        self
    }

    /// Set [`MemoryOptions::atomic_replace`].
    #[must_use]
    pub fn atomic_replace(mut self, on: bool) -> Self {
        self.atomic_replace = on;
        self
    }

    /// Set [`MemoryOptions::watch`].
    #[must_use]
    pub fn watch(mut self, on: bool) -> Self {
        self.watch = on;
        self
    }
}

impl Default for MemoryOptions {
    fn default() -> Self {
        MemoryOptions {
            writable: true,
            atomic_replace: true,
            watch: true,
        }
    }
}

enum Node {
    File {
        data: Vec<u8>,
        ver: u128,
    },
    Dir {
        children: BTreeMap<String, Node>,
        ver: u128,
    },
}

impl Node {
    fn version(&self) -> Version {
        let ver = match self {
            Node::File { ver, .. } | Node::Dir { ver, .. } => *ver,
        };
        let mut bytes = vec![b'm'];
        bytes.extend_from_slice(&ver.to_le_bytes());
        Version::from_bytes(&bytes)
    }

    fn kind(&self) -> Kind {
        match self {
            Node::File { .. } => Kind::File,
            Node::Dir { .. } => Kind::Dir,
        }
    }
}

struct Watcher {
    id: u64,
    dir: NsPath,
    opts: WatchOpts,
    sender: BatchSender,
    /// Whether the watched directory existed after the last mutation: its going away and coming back are `rescan`s.
    present: bool,
}

struct State {
    root: Node,
    counter: u128,
    watchers: Vec<Watcher>,
    next_watch_id: u64,
}

/// The first version number of a new `Memory`: `[instance: 32][random: 32][counter: 64]`. The instance part is unique in
/// this process and the random part makes a collision across processes vanishingly unlikely, so a version taken from
/// one `Memory` is never equal to one of another: used as `if_version` against the wrong mount it is a
/// `VersionMismatch`, not a lucky match.
fn fresh_counter_base() -> u128 {
    static INSTANCES: AtomicU32 = AtomicU32::new(0);
    let instance = u128::from(INSTANCES.fetch_add(1, Ordering::Relaxed));
    let random = u128::from(new_epoch() as u32);
    (instance << 96) | (random << 64)
}

fn tick(counter: &mut u128) -> u128 {
    *counter += 1;
    *counter
}

fn lookup<'a>(root: &'a Node, path: &NsPath) -> NsResult<&'a Node> {
    let mut cur = root;
    for name in path.components() {
        cur = match cur {
            Node::Dir { children, .. } => children
                .get(name)
                .ok_or_else(|| NsError::at(NsErrorKind::NotFound, path))?,
            Node::File { .. } => return Err(NsError::at(NsErrorKind::NotADirectory, path)),
        };
    }
    Ok(cur)
}

type DirMut<'a> = (&'a mut BTreeMap<String, Node>, &'a mut u128);

fn dir_mut<'a>(root: &'a mut Node, path: &NsPath) -> NsResult<DirMut<'a>> {
    let mut cur = root;
    for name in path.components() {
        cur = match cur {
            Node::Dir { children, .. } => children
                .get_mut(name)
                .ok_or_else(|| NsError::at(NsErrorKind::NotFound, path))?,
            Node::File { .. } => return Err(NsError::at(NsErrorKind::NotADirectory, path)),
        };
    }
    match cur {
        Node::Dir { children, ver } => Ok((children, ver)),
        Node::File { .. } => Err(NsError::at(NsErrorKind::NotADirectory, path)),
    }
}

/// Same-name or case-fold clash between `name` and the keys of `children`, ignoring `ignore`.
fn conflict(
    children: &BTreeMap<String, Node>,
    name: &str,
    ignore: Option<&str>,
) -> Option<NsErrorKind> {
    let key = case_fold_key(name);
    let mut fold = false;
    for existing in children.keys() {
        if Some(existing.as_str()) == ignore {
            continue;
        }
        if existing == name {
            return Some(NsErrorKind::AlreadyExists);
        }
        if case_fold_key(existing) == key {
            fold = true;
        }
    }
    fold.then_some(NsErrorKind::CaseCollision)
}

fn check_version(node: &Node, if_version: Option<&Version>, path: &NsPath) -> NsResult<()> {
    match if_version {
        Some(v) if *v != node.version() => Err(NsError::at(NsErrorKind::VersionMismatch, path)),
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

/// An in-memory mount. Cheap to clone: clones share one tree. See the [module docs](self).
#[derive(Clone)]
pub struct Memory {
    state: Arc<Mutex<State>>,
    opts: MemoryOptions,
}

impl std::fmt::Debug for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memory")
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    /// An empty tree with every capability.
    pub fn new() -> Self {
        Self::with_options(MemoryOptions::default())
    }

    /// An empty tree with some capabilities switched off.
    pub fn with_options(opts: MemoryOptions) -> Self {
        let base = fresh_counter_base();
        Memory {
            state: Arc::new(Mutex::new(State {
                root: Node::Dir {
                    children: BTreeMap::new(),
                    ver: base,
                },
                counter: base,
                watchers: Vec::new(),
                next_watch_id: 0,
            })),
            opts,
        }
    }

    /// Put a file in place, creating missing parent directories, regardless of the capability switches. For setting up
    /// a tree that is then read through a read-only `Memory`.
    pub fn preload(&self, path: &NsPath, data: &[u8]) -> NsResult<()> {
        let mut dirs = Vec::new();
        let mut cur = path.parent();
        while let Some(p) = cur {
            if p.is_root() {
                break;
            }
            cur = p.parent();
            dirs.push(p);
        }
        for dir in dirs.into_iter().rev() {
            match self.apply(&dir, WriteOp::MakeDir, &[], None) {
                Ok(_) => {}
                Err(e) if e.kind() == NsErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        self.apply(path, WriteOp::Replace, data, None).map(|_| ())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The write itself, with no capability checks. Returns the version and nothing else; watchers are notified here.
    fn apply(
        &self,
        path: &NsPath,
        op: WriteOp,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        let mut guard = self.lock();
        let st = &mut *guard;
        let (version, affected) = match op {
            WriteOp::CreateExclusive => {
                no_version(if_version, path)?;
                create(st, path, Some(data))?
            }
            WriteOp::MakeDir => {
                no_data(data, path)?;
                no_version(if_version, path)?;
                create(st, path, None)?
            }
            WriteOp::Replace => replace(st, path, data, if_version)?,
            WriteOp::Remove => {
                no_data(data, path)?;
                remove(st, path, if_version)?
            }
            WriteOp::RenameWithinMount { to } => {
                no_data(data, path)?;
                rename(st, path, &to, if_version)?
            }
        };
        notify(st, &affected);
        Ok(version)
    }
}

fn split(path: &NsPath, what_for_root: NsErrorKind) -> NsResult<(NsPath, &str)> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => Err(NsError::at(what_for_root, path)),
    }
}

/// `CreateExclusive` (`data` is `Some`) and `MakeDir` (`None`).
fn create(st: &mut State, path: &NsPath, data: Option<&[u8]>) -> NsResult<(Version, Vec<NsPath>)> {
    let (parent, name) = split(path, NsErrorKind::AlreadyExists)?;
    let State { root, counter, .. } = st;
    let (children, parent_ver) = dir_mut(root, &parent).map_err(|e| e.or_at(path))?;
    if let Some(kind) = conflict(children, name, None) {
        return Err(NsError::at(kind, path));
    }
    let ver = tick(counter);
    let node = match data {
        Some(d) => Node::File {
            data: d.to_vec(),
            ver,
        },
        None => Node::Dir {
            children: BTreeMap::new(),
            ver,
        },
    };
    let version = node.version();
    children.insert(name.to_string(), node);
    *parent_ver = tick(counter);
    Ok((version, vec![path.clone(), parent]))
}

fn replace(
    st: &mut State,
    path: &NsPath,
    data: &[u8],
    if_version: Option<&Version>,
) -> NsResult<(Version, Vec<NsPath>)> {
    let (parent, name) = split(path, NsErrorKind::IsADirectory)?;
    let State { root, counter, .. } = st;
    let (children, parent_ver) = dir_mut(root, &parent).map_err(|e| e.or_at(path))?;
    match children.get_mut(name) {
        Some(Node::Dir { .. }) => Err(NsError::at(NsErrorKind::IsADirectory, path)),
        Some(node @ Node::File { .. }) => {
            check_version(node, if_version, path)?;
            let ver = tick(counter);
            *node = Node::File {
                data: data.to_vec(),
                ver,
            };
            Ok((node.version(), vec![path.clone(), parent]))
        }
        None => {
            if if_version.is_some() {
                return Err(NsError::at(NsErrorKind::NotFound, path));
            }
            if let Some(NsErrorKind::CaseCollision) = conflict(children, name, None) {
                return Err(NsError::at(NsErrorKind::CaseCollision, path));
            }
            let node = Node::File {
                data: data.to_vec(),
                ver: tick(counter),
            };
            let version = node.version();
            children.insert(name.to_string(), node);
            *parent_ver = tick(counter);
            Ok((version, vec![path.clone(), parent]))
        }
    }
}

fn remove(
    st: &mut State,
    path: &NsPath,
    if_version: Option<&Version>,
) -> NsResult<(Version, Vec<NsPath>)> {
    let (parent, name) = split(path, NsErrorKind::InvalidInput(InputReason::MountRoot))?;
    let State { root, counter, .. } = st;
    let (children, parent_ver) = dir_mut(root, &parent).map_err(|e| e.or_at(path))?;
    let node = children
        .get(name)
        .ok_or_else(|| NsError::at(NsErrorKind::NotFound, path))?;
    check_version(node, if_version, path)?;
    if let Node::Dir {
        children: inner, ..
    } = node
    {
        if !inner.is_empty() {
            return Err(NsError::at(NsErrorKind::NotEmpty, path));
        }
    }
    let version = node.version();
    children.remove(name);
    *parent_ver = tick(counter);
    Ok((version, vec![path.clone(), parent]))
}

fn rename(
    st: &mut State,
    from: &NsPath,
    to: &NsPath,
    if_version: Option<&Version>,
) -> NsResult<(Version, Vec<NsPath>)> {
    let root_err = NsErrorKind::InvalidInput(InputReason::MountRoot);
    let (from_parent, from_name) = split(from, root_err)?;
    let (to_parent, to_name) = split(to, root_err)?;
    if from == to {
        // Not a no-op: the name is taken. Only a respelling of one's own name may "collide" with itself.
        return Err(NsError::at(NsErrorKind::AlreadyExists, to));
    }
    if to.starts_with(from) {
        return Err(NsError::at(
            NsErrorKind::InvalidInput(InputReason::MoveIntoSelf),
            to,
        ));
    }
    // Validate everything first (read-only), so the mutation below cannot fail half way.
    let node = lookup(&st.root, from)?;
    check_version(node, if_version, from)?;
    let version = node.version();
    let to_dir = lookup(&st.root, &to_parent).map_err(|e| e.or_at(to))?;
    let Node::Dir { children, .. } = to_dir else {
        return Err(NsError::at(NsErrorKind::NotADirectory, to));
    };
    let ignore = (from_parent == to_parent).then_some(from_name);
    if let Some(kind) = conflict(children, to_name, ignore) {
        return Err(NsError::at(kind, to));
    }

    let State { root, counter, .. } = st;
    let (src_children, src_ver) = dir_mut(root, &from_parent)?;
    let Some(moved) = src_children.remove(from_name) else {
        return Err(NsError::at(NsErrorKind::NotFound, from));
    };
    *src_ver = tick(counter);
    let (dst_children, dst_ver) = dir_mut(root, &to_parent)?;
    dst_children.insert(to_name.to_string(), moved);
    *dst_ver = tick(counter);
    Ok((
        version,
        vec![from.clone(), to.clone(), from_parent, to_parent],
    ))
}

/// Tell every watcher about a mutation. `affected` are the paths whose entry (or whose directory listing) changed.
fn notify(st: &mut State, affected: &[NsPath]) {
    let State { root, watchers, .. } = st;
    watchers.retain_mut(|w| {
        let present = matches!(lookup(root, &w.dir), Ok(Node::Dir { .. }));
        if present != w.present {
            // The watched directory went away or came back: events may have been lost, so say so.
            w.present = present;
            return w.sender.send(Vec::new(), true, w.opts.max_entries);
        }
        if !present {
            return true;
        }
        let changed: Vec<NsPath> = affected
            .iter()
            .filter(|p| {
                **p != w.dir
                    && p.starts_with(&w.dir)
                    && (w.opts.recursive || p.parent().as_ref() == Some(&w.dir))
            })
            .cloned()
            .collect();
        changed.is_empty() || w.sender.send(changed, false, w.opts.max_entries)
    });
}

impl Backend for Memory {
    fn caps(&self) -> Caps {
        Caps {
            writable: self.opts.writable,
            atomic_replace: self.opts.writable && self.opts.atomic_replace,
            exact_if_version: true,
            watch: if self.opts.watch {
                WatchKind::Native
            } else {
                WatchKind::None
            },
            owner_mode: false,
            case_sensitive: true,
            strict_confinement: true,
        }
    }

    fn walk(&self, path: &NsPath) -> NsResult<Vec<Entry>> {
        let st = self.lock();
        match lookup(&st.root, path)? {
            Node::Dir { children, .. } => Ok(children
                .iter()
                .map(|(name, node)| Entry {
                    name: name.clone(),
                    kind: node.kind(),
                })
                .collect()),
            Node::File { .. } => Err(NsError::at(NsErrorKind::NotADirectory, path)),
        }
    }

    fn read(&self, path: &NsPath, max: u64) -> NsResult<(Vec<u8>, Version)> {
        let st = self.lock();
        match lookup(&st.root, path)? {
            node @ Node::File { data, .. } => {
                if data.len() as u64 > max {
                    return Err(NsError::at(NsErrorKind::TooLarge, path));
                }
                Ok((data.clone(), node.version()))
            }
            Node::Dir { .. } => Err(NsError::at(NsErrorKind::IsADirectory, path)),
        }
    }

    fn stat(&self, path: &NsPath) -> NsResult<Stat> {
        let st = self.lock();
        let node = lookup(&st.root, path)?;
        Ok(Stat {
            kind: node.kind(),
            size: match node {
                Node::File { data, .. } => data.len() as u64,
                Node::Dir { .. } => 0,
            },
            version: node.version(),
            owner: None,
            mode: None,
            links: None,
            modified: None,
        })
    }

    fn write(
        &self,
        path: &NsPath,
        op: WriteOp,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        if !self.opts.writable {
            return Err(NsError::at(NsErrorKind::Unsupported(Feature::Write), path));
        }
        if matches!(op, WriteOp::Replace) && !self.opts.atomic_replace {
            return Err(NsError::at(
                NsErrorKind::Unsupported(Feature::AtomicReplace),
                path,
            ));
        }
        self.apply(path, op, data, if_version)
    }

    fn watch(&self, path: &NsPath, opts: WatchOpts) -> NsResult<Watch> {
        if !self.opts.watch {
            return Err(NsError::at(NsErrorKind::Unsupported(Feature::Watch), path));
        }
        let mut st = self.lock();
        match lookup(&st.root, path)? {
            Node::Dir { .. } => {}
            Node::File { .. } => return Err(NsError::at(NsErrorKind::NotADirectory, path)),
        }
        let (sender, rx) = BatchSender::channel();
        let id = st.next_watch_id;
        st.next_watch_id += 1;
        st.watchers.push(Watcher {
            id,
            dir: path.clone(),
            opts,
            sender,
            present: true,
        });
        let weak: Weak<Mutex<State>> = Arc::downgrade(&self.state);
        Ok(Watch::new(rx, move || {
            if let Some(state) = weak.upgrade() {
                let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
                st.watchers.retain(|w| w.id != id);
            }
        }))
    }
}
