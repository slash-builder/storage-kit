//! The conformance suite: the **same cases against every backend**.
//!
//! A case says which capabilities it needs ([`Requirement`]). If the backend's [`Caps`] says it lacks one, the case is
//! **skipped and reported with the reason**, never silently dropped and never failed. The mirror image is a case that runs
//! only when a capability is *missing* and proves the backend then returns `Unsupported` for it: declaring a capability
//! false is a promise the suite checks.
//!
//! ```
//! # #[cfg(feature = "conformance")] {
//! use storage_kit::ns::{conformance, Memory};
//! let report = conformance::run("memory", &Memory::new());
//! report.assert_ok();
//! # }
//! ```
//!
//! To check a new backend, call [`run`] on it from a test. A report lists what passed, what was skipped and why, and what
//! failed and why. The suite writes only inside a scratch directory it creates and removes (`/conf-...`); on a backend
//! that is not writable it runs the read-only cases against `/` and writes nothing.
//!
//! What it does *not* cover: `HostDir`'s symlink, hard-link, FIFO and race behaviour (a `Memory` has none to test), which
//! live in that backend's own tests.

use std::fmt::Debug;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Barrier;
use std::time::{Duration, Instant};

use super::backend::{Backend, Caps, Entry, Kind, Stat, Version, WatchKind, WriteOp};
use super::error::{InputReason, NsError, NsErrorKind, NsResult};
use super::namespace::Namespace;
use super::path::{validate_name, NsPath};
use super::watch::{Watch, WatchBatch, WatchCursor, WatchOpts};

/// A capability a case can depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    /// [`Caps::writable`]
    Writable,
    /// [`Caps::atomic_replace`]
    AtomicReplace,
    /// [`Caps::exact_if_version`]
    ExactIfVersion,
    /// `Caps::watch` is not [`WatchKind::None`]
    Watch,
    /// [`Caps::owner_mode`]
    OwnerMode,
}

impl Cap {
    fn present(self, caps: &Caps) -> bool {
        match self {
            Cap::Writable => caps.writable,
            Cap::AtomicReplace => caps.atomic_replace,
            Cap::ExactIfVersion => caps.exact_if_version,
            Cap::Watch => caps.watch != WatchKind::None,
            Cap::OwnerMode => caps.owner_mode,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Cap::Writable => "writable",
            Cap::AtomicReplace => "atomic_replace",
            Cap::ExactIfVersion => "exact_if_version",
            Cap::Watch => "watch",
            Cap::OwnerMode => "owner_mode",
        }
    }
}

/// What a case needs from the backend to be meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The backend declares this capability.
    Has(Cap),
    /// The backend declares this capability **false**: the case then proves it answers `Unsupported`.
    Lacks(Cap),
}

/// One conformance case.
#[derive(Clone, Copy)]
pub struct Case {
    /// A stable name, used in reports.
    pub name: &'static str,
    /// Capabilities required (all of them).
    pub requires: &'static [Requirement],
    run: fn(&Ctx<'_>) -> Outcome,
}

impl Debug for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Case")
            .field("name", &self.name)
            .field("requires", &self.requires)
            .finish()
    }
}

/// The result of running the suite on one backend.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// The label given to [`run`].
    pub backend: String,
    /// Names of the cases that passed.
    pub passed: Vec<String>,
    /// `(case, reason)` for each case skipped because of a declared capability.
    pub skipped: Vec<(String, String)>,
    /// `(case, reason)` for each failure.
    pub failed: Vec<(String, String)>,
}

impl Report {
    /// True if nothing failed. Skips are not failures: they are declared differences.
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }

    /// Panic with the full report if anything failed. For use in tests.
    pub fn assert_ok(&self) {
        assert!(self.is_ok(), "conformance failed:\n{self}");
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "conformance[{}]: {} passed, {} skipped, {} failed",
            self.backend,
            self.passed.len(),
            self.skipped.len(),
            self.failed.len()
        )?;
        for (case, why) in &self.skipped {
            writeln!(f, "  skipped {case}: {why}")?;
        }
        for (case, why) in &self.failed {
            writeln!(f, "  FAILED  {case}: {why}")?;
        }
        Ok(())
    }
}

/// Options for a run.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// Poll interval the watch cases ask for. Default 20 ms.
    pub watch_interval: Duration,
    /// How long a watch case waits for an expected batch before failing. Default 10 s.
    pub watch_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            watch_interval: Duration::from_millis(20),
            watch_timeout: Duration::from_secs(10),
        }
    }
}

type Outcome = Result<(), String>;

/// Run every case against `backend`. `label` names it in the report.
pub fn run(label: &str, backend: &dyn Backend) -> Report {
    run_with(label, backend, &Options::default())
}

/// [`run`] with options.
pub fn run_with(label: &str, backend: &dyn Backend, options: &Options) -> Report {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let caps = backend.caps();
    let mut report = Report {
        backend: label.to_string(),
        ..Report::default()
    };
    for case in CASES {
        if let Some(reason) = unmet(&caps, case.requires) {
            report.skipped.push((case.name.to_string(), reason));
            continue;
        }
        let base = if caps.writable {
            let name = format!(
                "conf-{:x}-{:x}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            );
            let base = NsPath::root()
                .join(&name)
                .expect("scratch name is inside the grammar");
            if let Err(e) = backend.write(&base, WriteOp::MakeDir, &[], None) {
                report.failed.push((
                    case.name.to_string(),
                    format!("could not create the scratch directory: {e}"),
                ));
                continue;
            }
            base
        } else {
            NsPath::root()
        };
        let ctx = Ctx {
            backend,
            base: base.clone(),
            options: options.clone(),
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| (case.run)(&ctx)))
            .unwrap_or_else(|p| Err(format!("panicked: {}", panic_text(&p))));
        if caps.writable {
            remove_tree(backend, &base);
        }
        match outcome {
            Ok(()) => report.passed.push(case.name.to_string()),
            Err(why) => report.failed.push((case.name.to_string(), why)),
        }
    }
    report
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic".to_string())
}

fn unmet(caps: &Caps, requires: &[Requirement]) -> Option<String> {
    for r in requires {
        match r {
            Requirement::Has(c) if !c.present(caps) => {
                return Some(format!("backend does not declare `{}`", c.name()));
            }
            Requirement::Lacks(c) if c.present(caps) => {
                return Some(format!(
                    "backend declares `{}`, so there is no missing capability to check",
                    c.name()
                ));
            }
            _ => {}
        }
    }
    None
}

/// Best-effort removal of a scratch tree.
fn remove_tree(backend: &dyn Backend, path: &NsPath) {
    if let Ok(entries) = backend.walk(path) {
        for e in entries {
            if let Some(child) = path.child(&e.name) {
                if e.kind == Kind::Dir {
                    remove_tree(backend, &child);
                } else {
                    let _ = backend.write(&child, WriteOp::Remove, &[], None);
                }
            }
        }
    }
    let _ = backend.write(path, WriteOp::Remove, &[], None);
}

// ---------------------------------------------------------------------------------------------------------------
// A mount seen through a Namespace, so the same cases can run through the mount table.
// ---------------------------------------------------------------------------------------------------------------

/// Presents the subtree of a [`Namespace`] at `base` as a [`Backend`], so [`run`] can exercise the mount table (longest
/// prefix, error rebasing, path mapping in watches) with exactly the cases a bare backend gets.
///
/// Its capabilities are those of the mount covering `base`. Use `ReadWrite` mounts: a `ReadOnly` mount answers
/// `PermissionDenied` to writes (the namespace's grant), not `Unsupported` (the backend's declaration).
pub struct ViaNamespace {
    ns: Namespace,
    base: NsPath,
    caps: Caps,
}

impl ViaNamespace {
    /// View `ns` at `base`, which must lie under a mount.
    pub fn new(ns: Namespace, base: NsPath) -> NsResult<Self> {
        let caps = ns
            .mounts()
            .filter(|(point, _, _)| base.starts_with(point))
            .max_by_key(|(point, _, _)| point.depth())
            .map(|(_, access, caps)| Caps {
                writable: caps.writable && access == super::Access::ReadWrite,
                ..caps
            })
            .ok_or_else(|| NsError::at(NsErrorKind::NotFound, &base))?;
        Ok(ViaNamespace { ns, base, caps })
    }

    fn up(&self, rel: &NsPath) -> NsResult<NsPath> {
        rel.rebase(&self.base)
    }

    fn down(&self, e: NsError) -> NsError {
        match e.path().and_then(|p| p.strip_prefix(&self.base)) {
            Some(rel) => NsError::at(e.kind(), &rel),
            None => NsError::new(e.kind()),
        }
    }
}

impl Backend for ViaNamespace {
    fn caps(&self) -> Caps {
        self.caps
    }

    fn walk(&self, path: &NsPath) -> NsResult<Vec<Entry>> {
        self.ns.walk(&self.up(path)?).map_err(|e| self.down(e))
    }

    fn read(&self, path: &NsPath, max: u64) -> NsResult<(Vec<u8>, Version)> {
        self.ns.read(&self.up(path)?, max).map_err(|e| self.down(e))
    }

    fn stat(&self, path: &NsPath) -> NsResult<Stat> {
        self.ns.stat(&self.up(path)?).map_err(|e| self.down(e))
    }

    fn write(
        &self,
        path: &NsPath,
        op: WriteOp,
        data: &[u8],
        if_version: Option<&Version>,
    ) -> NsResult<Version> {
        let op = match op {
            WriteOp::RenameWithinMount { to } => WriteOp::RenameWithinMount { to: self.up(&to)? },
            other => other,
        };
        self.ns
            .write(&self.up(path)?, op, data, if_version)
            .map_err(|e| self.down(e))
    }

    fn watch(&self, path: &NsPath, opts: WatchOpts) -> NsResult<Watch> {
        let base = self.base.clone();
        let w = self
            .ns
            .watch(&self.up(path)?, opts)
            .map_err(|e| self.down(e))?;
        Ok(w.map_paths(move |p| p.strip_prefix(&base)))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Case plumbing
// ---------------------------------------------------------------------------------------------------------------

struct Ctx<'a> {
    backend: &'a dyn Backend,
    base: NsPath,
    options: Options,
}

impl Ctx<'_> {
    fn p(&self, rel: &str) -> NsPath {
        self.base
            .join(rel)
            .expect("case paths are inside the grammar")
    }

    fn put(&self, rel: &str, data: &[u8]) -> Result<Version, String> {
        expect(
            self.backend
                .write(&self.p(rel), WriteOp::CreateExclusive, data, None),
            &format!("create {rel}"),
        )
    }

    fn mkdir(&self, rel: &str) -> Result<Version, String> {
        expect(
            self.backend
                .write(&self.p(rel), WriteOp::MakeDir, &[], None),
            &format!("mkdir {rel}"),
        )
    }

    fn replace(&self, rel: &str, data: &[u8], v: Option<&Version>) -> NsResult<Version> {
        self.backend.write(&self.p(rel), WriteOp::Replace, data, v)
    }

    fn get(&self, rel: &str) -> Result<(Vec<u8>, Version), String> {
        expect(
            self.backend.read(&self.p(rel), 1 << 20),
            &format!("read {rel}"),
        )
    }

    fn names(&self, rel: &str) -> Result<Vec<(String, Kind)>, String> {
        let path = if rel.is_empty() {
            self.base.clone()
        } else {
            self.p(rel)
        };
        let entries = expect(self.backend.walk(&path), &format!("walk {rel:?}"))?;
        Ok(entries.into_iter().map(|e| (e.name, e.kind)).collect())
    }

    fn watch_opts(&self, recursive: bool) -> WatchOpts {
        WatchOpts::default()
            .recursive(recursive)
            .interval(self.options.watch_interval)
    }
}

macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+));
        }
    };
}

fn expect<T>(r: NsResult<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: unexpected error: {e}"))
}

fn refuse<T: Debug>(r: NsResult<T>, kind: NsErrorKind, what: &str) -> Outcome {
    match r {
        Ok(v) => Err(format!("{what}: expected {kind:?}, got Ok({v:?})")),
        Err(e) if e.kind() == kind => Ok(()),
        Err(e) => Err(format!("{what}: expected {kind:?}, got {:?}", e.kind())),
    }
}

fn unsupported<T: Debug>(r: NsResult<T>, what: &str) -> Outcome {
    match r {
        Ok(v) => Err(format!(
            "{what}: backend declares this capability false but returned Ok({v:?})"
        )),
        Err(e) if matches!(e.kind(), NsErrorKind::Unsupported(_)) => Ok(()),
        Err(e) => Err(format!("{what}: expected Unsupported, got {:?}", e.kind())),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------------------------------

use Cap::{AtomicReplace, ExactIfVersion, OwnerMode, Watch as WatchCap, Writable};
use Requirement::{Has, Lacks};

const W: &[Requirement] = &[Has(Writable)];
/// Cases that call `Replace` (to modify a file) need it declared.
const WR: &[Requirement] = &[Has(Writable), Has(AtomicReplace)];
const WATCHED: &[Requirement] = &[Has(Writable), Has(WatchCap)];
const WATCHED_R: &[Requirement] = &[Has(Writable), Has(WatchCap), Has(AtomicReplace)];

macro_rules! case {
    ($name:literal, $requires:expr, $f:expr) => {
        Case {
            name: $name,
            requires: $requires,
            run: $f,
        }
    };
}

/// Every case, in the order they run.
pub const CASES: &[Case] = &[
    case!("read_missing_is_not_found", &[], read_missing_is_not_found),
    case!(
        "read_directory_is_a_directory",
        &[],
        read_directory_is_a_directory
    ),
    case!("walk_missing_is_not_found", &[], walk_missing_is_not_found),
    case!("stat_directory", &[], stat_directory),
    case!(
        "owner_and_mode_reported",
        &[Has(OwnerMode)],
        owner_and_mode_reported
    ),
    case!(
        "owner_and_mode_absent",
        &[Lacks(OwnerMode)],
        owner_and_mode_absent
    ),
    case!("write_roundtrip", WR, write_roundtrip),
    case!("read_over_max_is_too_large", W, read_over_max_is_too_large),
    case!("create_exclusive", W, create_exclusive),
    case!(
        "create_needs_a_directory_parent",
        W,
        create_needs_a_directory_parent
    ),
    case!("make_dir_and_walk", W, make_dir_and_walk),
    case!(
        "walk_is_sorted_in_utf8_byte_order",
        W,
        walk_is_sorted_in_utf8_byte_order
    ),
    case!(
        "case_collisions_are_refused",
        WR,
        case_collisions_are_refused
    ),
    case!("replace_semantics", WR, replace_semantics),
    case!("remove_semantics", W, remove_semantics),
    case!("rename_within_mount", W, rename_within_mount),
    case!("if_version_sequence", WR, if_version_sequence),
    case!(
        "if_version_is_exact_under_contention",
        &[Has(Writable), Has(AtomicReplace), Has(ExactIfVersion)],
        if_version_is_exact_under_contention
    ),
    case!(
        "data_refused_where_none_is_taken",
        W,
        data_refused_where_none_is_taken
    ),
    case!(
        "writes_are_unsupported_when_not_writable",
        &[Lacks(Writable)],
        writes_are_unsupported
    ),
    case!(
        "replace_is_unsupported_without_atomic_replace",
        &[Has(Writable), Lacks(AtomicReplace)],
        replace_unsupported
    ),
    case!(
        "watch_is_unsupported_without_watch",
        &[Lacks(WatchCap)],
        watch_unsupported
    ),
    case!(
        "watch_reports_create_modify_remove",
        WATCHED_R,
        watch_create_modify_remove
    ),
    case!(
        "watch_reports_replace_and_rename",
        WATCHED_R,
        watch_replace_and_rename
    ),
    case!(
        "watch_recursive_and_not",
        WATCHED_R,
        watch_recursive_and_not
    ),
    case!(
        "watch_target_must_be_a_directory",
        WATCHED,
        watch_target_must_be_a_directory
    ),
    case!(
        "watch_vanished_directory_rescans_and_recovers",
        WATCHED,
        watch_vanished_rescans
    ),
    case!(
        "watch_batches_are_sorted_unique_and_numbered",
        WATCHED,
        watch_batches_well_formed
    ),
    case!("watch_over_cap_becomes_rescan", WATCHED, watch_over_cap),
    case!("watch_drop_stops_it", WATCHED, watch_drop),
];

fn read_missing_is_not_found(c: &Ctx<'_>) -> Outcome {
    refuse(
        c.backend.read(&c.p("no-such-file"), 10),
        NsErrorKind::NotFound,
        "read missing",
    )?;
    refuse(
        c.backend.stat(&c.p("no-such-file")),
        NsErrorKind::NotFound,
        "stat missing",
    )
}

fn read_directory_is_a_directory(c: &Ctx<'_>) -> Outcome {
    refuse(
        c.backend.read(&c.base, 10),
        NsErrorKind::IsADirectory,
        "read of a directory",
    )
}

fn walk_missing_is_not_found(c: &Ctx<'_>) -> Outcome {
    refuse(
        c.backend.walk(&c.p("no-such-dir")),
        NsErrorKind::NotFound,
        "walk missing",
    )
}

fn stat_directory(c: &Ctx<'_>) -> Outcome {
    let a = expect(c.backend.stat(&c.base), "stat base")?;
    ensure!(
        a.kind == Kind::Dir,
        "a directory must stat as Dir, got {:?}",
        a.kind
    );
    ensure!(
        a.size == 0,
        "a directory's size must be reported as 0, got {}",
        a.size
    );
    let b = expect(c.backend.stat(&c.base), "stat base again")?;
    ensure!(
        a.version == b.version,
        "an unchanged directory must keep its version"
    );
    let root = expect(c.backend.stat(&NsPath::root()), "stat root")?;
    ensure!(root.kind == Kind::Dir, "the root must stat as Dir");
    Ok(())
}

fn owner_and_mode_reported(c: &Ctx<'_>) -> Outcome {
    let s = expect(c.backend.stat(&c.base), "stat base")?;
    ensure!(
        s.owner.is_some() && s.mode.is_some(),
        "owner_mode is declared but owner/mode are missing: {s:?}"
    );
    Ok(())
}

fn owner_and_mode_absent(c: &Ctx<'_>) -> Outcome {
    let s = expect(c.backend.stat(&c.base), "stat base")?;
    ensure!(
        s.owner.is_none() && s.mode.is_none(),
        "owner_mode is not declared but owner/mode are present: {s:?}"
    );
    Ok(())
}

fn write_roundtrip(c: &Ctx<'_>) -> Outcome {
    let v = expect(
        c.replace("a.txt", b"hello", None),
        "replace creates a missing file",
    )?;
    let (bytes, rv) = c.get("a.txt")?;
    ensure!(bytes == b"hello", "read back {bytes:?}");
    ensure!(
        v == rv,
        "write's version {v:?} must equal the next read's {rv:?}"
    );
    let st = expect(c.backend.stat(&c.p("a.txt")), "stat")?;
    ensure!(st.kind == Kind::File && st.size == 5, "stat says {st:?}");
    ensure!(st.version == rv, "stat's version must equal read's");
    let empty = expect(c.replace("empty", b"", None), "replace with nothing")?;
    let (bytes, rv) = c.get("empty")?;
    ensure!(bytes.is_empty() && rv == empty, "an empty file round-trips");
    Ok(())
}

fn read_over_max_is_too_large(c: &Ctx<'_>) -> Outcome {
    c.put("ten", b"0123456789")?;
    let (bytes, _) = expect(c.backend.read(&c.p("ten"), 10), "read at exactly max")?;
    ensure!(
        bytes.len() == 10,
        "reading at exactly max returns the whole file"
    );
    refuse(
        c.backend.read(&c.p("ten"), 9),
        NsErrorKind::TooLarge,
        "read over max",
    )?;
    refuse(
        c.backend.read(&c.p("ten"), 0),
        NsErrorKind::TooLarge,
        "read with max 0",
    )
}

fn create_exclusive(c: &Ctx<'_>) -> Outcome {
    let v = c.put("x", b"one")?;
    let st = expect(c.backend.stat(&c.p("x")), "stat")?;
    ensure!(st.version == v, "create's version must equal stat's");
    refuse(
        c.backend
            .write(&c.p("x"), WriteOp::CreateExclusive, b"two", None),
        NsErrorKind::AlreadyExists,
        "second create",
    )?;
    let (bytes, _) = c.get("x")?;
    ensure!(bytes == b"one", "a refused create must not change the file");
    Ok(())
}

fn create_needs_a_directory_parent(c: &Ctx<'_>) -> Outcome {
    refuse(
        c.backend
            .write(&c.p("nodir/f"), WriteOp::CreateExclusive, b"x", None),
        NsErrorKind::NotFound,
        "create in a missing directory",
    )?;
    c.put("file", b"x")?;
    refuse(
        c.backend
            .write(&c.p("file/f"), WriteOp::CreateExclusive, b"x", None),
        NsErrorKind::NotADirectory,
        "create under a file",
    )?;
    refuse(
        c.backend.walk(&c.p("file")),
        NsErrorKind::NotADirectory,
        "walk of a file",
    )
}

fn make_dir_and_walk(c: &Ctx<'_>) -> Outcome {
    c.mkdir("d")?;
    c.put("d/inner", b"i")?;
    c.put("b.txt", b"b")?;
    c.put("a.txt", b"a")?;
    let got = c.names("")?;
    let want = vec![
        ("a.txt".to_string(), Kind::File),
        ("b.txt".to_string(), Kind::File),
        ("d".to_string(), Kind::Dir),
    ];
    ensure!(
        got == want,
        "walk must be sorted by name with kinds: got {got:?}"
    );
    let inner = c.names("d")?;
    ensure!(
        inner == vec![("inner".to_string(), Kind::File)],
        "walk d: {inner:?}"
    );
    refuse(
        c.backend.write(&c.p("d"), WriteOp::MakeDir, &[], None),
        NsErrorKind::AlreadyExists,
        "mkdir over a directory",
    )?;
    refuse(
        c.backend.write(&c.p("x/y"), WriteOp::MakeDir, &[], None),
        NsErrorKind::NotFound,
        "mkdir without its parent",
    )
}

fn walk_is_sorted_in_utf8_byte_order(c: &Ctx<'_>) -> Outcome {
    // Chosen so that byte order differs from every "friendly" order: upper case before lower, an accented letter after
    // `z`, a CJK name after that, an astral character last. None of them fold-collides with another.
    let names = [
        "zebra",
        "Zulu",
        "alpha",
        "\u{e9}clair",
        "\u{4e2d}\u{6587}",
        "\u{1f600}smile",
        "Beta",
        "10",
        "9",
    ];
    for n in names {
        c.put(n, b"x")?;
    }
    let got: Vec<String> = c.names("")?.into_iter().map(|(n, _)| n).collect();
    let mut want: Vec<String> = names.iter().map(|s| (*s).to_string()).collect();
    want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ensure!(
        got == want,
        "walk must be sorted by name in UTF-8 byte order: got {got:?}, want {want:?}"
    );
    Ok(())
}

fn case_collisions_are_refused(c: &Ctx<'_>) -> Outcome {
    c.put("Readme.txt", b"1")?;
    refuse(
        c.backend
            .write(&c.p("README.TXT"), WriteOp::CreateExclusive, b"2", None),
        NsErrorKind::CaseCollision,
        "create of a case-colliding name",
    )?;
    refuse(
        c.backend
            .write(&c.p("readme.txt"), WriteOp::Replace, b"2", None),
        NsErrorKind::CaseCollision,
        "replace creating a case-colliding name",
    )?;
    refuse(
        c.backend
            .write(&c.p("ReadMe.Txt"), WriteOp::MakeDir, &[], None),
        NsErrorKind::CaseCollision,
        "mkdir of a case-colliding name",
    )?;
    c.put("other", b"3")?;
    refuse(
        c.backend.write(
            &c.p("other"),
            WriteOp::RenameWithinMount {
                to: c.p("README.txt"),
            },
            &[],
            None,
        ),
        NsErrorKind::CaseCollision,
        "rename onto a case-colliding name",
    )?;
    // The exact name is still fine to replace, and `ß` meets `SS` (the fold is Unicode, not ASCII).
    expect(
        c.replace("Readme.txt", b"3", None),
        "replace of the exact existing name",
    )?;
    c.put("stra\u{df}e", b"x")?;
    refuse(
        c.backend
            .write(&c.p("STRASSE"), WriteOp::CreateExclusive, b"y", None),
        NsErrorKind::CaseCollision,
        "create of a name that folds to an existing one only under Unicode folding",
    )?;
    let names = c.names("")?;
    ensure!(
        names
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("readme.txt"))
            .count()
            == 1,
        "exactly one readme must exist: {names:?}"
    );
    Ok(())
}

fn replace_semantics(c: &Ctx<'_>) -> Outcome {
    let v1 = expect(c.replace("f", b"one", None), "first replace")?;
    let v2 = expect(c.replace("f", b"two!", None), "second replace")?;
    ensure!(v1 != v2, "a replace must change the version");
    let (bytes, v) = c.get("f")?;
    ensure!(
        bytes == b"two!" && v == v2,
        "replace content/version: {bytes:?}"
    );
    c.mkdir("dir")?;
    refuse(
        c.replace("dir", b"x", None),
        NsErrorKind::IsADirectory,
        "replace of a directory",
    )?;
    refuse(
        c.replace("nodir/f", b"x", None),
        NsErrorKind::NotFound,
        "replace in a missing directory",
    )?;
    // Temporary files used to make the replace atomic must never be visible, and every listed name must be addressable.
    for (name, _) in c.names("")? {
        ensure!(
            validate_name(&name).is_ok(),
            "listing contains a name outside the grammar: {name:?}"
        );
    }
    Ok(())
}

fn remove_semantics(c: &Ctx<'_>) -> Outcome {
    let v = c.put("f", b"x")?;
    let removed = expect(
        c.backend.write(&c.p("f"), WriteOp::Remove, &[], None),
        "remove a file",
    )?;
    ensure!(removed == v, "remove returns the version the entry had");
    refuse(
        c.backend.read(&c.p("f"), 10),
        NsErrorKind::NotFound,
        "read after remove",
    )?;
    refuse(
        c.backend.write(&c.p("f"), WriteOp::Remove, &[], None),
        NsErrorKind::NotFound,
        "remove of a missing file",
    )?;
    c.mkdir("d")?;
    c.put("d/x", b"x")?;
    refuse(
        c.backend.write(&c.p("d"), WriteOp::Remove, &[], None),
        NsErrorKind::NotEmpty,
        "remove of a non-empty directory",
    )?;
    expect(
        c.backend.write(&c.p("d/x"), WriteOp::Remove, &[], None),
        "remove d/x",
    )?;
    expect(
        c.backend.write(&c.p("d"), WriteOp::Remove, &[], None),
        "remove empty d",
    )?;
    // The root cannot be removed (the exact kind is the backend's: a mount root is InvalidInput, a view of a
    // non-empty subtree is NotEmpty), and it must still be there afterwards.
    ensure!(
        c.backend
            .write(&NsPath::root(), WriteOp::Remove, &[], None)
            .is_err(),
        "removing the root must be refused"
    );
    expect(
        c.backend.stat(&NsPath::root()),
        "stat of the root after a refused remove",
    )?;
    Ok(())
}

fn rename_within_mount(c: &Ctx<'_>) -> Outcome {
    c.put("a", b"AAA")?;
    c.put("b", b"BBB")?;
    expect(
        c.backend.write(
            &c.p("a"),
            WriteOp::RenameWithinMount { to: c.p("c") },
            &[],
            None,
        ),
        "rename a to c",
    )?;
    refuse(
        c.backend.read(&c.p("a"), 10),
        NsErrorKind::NotFound,
        "old name after rename",
    )?;
    ensure!(c.get("c")?.0 == b"AAA", "renamed content");
    refuse(
        c.backend.write(
            &c.p("c"),
            WriteOp::RenameWithinMount { to: c.p("b") },
            &[],
            None,
        ),
        NsErrorKind::AlreadyExists,
        "rename onto an existing name",
    )?;
    ensure!(
        c.get("b")?.0 == b"BBB",
        "a refused rename must not touch the destination"
    );
    refuse(
        c.backend.write(
            &c.p("zz"),
            WriteOp::RenameWithinMount { to: c.p("yy") },
            &[],
            None,
        ),
        NsErrorKind::NotFound,
        "rename of a missing source",
    )?;
    refuse(
        c.backend.write(
            &c.p("c"),
            WriteOp::RenameWithinMount { to: c.p("nodir/c") },
            &[],
            None,
        ),
        NsErrorKind::NotFound,
        "rename into a missing directory",
    )?;
    // Directories move with their contents, across directories.
    c.mkdir("d1")?;
    c.mkdir("d2")?;
    c.put("d1/f", b"F")?;
    expect(
        c.backend.write(
            &c.p("d1"),
            WriteOp::RenameWithinMount {
                to: c.p("d2/moved"),
            },
            &[],
            None,
        ),
        "rename a directory",
    )?;
    ensure!(
        c.get("d2/moved/f")?.0 == b"F",
        "directory contents moved with it"
    );
    refuse(
        c.backend.write(
            &c.p("d2"),
            WriteOp::RenameWithinMount {
                to: c.p("d2/moved/inside"),
            },
            &[],
            None,
        ),
        NsErrorKind::InvalidInput(InputReason::MoveIntoSelf),
        "rename of a directory into itself",
    )?;
    // Onto itself is not a no-op: the name is taken.
    refuse(
        c.backend.write(
            &c.p("c"),
            WriteOp::RenameWithinMount { to: c.p("c") },
            &[],
            None,
        ),
        NsErrorKind::AlreadyExists,
        "rename of an entry onto itself",
    )?;
    // A rename that changes only the case of one's own name is allowed.
    expect(
        c.backend.write(
            &c.p("c"),
            WriteOp::RenameWithinMount { to: c.p("C") },
            &[],
            None,
        ),
        "case-only rename of one's own name",
    )?;
    ensure!(c.get("C")?.0 == b"AAA", "case-only rename keeps content");
    Ok(())
}

fn if_version_sequence(c: &Ctx<'_>) -> Outcome {
    let v1 = c.put("f", b"1")?;
    let v2 = expect(
        c.replace("f", b"2", Some(&v1)),
        "replace with the current version",
    )?;
    ensure!(v1 != v2, "a replace changes the version");
    refuse(
        c.replace("f", b"3", Some(&v1)),
        NsErrorKind::VersionMismatch,
        "replace with a stale version",
    )?;
    ensure!(
        c.get("f")?.0 == b"2",
        "a refused replace must not change the file"
    );
    refuse(
        c.backend.write(&c.p("f"), WriteOp::Remove, &[], Some(&v1)),
        NsErrorKind::VersionMismatch,
        "remove with a stale version",
    )?;
    refuse(
        c.backend.write(
            &c.p("f"),
            WriteOp::RenameWithinMount { to: c.p("g") },
            &[],
            Some(&v1),
        ),
        NsErrorKind::VersionMismatch,
        "rename with a stale version",
    )?;
    refuse(
        c.replace("missing", b"x", Some(&v1)),
        NsErrorKind::NotFound,
        "versioned replace of a missing file",
    )?;
    refuse(
        c.backend
            .write(&c.p("new"), WriteOp::CreateExclusive, b"x", Some(&v1)),
        NsErrorKind::InvalidInput(InputReason::VersionOnCreate),
        "versioned create",
    )?;
    expect(
        c.backend.write(&c.p("f"), WriteOp::Remove, &[], Some(&v2)),
        "remove with the current version",
    )?;
    Ok(())
}

fn if_version_is_exact_under_contention(c: &Ctx<'_>) -> Outcome {
    const RACERS: usize = 8;
    let v0 = c.put("f", b"start")?;
    let barrier = Barrier::new(RACERS);
    let results: Vec<NsResult<Version>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..RACERS)
            .map(|i| {
                let (barrier, v0) = (&barrier, &v0);
                s.spawn(move || {
                    barrier.wait();
                    c.replace("f", format!("racer {i}").as_bytes(), Some(v0))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("racer panicked"))
            .collect()
    });
    let winners = results.iter().filter(|r| r.is_ok()).count();
    ensure!(
        winners == 1,
        "exact_if_version is declared, so exactly one racer may win; {winners} did"
    );
    for r in results.iter().filter_map(|r| r.as_ref().err()) {
        ensure!(
            r.kind() == NsErrorKind::VersionMismatch,
            "a loser must see VersionMismatch, saw {:?}",
            r.kind()
        );
    }
    Ok(())
}

fn data_refused_where_none_is_taken(c: &Ctx<'_>) -> Outcome {
    c.put("f", b"x")?;
    let is_invalid = |r: NsResult<Version>, what: &str| match r {
        Err(e) if matches!(e.kind(), NsErrorKind::InvalidInput(_)) => Ok(()),
        other => Err(format!("{what}: expected InvalidInput, got {other:?}")),
    };
    is_invalid(
        c.backend.write(&c.p("f"), WriteOp::Remove, b"data", None),
        "remove with data",
    )?;
    is_invalid(
        c.backend.write(&c.p("d"), WriteOp::MakeDir, b"data", None),
        "mkdir with data",
    )?;
    is_invalid(
        c.backend.write(
            &c.p("f"),
            WriteOp::RenameWithinMount { to: c.p("g") },
            b"data",
            None,
        ),
        "rename with data",
    )?;
    ensure!(
        c.get("f")?.0 == b"x",
        "a refused operation must not change anything"
    );
    Ok(())
}

fn writes_are_unsupported(c: &Ctx<'_>) -> Outcome {
    let p = c.p("f");
    unsupported(
        c.backend.write(&p, WriteOp::CreateExclusive, b"x", None),
        "create",
    )?;
    unsupported(c.backend.write(&p, WriteOp::Replace, b"x", None), "replace")?;
    unsupported(c.backend.write(&p, WriteOp::Remove, &[], None), "remove")?;
    unsupported(c.backend.write(&p, WriteOp::MakeDir, &[], None), "mkdir")?;
    unsupported(
        c.backend
            .write(&p, WriteOp::RenameWithinMount { to: c.p("g") }, &[], None),
        "rename",
    )?;
    // Reads must still work.
    expect(c.backend.walk(&NsPath::root()), "walk of a read-only mount")?;
    Ok(())
}

fn replace_unsupported(c: &Ctx<'_>) -> Outcome {
    unsupported(c.replace("f", b"x", None), "replace")?;
    c.put("g", b"x")?;
    Ok(())
}

fn watch_unsupported(c: &Ctx<'_>) -> Outcome {
    unsupported(c.backend.watch(&c.base, WatchOpts::default()), "watch")
}

// --- watch helpers ---------------------------------------------------------------------------------------------

struct Watching {
    watch: Watch,
    cursor: WatchCursor,
    seen: Vec<WatchBatch>,
    unexpected_rescan: bool,
    timeout: Duration,
}

impl Watching {
    fn start(c: &Ctx<'_>, rel: &str, recursive: bool) -> Result<Self, String> {
        let path = if rel.is_empty() {
            c.base.clone()
        } else {
            c.p(rel)
        };
        let watch = expect(c.backend.watch(&path, c.watch_opts(recursive)), "watch")?;
        Ok(Watching {
            watch,
            cursor: WatchCursor::new(),
            seen: Vec::new(),
            unexpected_rescan: false,
            timeout: c.options.watch_timeout,
        })
    }

    /// Receive batches until one satisfies `pred`; returns an error on timeout.
    fn wait_for(
        &mut self,
        what: &str,
        pred: impl Fn(&WatchBatch) -> bool,
    ) -> Result<WatchBatch, String> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!("timed out waiting for {what}; saw {:?}", self.seen));
            }
            match self.watch.recv_timeout(left) {
                Ok(b) => {
                    if self.cursor.observe(&b) {
                        self.unexpected_rescan |= !pred(&b);
                    }
                    self.seen.push(b.clone());
                    if pred(&b) {
                        return Ok(b);
                    }
                }
                Err(_) => return Err(format!("timed out waiting for {what}; saw {:?}", self.seen)),
            }
        }
    }

    fn wait_for_path(&mut self, path: &NsPath) -> Result<WatchBatch, String> {
        let want = path.clone();
        self.wait_for(&format!("a change to {path}"), move |b| {
            !b.rescan && b.changed.contains(&want)
        })
    }

    fn ever_reported(&self, path: &NsPath) -> bool {
        self.seen.iter().any(|b| b.changed.contains(path))
    }
}

fn watch_create_modify_remove(c: &Ctx<'_>) -> Outcome {
    let mut w = Watching::start(c, "", false)?;
    let f = c.p("f");
    c.put("f", b"1")?;
    w.wait_for_path(&f).map_err(|e| format!("create: {e}"))?;
    expect(c.replace("f", b"22", None), "modify")?;
    w.wait_for_path(&f).map_err(|e| format!("modify: {e}"))?;
    expect(c.backend.write(&f, WriteOp::Remove, &[], None), "remove")?;
    w.wait_for_path(&f).map_err(|e| format!("remove: {e}"))?;
    ensure!(
        !w.unexpected_rescan,
        "an ordinary run of changes must not look like lost events: {:?}",
        w.seen
    );
    Ok(())
}

fn watch_replace_and_rename(c: &Ctx<'_>) -> Outcome {
    c.put("doc", b"v1")?;
    let mut w = Watching::start(c, "", false)?;
    // The editor pattern: the file is replaced atomically, its identity changes under the same name.
    let doc = c.p("doc");
    expect(c.replace("doc", b"v2 (replaced)", None), "replace")?;
    w.wait_for_path(&doc)
        .map_err(|e| format!("replace of an existing file: {e}"))?;
    expect(
        c.backend.write(
            &doc,
            WriteOp::RenameWithinMount { to: c.p("moved") },
            &[],
            None,
        ),
        "rename",
    )?;
    let (from, to) = (doc, c.p("moved"));
    w.wait_for(&format!("both {from} and {to}"), |b| {
        b.changed.contains(&from) && b.changed.contains(&to)
    })
    .or_else(|first| {
        // A polling backend might split the two sides across polls only if the rename straddled one; accept both
        // arriving, in either order, across batches.
        if w.ever_reported(&from) && w.ever_reported(&to) {
            Ok(WatchBatch::new(0, 0, vec![], false))
        } else {
            Err(first)
        }
    })
    .map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

fn watch_recursive_and_not(c: &Ctx<'_>) -> Outcome {
    c.mkdir("sub")?;
    let deep = c.p("sub/deep");
    {
        let mut shallow = Watching::start(c, "", false)?;
        c.put("sub/deep", b"x")?;
        let sentinel = c.p("sentinel");
        c.put("sentinel", b"x")?;
        shallow.wait_for_path(&sentinel)?;
        ensure!(
            !shallow.ever_reported(&deep),
            "a non-recursive watch must not report grandchildren: {:?}",
            shallow.seen
        );
    }
    let mut deep_watch = Watching::start(c, "", true)?;
    expect(c.replace("sub/deep", b"changed", None), "modify deep")?;
    deep_watch
        .wait_for_path(&deep)
        .map_err(|e| format!("a recursive watch must report a nested change: {e}"))?;
    Ok(())
}

fn watch_target_must_be_a_directory(c: &Ctx<'_>) -> Outcome {
    c.put("file", b"x")?;
    refuse(
        c.backend.watch(&c.p("file"), c.watch_opts(false)),
        NsErrorKind::NotADirectory,
        "watch of a file",
    )?;
    refuse(
        c.backend.watch(&c.p("nothing"), c.watch_opts(false)),
        NsErrorKind::NotFound,
        "watch of a missing path",
    )
}

fn watch_vanished_rescans(c: &Ctx<'_>) -> Outcome {
    c.mkdir("d")?;
    let d = c.p("d");
    let mut w = Watching::start(c, "d", false)?;
    expect(
        c.backend.write(&d, WriteOp::Remove, &[], None),
        "remove the watched directory",
    )?;
    let gone = w.wait_for("a rescan after the directory vanished", |b| b.rescan)?;
    ensure!(gone.changed.is_empty(), "a rescan batch carries no paths");
    c.mkdir("d")?;
    w.wait_for("a rescan when the directory returned", |b| b.rescan)?;
    c.put("d/back", b"x")?;
    w.wait_for_path(&c.p("d/back"))
        .map_err(|e| format!("the watch must keep working after the directory returns: {e}"))?;
    Ok(())
}

fn watch_batches_well_formed(c: &Ctx<'_>) -> Outcome {
    let mut w = Watching::start(c, "", false)?;
    for name in ["z", "m", "a", "k"] {
        c.put(name, b"x")?;
    }
    let last = c.p("k");
    w.wait_for_path(&last)?;
    let mut paths_seen = 0;
    for b in &w.seen {
        let mut sorted = b.changed.clone();
        sorted.sort();
        sorted.dedup();
        ensure!(
            sorted == b.changed,
            "changed must be sorted and unique: {:?}",
            b.changed
        );
        ensure!(
            b.changed.iter().all(|p| p.starts_with(&c.base)),
            "paths must be in the backend's namespace: {:?}",
            b.changed
        );
        paths_seen += b.changed.len();
    }
    ensure!(
        paths_seen >= 4,
        "all four creates must be reported, saw {paths_seen}"
    );
    let epoch = w.seen[0].epoch;
    ensure!(
        w.seen.iter().all(|b| b.epoch == epoch),
        "one watch has one epoch"
    );
    ensure!(
        w.seen
            .iter()
            .enumerate()
            .all(|(i, b)| b.generation == i as u64 + 1),
        "generation must start at 1 and rise by one: {:?}",
        w.seen.iter().map(|b| b.generation).collect::<Vec<_>>()
    );
    let other = Watching::start(c, "", false)?;
    c.put("again", b"x")?;
    let mut other = other;
    let first_of_other = other.wait_for_path(&c.p("again"))?;
    ensure!(
        first_of_other.epoch != epoch,
        "two watches must not share an epoch"
    );
    Ok(())
}

fn watch_over_cap(c: &Ctx<'_>) -> Outcome {
    c.put("one", b"x")?;
    let opts = c.watch_opts(false).max_entries(1);
    let watch = expect(c.backend.watch(&c.base, opts), "watch with a cap of 1")?;
    // A rename changes two paths at once, which is over a cap of 1.
    expect(
        c.backend.write(
            &c.p("one"),
            WriteOp::RenameWithinMount { to: c.p("two") },
            &[],
            None,
        ),
        "rename",
    )?;
    let deadline = Instant::now() + c.options.watch_timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let b = watch
            .recv_timeout(left)
            .map_err(|_| "timed out waiting for the over-cap rescan".to_string())?;
        if b.rescan {
            ensure!(
                b.changed.is_empty(),
                "past the cap the batch must be rescan with no paths, got {:?}",
                b.changed
            );
            return Ok(());
        }
        ensure!(
            b.changed.len() <= 1,
            "a batch exceeded max_entries without becoming a rescan: {:?}",
            b.changed
        );
    }
}

fn watch_drop(c: &Ctx<'_>) -> Outcome {
    let opts = c.watch_opts(false).interval(Duration::from_secs(30));
    let watch = expect(c.backend.watch(&c.base, opts), "watch with a long interval")?;
    // Drop on its own thread under a deadline: a watch that never signals its producer to stop would make `Drop` wait
    // forever, and a regression must FAIL here, not hang the run.
    let started = Instant::now();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(watch);
        let _ = done_tx.send(());
    });
    ensure!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "dropping a watch must stop it at once, not wait out its interval or hang (gave up after {:?})",
        started.elapsed()
    );
    // The backend must carry on normally after a watch is gone.
    c.put("after", b"x")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ns::{Access, HostDir, Memory, MemoryOptions};

    fn summary(r: &Report) -> String {
        format!("{r}")
    }

    #[test]
    fn memory_passes_every_case() {
        let r = run("memory", &Memory::new());
        r.assert_ok();
        let skipped: Vec<_> = r.skipped.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(
            skipped,
            [
                "owner_and_mode_reported",
                "writes_are_unsupported_when_not_writable",
                "replace_is_unsupported_without_atomic_replace",
                "watch_is_unsupported_without_watch"
            ],
            "{}",
            summary(&r)
        );
    }

    #[test]
    fn host_dir_passes_every_case() {
        let tmp = tempfile::tempdir().unwrap();
        let hd = HostDir::open_ambient(tmp.path()).unwrap();
        let r = run("host-dir", &hd);
        r.assert_ok();
        // HostDir declares inexact versions, so the contention case is reported as skipped, not silently absent.
        assert!(r
            .skipped
            .iter()
            .any(|(c, why)| c == "if_version_is_exact_under_contention"
                && why.contains("exact_if_version")));
        assert!(r.passed.len() >= 24, "{}", summary(&r));
    }

    #[test]
    fn read_only_memory_proves_unsupported() {
        let m = Memory::with_options(MemoryOptions {
            writable: false,
            ..MemoryOptions::default()
        });
        m.preload(&NsPath::parse("/seed/file").unwrap(), b"x")
            .unwrap();
        let r = run("memory-read-only", &m);
        r.assert_ok();
        assert!(
            r.passed
                .iter()
                .any(|c| c == "writes_are_unsupported_when_not_writable"),
            "{}",
            summary(&r)
        );
        assert!(r.skipped.iter().any(|(c, _)| c == "write_roundtrip"));
    }

    #[test]
    fn memory_without_atomic_replace_or_watch_proves_unsupported() {
        let m = Memory::with_options(MemoryOptions {
            atomic_replace: false,
            watch: false,
            ..MemoryOptions::default()
        });
        let r = run("memory-restricted", &m);
        r.assert_ok();
        for case in [
            "replace_is_unsupported_without_atomic_replace",
            "watch_is_unsupported_without_watch",
        ] {
            assert!(
                r.passed.iter().any(|c| c == case),
                "{case} must run and pass: {}",
                summary(&r)
            );
        }
        assert!(r
            .skipped
            .iter()
            .any(|(c, _)| c == "watch_reports_create_modify_remove"));
        assert!(r.skipped.iter().any(|(c, _)| c == "replace_semantics"));
    }

    #[test]
    fn two_mount_namespace_passes_every_case_on_both_mounts() {
        let tmp = tempfile::tempdir().unwrap();
        let ns = Namespace::builder()
            .mount(
                NsPath::parse("/mem").unwrap(),
                Arc::new(Memory::new()),
                Access::ReadWrite,
            )
            .mount(
                NsPath::parse("/host").unwrap(),
                Arc::new(HostDir::open_ambient(tmp.path()).unwrap()),
                Access::ReadWrite,
            )
            .build()
            .unwrap();
        for at in ["/mem", "/host"] {
            // View the mount root itself, and a subdirectory of it (so the prefix mapping is exercised).
            let root_view = ViaNamespace::new(ns.clone(), NsPath::parse(at).unwrap()).unwrap();
            run(&format!("namespace:{at}"), &root_view).assert_ok();
            let sub = NsPath::parse(at).unwrap().join("view").unwrap();
            ns.write(&sub, WriteOp::MakeDir, &[], None).unwrap();
            let sub_view = ViaNamespace::new(ns.clone(), sub).unwrap();
            run(&format!("namespace:{at}/view"), &sub_view).assert_ok();
        }
    }
}
