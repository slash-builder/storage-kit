//! The mount table: resolution, synthesised ancestors, grants, cross-mount rename, path rebasing.
#![cfg(feature = "ns")]

use std::sync::Arc;
use std::time::Duration;

use storage_kit::ns::{
    Access, Backend, Entry, Kind, Memory, MemoryOptions, Namespace, NsErrorKind, NsPath, WatchOpts,
    WriteOp,
};

fn p(s: &str) -> NsPath {
    NsPath::parse(s).unwrap()
}

fn mem() -> Arc<Memory> {
    Arc::new(Memory::new())
}

fn names(entries: &[Entry]) -> Vec<(&str, Kind)> {
    entries.iter().map(|e| (e.name.as_str(), e.kind)).collect()
}

fn kind<T: std::fmt::Debug>(r: Result<T, storage_kit::ns::NsError>) -> NsErrorKind {
    r.expect_err("expected an error").kind()
}

#[test]
fn longest_prefix_wins_and_mounts_nest() {
    let (outer, inner, root) = (mem(), mem(), mem());
    outer.preload(&p("/x/file"), b"from outer").unwrap();
    outer.preload(&p("/y"), b"outer y").unwrap();
    inner.preload(&p("/file"), b"from inner").unwrap();
    root.preload(&p("/data/x/file"), b"from the root mount")
        .unwrap();
    let ns = Namespace::builder()
        .mount(p("/"), root, Access::ReadWrite)
        .mount(p("/data"), outer, Access::ReadWrite)
        .mount(p("/data/x"), inner, Access::ReadWrite)
        .build()
        .unwrap();
    assert_eq!(ns.read(&p("/data/x/file"), 100).unwrap().0, b"from inner");
    assert_eq!(ns.read(&p("/data/y"), 100).unwrap().0, b"outer y");
    // The root mount still serves what no deeper mount claims.
    assert_eq!(ns.read(&p("/data/x/file"), 100).unwrap().0, b"from inner");
    // `/data/xylophone` is not under `/data/x`: prefixes are whole components.
    assert_eq!(
        kind(ns.read(&p("/data/xylophone"), 100)),
        NsErrorKind::NotFound
    );
    // A write lands in the deepest mount.
    ns.write(&p("/data/x/new"), WriteOp::Replace, b"n", None)
        .unwrap();
    assert_eq!(ns.read(&p("/data/x/new"), 100).unwrap().0, b"n");
}

#[test]
fn two_mounts_at_the_same_path_are_an_error() {
    let err = Namespace::builder()
        .mount(p("/a"), mem(), Access::ReadWrite)
        .mount(p("/a"), mem(), Access::ReadOnly)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::AlreadyExists);
    assert_eq!(err.path().map(NsPath::as_str), Some("/a"));
}

#[test]
fn mount_ancestors_are_synthesised_in_listings() {
    let ns = Namespace::builder()
        .mount(p("/config"), mem(), Access::ReadWrite)
        .mount(p("/data/x"), mem(), Access::ReadWrite)
        .mount(p("/data/y/z"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    assert_eq!(
        names(&ns.walk(&p("/")).unwrap()),
        [("config", Kind::Dir), ("data", Kind::Dir)]
    );
    assert_eq!(
        names(&ns.walk(&p("/data")).unwrap()),
        [("x", Kind::Dir), ("y", Kind::Dir)]
    );
    assert_eq!(names(&ns.walk(&p("/data/y")).unwrap()), [("z", Kind::Dir)]);
    assert!(ns.walk(&p("/config")).unwrap().is_empty());
    // Only the mounts exist: the rest of the tree is not there.
    assert_eq!(kind(ns.walk(&p("/other"))), NsErrorKind::NotFound);
    assert_eq!(kind(ns.walk(&p("/data/nothing"))), NsErrorKind::NotFound);
    // An ancestor is a directory with a stat, and is not a file.
    let st = ns.stat(&p("/data")).unwrap();
    assert_eq!((st.kind, st.size), (Kind::Dir, 0));
    assert_eq!(kind(ns.read(&p("/data"), 10)), NsErrorKind::IsADirectory);
    assert_eq!(kind(ns.stat(&p("/other"))), NsErrorKind::NotFound);
}

#[test]
fn a_mount_over_another_mounts_directory_merges_and_shadows() {
    let outer = mem();
    outer.preload(&p("/real"), b"r").unwrap();
    outer
        .preload(&p("/x"), b"a FILE named x in the outer mount")
        .unwrap();
    let ns = Namespace::builder()
        .mount(p("/data"), outer, Access::ReadWrite)
        .mount(p("/data/x"), mem(), Access::ReadWrite)
        .mount(p("/data/virtual/deep"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    // `x` is a mount, so it is a directory in the listing even though the outer mount has a file of that name.
    assert_eq!(
        names(&ns.walk(&p("/data")).unwrap()),
        [
            ("real", Kind::File),
            ("virtual", Kind::Dir),
            ("x", Kind::Dir)
        ]
    );
}

#[test]
fn read_only_is_enforced_by_the_namespace() {
    let backend = mem();
    backend.preload(&p("/f"), b"x").unwrap();
    let ns = Namespace::builder()
        .mount(p("/ro"), backend.clone(), Access::ReadOnly)
        .mount(p("/rw"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    for (op, data) in [
        (WriteOp::CreateExclusive, &b"x"[..]),
        (WriteOp::Replace, &b"x"[..]),
        (WriteOp::Remove, &b""[..]),
        (WriteOp::MakeDir, &b""[..]),
        (WriteOp::RenameWithinMount { to: p("/ro/g") }, &b""[..]),
    ] {
        let target = if matches!(op, WriteOp::CreateExclusive | WriteOp::MakeDir) {
            p("/ro/new")
        } else {
            p("/ro/f")
        };
        let err = ns.write(&target, op.clone(), data, None).unwrap_err();
        assert_eq!(err.kind(), NsErrorKind::PermissionDenied, "{op:?}");
        assert_eq!(
            err.path(),
            Some(&target),
            "the error names the namespace path"
        );
    }
    // The backend itself is untouched, and reading and watching a read-only mount still work.
    assert_eq!(backend.read(&p("/f"), 10).unwrap().0, b"x");
    assert_eq!(ns.read(&p("/ro/f"), 10).unwrap().0, b"x");
    assert!(ns.watch(&p("/ro"), WatchOpts::default()).is_ok());
    ns.write(&p("/rw/ok"), WriteOp::Replace, b"y", None)
        .unwrap();
}

#[test]
fn a_backend_that_is_not_writable_is_unsupported_even_under_read_write() {
    let frozen = Arc::new(Memory::with_options(
        MemoryOptions::default().writable(false),
    ));
    let ns = Namespace::builder()
        .mount(p("/m"), frozen, Access::ReadWrite)
        .build()
        .unwrap();
    assert!(matches!(
        kind(ns.write(&p("/m/f"), WriteOp::Replace, b"x", None)),
        NsErrorKind::Unsupported(_)
    ));
}

#[test]
fn writes_to_a_mount_ancestor_or_nowhere_are_refused() {
    let ns = Namespace::builder()
        .mount(p("/data/x"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    assert_eq!(
        kind(ns.write(&p("/data/new"), WriteOp::Replace, b"x", None)),
        NsErrorKind::NotFound
    );
    assert_eq!(
        kind(ns.write(&p("/data"), WriteOp::MakeDir, &[], None)),
        NsErrorKind::PermissionDenied
    );
    assert_eq!(
        kind(ns.write(&p("/nowhere/f"), WriteOp::Replace, b"x", None)),
        NsErrorKind::NotFound
    );
}

#[test]
fn a_rename_across_two_mounts_is_cross_mount() {
    let ns = Namespace::builder()
        .mount(p("/a"), mem(), Access::ReadWrite)
        .mount(p("/b"), mem(), Access::ReadWrite)
        .mount(p("/a/inner"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    ns.write(&p("/a/f"), WriteOp::Replace, b"x", None).unwrap();
    for to in ["/b/f", "/a/inner/f", "/nowhere/f"] {
        let err = ns
            .write(
                &p("/a/f"),
                WriteOp::RenameWithinMount { to: p(to) },
                &[],
                None,
            )
            .unwrap_err();
        assert_eq!(err.kind(), NsErrorKind::CrossMount, "{to}");
    }
    // Nothing moved, nothing was half done.
    assert_eq!(ns.read(&p("/a/f"), 10).unwrap().0, b"x");
    // Within one mount (nested mounts excluded) a rename works and uses namespace paths on both sides.
    ns.write(
        &p("/a/f"),
        WriteOp::RenameWithinMount { to: p("/a/g") },
        &[],
        None,
    )
    .unwrap();
    assert_eq!(ns.read(&p("/a/g"), 10).unwrap().0, b"x");
    assert_eq!(kind(ns.read(&p("/a/f"), 10)), NsErrorKind::NotFound);
}

#[test]
fn errors_from_a_mount_carry_the_namespace_path_not_the_mount_relative_one() {
    let ns = Namespace::builder()
        .mount(p("/deep/mount"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    let err = ns.read(&p("/deep/mount/missing"), 10).unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::NotFound);
    assert_eq!(err.path().unwrap().as_str(), "/deep/mount/missing");
    assert!(err.to_string().starts_with("/deep/mount/missing"), "{err}");
    let err = ns
        .write(&p("/deep/mount/a/b"), WriteOp::CreateExclusive, b"x", None)
        .unwrap_err();
    assert!(
        err.path().unwrap().starts_with(&p("/deep/mount")),
        "{err:?}"
    );
}

#[test]
fn a_watch_through_the_namespace_reports_namespace_paths() {
    let ns = Namespace::builder()
        .mount(p("/m"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    ns.write(&p("/m/dir"), WriteOp::MakeDir, &[], None).unwrap();
    let w = ns.watch(&p("/m/dir"), WatchOpts::default()).unwrap();
    ns.write(&p("/m/dir/f"), WriteOp::Replace, b"x", None)
        .unwrap();
    let batch = w.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(batch.changed, vec![p("/m/dir/f")]);
    // An ancestor that is only a name cannot be watched; nor can nothing.
    assert!(matches!(
        ns.watch(&p("/"), WatchOpts::default()).unwrap_err().kind(),
        NsErrorKind::Unsupported(_)
    ));
    assert_eq!(
        kind(ns.watch(&p("/other"), WatchOpts::default())),
        NsErrorKind::NotFound
    );
    assert_eq!(
        kind(ns.watch(&p("/m/dir/f"), WatchOpts::default())),
        NsErrorKind::NotADirectory
    );
}

#[test]
fn if_version_passes_through_the_namespace() {
    let ns = Namespace::builder()
        .mount(p("/m"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    let v1 = ns.write(&p("/m/f"), WriteOp::Replace, b"1", None).unwrap();
    ns.write(&p("/m/f"), WriteOp::Replace, b"2", Some(&v1))
        .unwrap();
    assert_eq!(
        kind(ns.write(&p("/m/f"), WriteOp::Replace, b"3", Some(&v1))),
        NsErrorKind::VersionMismatch
    );
}

#[test]
fn the_mount_table_can_be_inspected() {
    let ns = Namespace::builder()
        .mount(p("/a"), mem(), Access::ReadOnly)
        .mount(p("/b"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    let listed: Vec<_> = ns
        .mounts()
        .map(|(point, access, caps)| (point.to_string(), access, caps.writable))
        .collect();
    assert_eq!(
        listed,
        [
            ("/a".to_string(), Access::ReadOnly, true),
            ("/b".to_string(), Access::ReadWrite, true)
        ]
    );
    assert!(format!("{ns:?}").contains("/a"));
}
