//! The mount table: resolution, synthesised ancestors, grants, cross-mount rename, path rebasing.
#![cfg(feature = "ns")]

use std::sync::Arc;
use std::time::Duration;

use storage_kit::ns::{
    Access, Backend, Entry, InputReason, Kind, Memory, MemoryOptions, Namespace, NsErrorKind,
    NsPath, WatchOpts, WriteOp,
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
fn a_real_entry_wins_over_a_mount_point_for_what_it_is() {
    // The mount at /a has a FILE `b`; another mount sits at /a/b/c, which cannot hang off a file.
    let outer = mem();
    outer.preload(&p("/b"), b"I am a file").unwrap();
    outer.preload(&p("/real"), b"r").unwrap();
    let ns = Namespace::builder()
        .mount(p("/a"), outer, Access::ReadWrite)
        .mount(p("/a/b/c"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    // Every verb agrees that `b` is a file ...
    assert_eq!(
        names(&ns.walk(&p("/a")).unwrap()),
        [("b", Kind::File), ("real", Kind::File)]
    );
    assert_eq!(ns.stat(&p("/a/b")).unwrap().kind, Kind::File);
    assert_eq!(ns.read(&p("/a/b"), 100).unwrap().0, b"I am a file");
    assert_eq!(kind(ns.walk(&p("/a/b"))), NsErrorKind::NotADirectory);
    // ... and the nested mount is what is refused, by a named error that points at the file in the way.
    for result in [
        ns.walk(&p("/a/b/c")).map(|_| ()),
        ns.stat(&p("/a/b/c/f")).map(|_| ()),
        ns.read(&p("/a/b/c/f"), 10).map(|_| ()),
        ns.write(&p("/a/b/c/f"), WriteOp::Replace, b"x", None)
            .map(|_| ()),
        ns.watch(&p("/a/b/c"), WatchOpts::default()).map(|_| ()),
    ] {
        let err = result.unwrap_err();
        assert_eq!(err.kind(), NsErrorKind::NotADirectory, "{err:?}");
        assert_eq!(err.path().map(NsPath::as_str), Some("/a/b"));
    }
}

#[test]
fn a_mount_under_a_directory_or_under_nothing_works_and_lists_once() {
    let outer = mem();
    outer.preload(&p("/dir/keep"), b"k").unwrap();
    let ns = Namespace::builder()
        .mount(p("/a"), outer, Access::ReadWrite)
        .mount(p("/a/dir/c"), mem(), Access::ReadWrite) // under a real directory
        .mount(p("/a/virtual/deep/c"), mem(), Access::ReadWrite) // under nothing: synthetic
        .build()
        .unwrap();
    assert_eq!(
        names(&ns.walk(&p("/a")).unwrap()),
        [("dir", Kind::Dir), ("virtual", Kind::Dir)]
    );
    assert_eq!(
        names(&ns.walk(&p("/a/dir")).unwrap()),
        [("c", Kind::Dir), ("keep", Kind::File)]
    );
    ns.write(&p("/a/dir/c/f"), WriteOp::Replace, b"x", None)
        .unwrap();
    ns.write(&p("/a/virtual/deep/c/f"), WriteOp::Replace, b"x", None)
        .unwrap();
    assert_eq!(ns.read(&p("/a/virtual/deep/c/f"), 10).unwrap().0, b"x");
}

#[test]
fn a_mount_name_that_folds_equal_to_a_backend_entry_is_listed_once() {
    let root = mem();
    root.preload(&p("/config/file"), b"x").unwrap();
    let ns = Namespace::builder()
        .mount(p("/"), root, Access::ReadWrite)
        .mount(p("/Config/sub"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    let listing = ns.walk(&p("/")).unwrap();
    assert_eq!(
        names(&listing),
        [("config", Kind::Dir)],
        "one entry, the backend's spelling"
    );
}

#[test]
fn walk_is_sorted_by_name_in_utf8_byte_order_with_synthesised_names_merged() {
    let root = mem();
    root.preload(&p("/m"), b"x").unwrap();
    root.preload(&p("/Y"), b"x").unwrap();
    let ns = Namespace::builder()
        .mount(p("/"), root, Access::ReadWrite)
        .mount(p("/z/deep"), mem(), Access::ReadWrite)
        .mount(p("/B/deep"), mem(), Access::ReadWrite)
        .mount(p("/\u{e9}/deep"), mem(), Access::ReadWrite)
        .mount(p("/a/deep"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    let got: Vec<String> = ns
        .walk(&p("/"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    // Upper case sorts before lower case, and the accented letter after `z`: bytes, not locale or case-folded order.
    assert_eq!(got, ["B", "Y", "a", "m", "z", "\u{e9}"]);
}

/// Two mounts over the same host directory are refused, whatever the grants and wherever they sit: a grant is per mount,
/// so a write through one would change what the other (perhaps read-only) one reads.
#[test]
fn the_same_host_directory_mounted_twice_is_refused() {
    use storage_kit::ns::HostDir;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path();
    let one = Arc::new(HostDir::open_ambient(path).unwrap());
    // The same Arc twice, and two independent opens of the same directory, are both "the same directory".
    let again = Arc::new(HostDir::open_ambient(path).unwrap());
    let from_handle = Arc::new(
        HostDir::from_dir(
            cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority()).unwrap(),
        )
        .unwrap(),
    );
    assert!(one.root_identity().is_some());

    for (a, b) in [
        (Access::ReadWrite, Access::ReadOnly),
        (Access::ReadOnly, Access::ReadWrite),
        (Access::ReadWrite, Access::ReadWrite),
        (Access::ReadOnly, Access::ReadOnly),
    ] {
        for second in [one.clone(), again.clone(), from_handle.clone()] {
            let err = Namespace::builder()
                .mount(p("/rw"), one.clone(), a)
                .mount(p("/ro"), second, b)
                .build()
                .unwrap_err();
            assert_eq!(
                err.kind(),
                NsErrorKind::InvalidInput(InputReason::DuplicateRoot),
                "{a:?} then {b:?}"
            );
            assert_eq!(
                err.path().map(NsPath::as_str),
                Some("/ro"),
                "names the later mount point"
            );
        }
    }
    // Not only siblings: a mount nested under another, or sharing a synthesised ancestor, is checked all the same.
    let err = Namespace::builder()
        .mount(p("/a/x"), one.clone(), Access::ReadOnly)
        .mount(p("/b/y"), again.clone(), Access::ReadOnly)
        .build()
        .unwrap_err();
    assert_eq!(
        err.kind(),
        NsErrorKind::InvalidInput(InputReason::DuplicateRoot)
    );
    assert!(format!("{err}").contains("same host directory"), "{err}");
}

#[test]
fn different_host_directories_and_memory_mounts_build() {
    use storage_kit::ns::HostDir;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("one")).unwrap();
    std::fs::create_dir(tmp.path().join("two")).unwrap();
    let one = Arc::new(HostDir::open_ambient(tmp.path().join("one")).unwrap());
    let two = Arc::new(HostDir::open_ambient(tmp.path().join("two")).unwrap());
    assert_ne!(one.root_identity(), two.root_identity());
    let m = mem();
    // `Memory` reports no identity (it has no host directory), so the same `Memory` twice is not what this check is for.
    assert_eq!(m.root_identity(), None);
    let ns = Namespace::builder()
        .mount(p("/one"), one, Access::ReadWrite)
        .mount(p("/two"), two, Access::ReadOnly)
        .mount(p("/m1"), m.clone(), Access::ReadWrite)
        .mount(p("/m2"), m, Access::ReadOnly)
        .build();
    assert!(ns.is_ok(), "{:?}", ns.err());
}

/// What the Kit does NOT see, pinned so the documentation stays true: it holds no host paths, so a directory mounted
/// together with one of its descendants is not detected, and a write through the writable mount shows through the
/// read-only one. The embedder chooses the host directories and must keep them disjoint.
#[test]
fn an_ancestor_and_a_descendant_mounted_together_are_not_detected() {
    use storage_kit::ns::HostDir;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("locked")).unwrap();
    std::fs::write(tmp.path().join("locked/cfg"), b"original").unwrap();
    let outer = Arc::new(HostDir::open_ambient(tmp.path()).unwrap());
    let inner = Arc::new(HostDir::open_ambient(tmp.path().join("locked")).unwrap());
    assert_ne!(outer.root_identity(), inner.root_identity());
    let ns = Namespace::builder()
        .mount(p("/rw"), outer, Access::ReadWrite)
        .mount(p("/ro"), inner, Access::ReadOnly)
        .build()
        .expect("an ancestor and a descendant are not detected (documented)");
    assert_eq!(
        kind(ns.write(&p("/ro/cfg"), WriteOp::Replace, b"x", None)),
        NsErrorKind::PermissionDenied
    );
    ns.write(&p("/rw/locked/cfg"), WriteOp::Replace, b"changed", None)
        .unwrap();
    assert_eq!(ns.read(&p("/ro/cfg"), 100).unwrap().0, b"changed");
}

#[test]
fn a_read_only_mount_nested_under_a_read_write_one_is_refused() {
    // The attack: /data is writable, /data/a/locked is meant to be read-only. Through the writable parent one renames
    // /data/a to /data/z and writes /data/z/locked/cfg: a path no nested mount covers, onto the protected directory.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("a/locked")).unwrap();
    std::fs::write(tmp.path().join("a/locked/cfg"), b"original").unwrap();
    let host = Arc::new(storage_kit::ns::HostDir::open_ambient(tmp.path()).unwrap());
    let locked =
        Arc::new(storage_kit::ns::HostDir::open_ambient(tmp.path().join("a/locked")).unwrap());

    let err = Namespace::builder()
        .mount(p("/data"), host.clone(), Access::ReadWrite)
        .mount(p("/data/a/locked"), locked.clone(), Access::ReadOnly)
        .build()
        .unwrap_err();
    assert_eq!(
        err.kind(),
        NsErrorKind::InvalidInput(InputReason::ReadOnlyUnderReadWrite)
    );
    assert_eq!(err.path().map(NsPath::as_str), Some("/data/a/locked"));

    // The same through a root mount, and through an intermediate ancestor that is itself a mount.
    for parent in ["/", "/data/a"] {
        let r = Namespace::builder()
            .mount(p(parent), mem(), Access::ReadWrite)
            .mount(p("/data/a/locked"), mem(), Access::ReadOnly)
            .build();
        assert_eq!(
            r.unwrap_err().kind(),
            NsErrorKind::InvalidInput(InputReason::ReadOnlyUnderReadWrite),
            "under {parent}"
        );
    }

    // What IS allowed: read-only beside writable, read-only under read-only, writable under read-only.
    let ns = Namespace::builder()
        .mount(p("/data"), host.clone(), Access::ReadWrite)
        .mount(p("/ro"), locked.clone(), Access::ReadOnly)
        .mount(p("/ro/inner"), mem(), Access::ReadOnly)
        .mount(p("/ro/scratch"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    // Writes through the read-only mount are refused. (The protected directory is NOT unreachable: `/data/a/locked` is the
    // same host directory. The Kit enforces the grant per mount and does not see that overlap; see the test below.)
    assert_eq!(
        kind(ns.write(&p("/ro/cfg"), WriteOp::Replace, b"x", None)),
        NsErrorKind::PermissionDenied
    );
    assert_eq!(
        kind(ns.write(&p("/ro/inner/f"), WriteOp::Replace, b"x", None)),
        NsErrorKind::PermissionDenied
    );
    ns.write(&p("/ro/scratch/f"), WriteOp::Replace, b"x", None)
        .unwrap();
    assert_eq!(
        std::fs::read(tmp.path().join("a/locked/cfg")).unwrap(),
        b"original"
    );
}

#[test]
fn mount_points_match_case_folded() {
    // Two points that fold equal are one point.
    let err = Namespace::builder()
        .mount(p("/Config"), mem(), Access::ReadWrite)
        .mount(p("/config"), mem(), Access::ReadWrite)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::AlreadyExists);
    // Composed forms too: `/\u{e9}` and its upper case.
    assert!(Namespace::builder()
        .mount(p("/\u{e9}"), mem(), Access::ReadWrite)
        .mount(p("/\u{c9}"), mem(), Access::ReadWrite)
        .build()
        .is_err());

    // A read-only mount answers to every spelling: no spelling routes around its grant.
    let ro = mem();
    ro.preload(&p("/cfg"), b"x").unwrap();
    let ns = Namespace::builder()
        .mount(p("/Config"), ro, Access::ReadOnly)
        .build()
        .unwrap();
    for spelling in ["/Config/cfg", "/config/cfg", "/CONFIG/cfg", "/cOnFiG/cfg"] {
        assert_eq!(ns.read(&p(spelling), 10).unwrap().0, b"x", "{spelling}");
        assert_eq!(
            kind(ns.write(&p(spelling), WriteOp::Replace, b"y", None)),
            NsErrorKind::PermissionDenied,
            "{spelling}"
        );
    }
    // And a rename between two spellings of the same mount is within that mount.
    let ns = Namespace::builder()
        .mount(p("/Data"), mem(), Access::ReadWrite)
        .build()
        .unwrap();
    ns.write(&p("/Data/f"), WriteOp::Replace, b"x", None)
        .unwrap();
    ns.write(
        &p("/data/f"),
        WriteOp::RenameWithinMount { to: p("/DATA/g") },
        &[],
        None,
    )
    .unwrap();
    assert_eq!(ns.read(&p("/dAtA/g"), 10).unwrap().0, b"x");
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
    for to in ["/b/f", "/a/inner/f"] {
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
    // A destination in NO mount is not a "cross-mount" rename; there is simply nothing there. (Same for a destination
    // that is only a synthesised mount ancestor.)
    for to in ["/nowhere/f", "/"] {
        let err = ns
            .write(
                &p("/a/f"),
                WriteOp::RenameWithinMount { to: p(to) },
                &[],
                None,
            )
            .unwrap_err();
        assert_eq!(err.kind(), NsErrorKind::NotFound, "{to}");
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
