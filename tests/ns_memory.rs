//! `Memory`-specific behaviour and the shape of the public types.
#![cfg(feature = "ns")]

use storage_kit::ns::{
    Backend, Entry, Feature, InputReason, Kind, Memory, MemoryOptions, NsErrorKind, NsPath, WriteOp,
};

fn p(s: &str) -> NsPath {
    NsPath::parse(s).unwrap()
}

#[test]
fn a_version_from_one_memory_never_validates_against_another() {
    let (a, b) = (Memory::new(), Memory::new());
    // The same operations on two fresh instances: a bare counter would give equal versions.
    let va = a.write(&p("/f"), WriteOp::Replace, b"x", None).unwrap();
    let vb = b.write(&p("/f"), WriteOp::Replace, b"x", None).unwrap();
    assert_ne!(
        va, vb,
        "versions of two instances must differ even for identical histories"
    );
    assert_ne!(
        a.stat(&p("/")).unwrap().version,
        b.stat(&p("/")).unwrap().version
    );
    // Used against the wrong mount, a version is a mismatch, not a lucky match.
    let err = b
        .write(&p("/f"), WriteOp::Replace, b"y", Some(&va))
        .unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::VersionMismatch);
    let err = b
        .write(&p("/f"), WriteOp::Remove, &[], Some(&va))
        .unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::VersionMismatch);
    // Many instances, one process: all distinct.
    let versions: std::collections::HashSet<_> = (0..200)
        .map(|_| Memory::new().stat(&p("/")).unwrap().version)
        .collect();
    assert_eq!(versions.len(), 200);
    // Clones share a tree, so they share versions.
    let c = a.clone();
    assert_eq!(c.stat(&p("/f")).unwrap().version, va);
}

#[test]
fn a_directory_version_changes_when_its_entries_change() {
    let m = Memory::new();
    m.write(&p("/d"), WriteOp::MakeDir, &[], None).unwrap();
    let mut last = m.stat(&p("/d")).unwrap().version;
    let mut step = |op: WriteOp, path: &str, data: &[u8], what: &str| {
        m.write(&p(path), op, data, None).unwrap();
        let now = m.stat(&p("/d")).unwrap().version;
        assert_ne!(now, last, "{what} must change the directory's version");
        last = now;
    };
    step(WriteOp::CreateExclusive, "/d/a", b"1", "adding an entry");
    step(WriteOp::MakeDir, "/d/sub", &[], "adding a directory");
    step(
        WriteOp::RenameWithinMount { to: p("/d/b") },
        "/d/a",
        &[],
        "renaming an entry",
    );
    step(WriteOp::Remove, "/d/b", &[], "removing an entry");
}

#[test]
fn errors_carry_typed_reasons_not_text() {
    fn copy<T: Copy + Eq + std::fmt::Debug>() {}
    copy::<NsErrorKind>();
    copy::<InputReason>();
    copy::<Feature>();
    let m = Memory::new();
    let e = m
        .write(&p("/f"), WriteOp::CreateExclusive, b"x", None)
        .unwrap();
    let _ = e;
    assert_eq!(
        m.write(&p("/f"), WriteOp::Remove, b"junk", None)
            .unwrap_err()
            .kind(),
        NsErrorKind::InvalidInput(InputReason::UnexpectedData)
    );
    assert_eq!(
        m.write(&p("/"), WriteOp::Remove, &[], None)
            .unwrap_err()
            .kind(),
        NsErrorKind::InvalidInput(InputReason::MountRoot)
    );
    let frozen = Memory::with_options(MemoryOptions::default().writable(false));
    assert_eq!(
        frozen
            .write(&p("/f"), WriteOp::Replace, b"x", None)
            .unwrap_err()
            .kind(),
        NsErrorKind::Unsupported(Feature::Write)
    );
    // Every kind round-trips through its Debug form without a free-text payload leaking a path.
    let shown = format!("{:?}", NsErrorKind::InvalidInput(InputReason::MoveIntoSelf));
    assert_eq!(shown, "InvalidInput(MoveIntoSelf)");
}

#[test]
fn entries_are_constructed_not_literal() {
    // `Entry` is `#[non_exhaustive]`: backends build it with `new`, so a field can be added later without a break.
    let e = Entry::new("name", Kind::File);
    assert_eq!((e.name.as_str(), e.kind), ("name", Kind::File));
}

#[test]
fn memory_walk_is_sorted_by_utf8_bytes() {
    let m = Memory::new();
    for n in ["b", "Z", "\u{e9}", "a", "z2", "\u{1f600}", "10", "9"] {
        m.write(&p(&format!("/{n}")), WriteOp::CreateExclusive, b"x", None)
            .unwrap();
    }
    let got: Vec<String> = m
        .walk(&p("/"))
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    let mut want = got.clone();
    want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(got, want);
    assert_eq!(got.first().map(String::as_str), Some("10"));
}
