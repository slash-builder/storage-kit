//! The polling watch over a real directory, driven by changes made the way other programs make them (directly on disk).
#![cfg(feature = "ns")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use storage_kit::ns::{Backend, HostDir, NsPath, Watch, WatchBatch, WatchCursor, WatchOpts};

const TIMEOUT: Duration = Duration::from_secs(10);

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    dir: HostDir,
}

fn fixture() -> Fixture {
    let tmp = tempfile::Builder::new()
        .prefix("HOSTSECRET-")
        .tempdir()
        .unwrap();
    let root = tmp.path().to_path_buf();
    let dir = HostDir::open_ambient(&root).unwrap();
    Fixture {
        _tmp: tmp,
        root,
        dir,
    }
}

fn p(s: &str) -> NsPath {
    NsPath::parse(s).unwrap()
}

fn fast() -> WatchOpts {
    WatchOpts::default().interval(Duration::from_millis(15))
}

/// Receive until `pred` holds for a batch; collect everything seen.
fn wait(
    w: &Watch,
    seen: &mut Vec<WatchBatch>,
    what: &str,
    mut pred: impl FnMut(&WatchBatch) -> bool,
) -> WatchBatch {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let b = w
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("timed out waiting for {what}; saw {seen:?}"));
        seen.push(b.clone());
        if pred(&b) {
            return b;
        }
    }
}

fn reports(path: &'static str) -> impl Fn(&WatchBatch) -> bool {
    move |b| !b.rescan && b.changed.iter().any(|c| c.as_str() == path)
}

fn assert_no_host_paths(seen: &[WatchBatch], root: &Path) {
    let root = root.to_string_lossy();
    for b in seen {
        for c in &b.changed {
            assert!(c.as_str().starts_with('/'));
            assert!(
                !c.as_str().contains(root.as_ref()) && !c.as_str().contains("HOSTSECRET"),
                "{c}"
            );
        }
        assert!(!format!("{b:?}").contains("HOSTSECRET"));
    }
}

#[test]
fn reports_create_modify_remove_and_rename_replace() {
    let f = fixture();
    let w = f.dir.watch(&NsPath::root(), fast()).unwrap();
    let mut seen = Vec::new();

    fs::write(f.root.join("note.txt"), b"1").unwrap();
    wait(&w, &mut seen, "create", reports("/note.txt"));

    // Modify in place: a different length is always visible.
    fs::write(f.root.join("note.txt"), b"22222").unwrap();
    wait(&w, &mut seen, "modify", reports("/note.txt"));

    // An editor's save: write a temp file, rename it over the original. The name stays, the file behind it changes.
    fs::write(f.root.join("note.txt.tmp"), b"22222").unwrap(); // same length and (likely) same second as before
    fs::rename(f.root.join("note.txt.tmp"), f.root.join("note.txt")).unwrap();
    wait(&w, &mut seen, "rename-replace", reports("/note.txt"));

    // A plain rename reports both names.
    fs::rename(f.root.join("note.txt"), f.root.join("moved.txt")).unwrap();
    let mut both = (false, false);
    wait(&w, &mut seen, "rename", |b| {
        both.0 |= b.changed.iter().any(|c| c.as_str() == "/note.txt");
        both.1 |= b.changed.iter().any(|c| c.as_str() == "/moved.txt");
        both.0 && both.1
    });

    fs::remove_file(f.root.join("moved.txt")).unwrap();
    wait(&w, &mut seen, "remove", reports("/moved.txt"));

    // Every batch followed the one before it, in one epoch, and none was a rescan.
    let mut cursor = WatchCursor::new();
    for b in &seen {
        assert!(!cursor.observe(b), "unexpected rescan or gap: {b:?}");
        assert!(
            b.changed.windows(2).all(|w| w[0] < w[1]),
            "changed must be sorted and unique: {b:?}"
        );
    }
    assert_no_host_paths(&seen, &f.root);
}

#[test]
fn several_writes_within_an_interval_are_one_batch_reported_on_the_next_poll() {
    let f = fixture();
    let interval = Duration::from_millis(600);
    let w = f
        .dir
        .watch(&NsPath::root(), WatchOpts::default().interval(interval))
        .unwrap();
    let mut seen = Vec::new();

    // Line up with a poll: a change is reported by the poll that sees it, so right after that batch we are at the
    // start of an interval and have nearly all of it to make changes in.
    fs::write(f.root.join("sync"), b"x").unwrap();
    wait(&w, &mut seen, "the sync file", reports("/sync"));
    let started = Instant::now();
    for i in 0..5 {
        fs::write(f.root.join(format!("burst{i}")), b"x").unwrap();
    }
    let burst = wait(&w, &mut seen, "the burst", |b| {
        b.changed.iter().any(|c| c.as_str().starts_with("/burst"))
    });
    let latency = started.elapsed();
    assert_eq!(
        burst.changed.len(),
        5,
        "five writes inside one interval must be one batch: {burst:?}"
    );
    assert!(
        latency < interval * 2,
        "a change must be reported on the next poll, not later (took {latency:?})"
    );
    assert_eq!(
        burst.generation, 2,
        "sync was generation 1, the burst is the very next batch"
    );
}

#[test]
fn a_vanished_directory_sends_one_rescan_and_the_watch_survives() {
    let f = fixture();
    fs::create_dir(f.root.join("d")).unwrap();
    let w = f.dir.watch(&p("/d"), fast()).unwrap();
    let mut seen = Vec::new();

    fs::remove_dir(f.root.join("d")).unwrap();
    let gone = wait(&w, &mut seen, "rescan on vanish", |b| b.rescan);
    assert!(gone.changed.is_empty());

    // While it stays gone there must not be a stream of rescans: exactly one.
    assert!(
        w.recv_timeout(Duration::from_millis(300)).is_err(),
        "a missing directory must be reported once"
    );

    fs::create_dir(f.root.join("d")).unwrap();
    let back = wait(&w, &mut seen, "rescan on return", |b| b.rescan);
    assert_eq!(back.generation, gone.generation + 1);

    fs::write(f.root.join("d/after"), b"x").unwrap();
    wait(
        &w,
        &mut seen,
        "a change after the return",
        reports("/d/after"),
    );
}

#[test]
fn a_directory_replaced_by_a_symlink_counts_as_gone() {
    let f = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"x").unwrap();
    fs::create_dir(f.root.join("d")).unwrap();
    let w = f.dir.watch(&p("/d"), fast()).unwrap();
    let mut seen = Vec::new();
    fs::remove_dir(f.root.join("d")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), f.root.join("d")).unwrap();
    wait(
        &w,
        &mut seen,
        "rescan when the directory became a link",
        |b| b.rescan,
    );
    // The outside directory's contents are never reported.
    assert!(w.recv_timeout(Duration::from_millis(300)).is_err());
    assert!(seen.iter().all(|b| b.changed.is_empty()));
}

#[test]
fn a_watch_on_a_file_or_a_missing_path_is_refused_up_front() {
    use storage_kit::ns::NsErrorKind;
    let f = fixture();
    fs::write(f.root.join("file"), b"x").unwrap();
    assert_eq!(
        f.dir.watch(&p("/file"), fast()).unwrap_err().kind(),
        NsErrorKind::NotADirectory
    );
    assert_eq!(
        f.dir.watch(&p("/nope"), fast()).unwrap_err().kind(),
        NsErrorKind::NotFound
    );
}

#[test]
fn recursive_sees_nested_changes_and_non_recursive_does_not() {
    let f = fixture();
    fs::create_dir_all(f.root.join("a/b")).unwrap();
    let shallow = f.dir.watch(&NsPath::root(), fast()).unwrap();
    let deep = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true))
        .unwrap();
    fs::write(f.root.join("a/b/leaf"), b"x").unwrap();
    fs::write(f.root.join("sentinel"), b"x").unwrap();
    let (mut s1, mut s2) = (Vec::new(), Vec::new());
    wait(&shallow, &mut s1, "sentinel", reports("/sentinel"));
    wait(&deep, &mut s2, "the leaf", reports("/a/b/leaf"));
    assert!(s1
        .iter()
        .all(|b| !b.changed.iter().any(|c| c.as_str() == "/a/b/leaf")));
}

#[test]
fn more_changes_than_max_entries_is_a_rescan_with_no_paths() {
    let f = fixture();
    let w = f
        .dir
        .watch(
            &NsPath::root(),
            WatchOpts::default()
                .interval(Duration::from_millis(400))
                .max_entries(3),
        )
        .unwrap();
    let mut seen = Vec::new();
    // Line up just after a poll so the whole burst lands in one interval.
    fs::write(f.root.join("sync"), b"x").unwrap();
    wait(&w, &mut seen, "sync", reports("/sync"));
    for i in 0..20 {
        fs::write(f.root.join(format!("f{i}")), b"x").unwrap();
    }
    let b = wait(&w, &mut seen, "the over-cap batch", |b| b.rescan);
    assert!(b.changed.is_empty());
}

#[test]
fn dropping_the_watch_returns_at_once_even_with_a_long_interval() {
    let f = fixture();
    let w = f
        .dir
        .watch(
            &NsPath::root(),
            WatchOpts::default().interval(Duration::from_secs(60)),
        )
        .unwrap();
    let started = Instant::now();
    drop(w);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "drop took {:?}",
        started.elapsed()
    );
    // The directory is still fully usable.
    f.dir
        .write(&p("/after"), storage_kit::ns::WriteOp::Replace, b"x", None)
        .unwrap();
}

#[test]
fn a_sub_minimum_interval_is_raised_not_spun_on() {
    assert_eq!(
        WatchOpts::default()
            .interval(Duration::from_millis(1))
            .interval,
        Duration::from_millis(1),
        "the option keeps what was asked for"
    );
    // The engine raises it to the minimum; observable as: with a 1 ms request, a burst of changes is still delivered
    // and nothing panics or spins the test machine.
    let f = fixture();
    let w = f
        .dir
        .watch(
            &NsPath::root(),
            WatchOpts::default().interval(Duration::from_millis(1)),
        )
        .unwrap();
    fs::write(f.root.join("x"), b"1").unwrap();
    let mut seen = Vec::new();
    wait(&w, &mut seen, "x", reports("/x"));
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_reported_like_a_vanished_one_and_recovers() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    fs::create_dir(f.root.join("d")).unwrap();
    let w = f.dir.watch(&p("/d"), fast()).unwrap();
    let mut seen = Vec::new();

    fs::set_permissions(f.root.join("d"), fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(f.root.join("d")).is_ok() {
        // Running as a user that ignores permission bits (root): there is no unreadable directory to test with.
        fs::set_permissions(f.root.join("d"), fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skipped: permission bits are not enforced for this user");
        return;
    }
    let gone = wait(
        &w,
        &mut seen,
        "rescan when the directory became unreadable",
        |b| b.rescan,
    );
    assert!(gone.changed.is_empty());
    assert!(
        w.recv_timeout(Duration::from_millis(300)).is_err(),
        "reported once, not on every poll"
    );

    fs::set_permissions(f.root.join("d"), fs::Permissions::from_mode(0o700)).unwrap();
    wait(&w, &mut seen, "rescan when it became readable again", |b| {
        b.rescan
    });
    fs::write(f.root.join("d/x"), b"x").unwrap();
    wait(&w, &mut seen, "a change after recovery", reports("/d/x"));
}
