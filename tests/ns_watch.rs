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

// Unix only: it needs a symlink, which this crate's tests cannot create portably.
#[cfg(unix)]
#[test]
fn a_directory_replaced_by_a_symlink_counts_as_gone() {
    let f = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"x").unwrap();
    fs::create_dir(f.root.join("d")).unwrap();
    let w = f.dir.watch(&p("/d"), fast()).unwrap();
    let mut seen = Vec::new();
    fs::remove_dir(f.root.join("d")).unwrap();
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

/// Run `f` on its own thread and FAIL (not hang) if it has not finished after `secs`; a panic inside is re-raised.
fn within<F: FnOnce() + Send + 'static>(secs: u64, what: &str, f: F) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(()) => handle.join().expect("the thread panicked after finishing"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("{what}: still running after {secs}s (hung: the thread is abandoned)")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            if let Err(panic) = handle.join() {
                std::panic::resume_unwind(panic);
            }
        }
    }
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
    // The drop runs under a deadline: a watch that never tells its thread to stop would make `Drop` join forever, and
    // that must fail this test rather than hang the run.
    let started = Instant::now();
    within(10, "dropping a watch", move || drop(w));
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
fn the_longest_possible_interval_neither_panics_nor_delays_the_drop() {
    // `Instant::now() + Duration::MAX` overflows and panics; the interval is clamped to an hour instead.
    let f = fixture();
    let w = f
        .dir
        .watch(
            &NsPath::root(),
            WatchOpts::default().interval(Duration::MAX),
        )
        .unwrap();
    within(10, "dropping a Duration::MAX watch", move || drop(w));
    let w = f
        .dir
        .watch(
            &NsPath::root(),
            WatchOpts::default().interval(Duration::ZERO),
        )
        .unwrap();
    fs::write(f.root.join("x"), b"1").unwrap();
    let mut seen = Vec::new();
    wait(
        &w,
        &mut seen,
        "a change with a zero interval",
        reports("/x"),
    );
}

#[test]
fn a_tree_over_max_tracked_is_refused_up_front_and_degrades_to_one_rescan_when_it_grows() {
    use storage_kit::ns::NsErrorKind;
    let f = fixture();
    for i in 0..30 {
        fs::write(f.root.join(format!("f{i:02}")), b"x").unwrap();
    }
    // Too big to track at the start: refused, not half-watched.
    let err = f
        .dir
        .watch(&NsPath::root(), fast().max_tracked(10))
        .unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::TooLarge);
    assert_eq!(err.path().map(NsPath::as_str), Some("/"));

    // Small at the start, grows past the bound: one rescan, then silence until it fits again, then one rescan.
    fs::create_dir(f.root.join("small")).unwrap();
    for i in 0..5 {
        fs::write(f.root.join(format!("small/f{i}")), b"x").unwrap();
    }
    let w = f.dir.watch(&p("/small"), fast().max_tracked(8)).unwrap();
    let mut seen = Vec::new();
    for i in 5..20 {
        fs::write(f.root.join(format!("small/f{i}")), b"x").unwrap();
    }
    let grown = wait(
        &w,
        &mut seen,
        "a rescan when the tree outgrew the bound",
        |b| b.rescan,
    );
    assert!(grown.changed.is_empty());
    assert!(
        w.recv_timeout(Duration::from_millis(300)).is_err(),
        "an over-bound tree is reported once, not on every poll"
    );
    for i in 3..20 {
        fs::remove_file(f.root.join(format!("small/f{i}"))).unwrap();
    }
    wait(&w, &mut seen, "a rescan when it fits again", |b| b.rescan);
}

/// `levels` nested directories named `d`, built through open handles (a host path this long is not accepted by the OS).
#[cfg(unix)]
fn make_chain(root: &Path, levels: usize) {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    let mut cur = Dir::open_ambient_dir(root, ambient_authority()).unwrap();
    for _ in 0..levels {
        cur.create_dir("d").unwrap();
        cur = cur.open_dir("d").unwrap();
    }
    cur.write("leaf", b"x").unwrap();
}

#[test]
fn a_tree_within_max_depth_is_fully_reported_and_one_beyond_it_is_refused() {
    use storage_kit::ns::NsErrorKind;
    let f = fixture();
    // /a/b/c/d is 4 levels below the watched directory, with a file at each level.
    fs::create_dir_all(f.root.join("a/b/c/d")).unwrap();
    for n in ["a", "a/b", "a/b/c", "a/b/c/d"] {
        fs::write(f.root.join(n).join("f"), b"1").unwrap();
    }
    let w = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true).max_depth(4))
        .unwrap();
    // Changes at every level, the deepest included, are reported by name.
    for n in ["a/f", "a/b/f", "a/b/c/f", "a/b/c/d/f"] {
        fs::write(f.root.join(n), b"22").unwrap();
    }
    let mut seen = Vec::new();
    let mut want: std::collections::BTreeSet<&str> =
        ["/a/f", "/a/b/f", "/a/b/c/f", "/a/b/c/d/f"].into();
    wait(&w, &mut seen, "a change at every level", |b| {
        assert!(!b.rescan, "within the cap there is nothing to rescan");
        for c in &b.changed {
            want.remove(c.as_str());
        }
        want.is_empty()
    });

    // One level more than the cap is refused up front, like a tree over max_tracked.
    let err = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true).max_depth(3))
        .unwrap_err();
    assert_eq!(err.kind(), NsErrorKind::TooLarge);
    // A flat watch has no depth to exceed, whatever the cap.
    f.dir
        .watch(&NsPath::root(), fast().max_depth(0))
        .expect("a non-recursive watch ignores max_depth");
}

#[test]
fn a_tree_that_grows_past_max_depth_is_one_rescan_then_silence_then_one_rescan() {
    let f = fixture();
    fs::create_dir(f.root.join("a")).unwrap();
    let w = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true).max_depth(3))
        .unwrap();
    let mut seen = Vec::new();
    fs::create_dir_all(f.root.join("a/b/c")).unwrap();
    wait(&w, &mut seen, "the new directories, within the cap", |b| {
        b.changed.iter().any(|c| c.as_str() == "/a/b/c")
    });
    // One level too many.
    fs::create_dir(f.root.join("a/b/c/d")).unwrap();
    let batch = wait(&w, &mut seen, "a rescan when the tree got too deep", |b| {
        b.rescan
    });
    assert!(batch.changed.is_empty(), "a rescan carries no paths");
    assert!(
        w.recv_timeout(Duration::from_millis(300)).is_err(),
        "a too-deep tree is reported once, not on every poll"
    );
    // And back within the cap: one more rescan, then it reports again.
    fs::remove_dir(f.root.join("a/b/c/d")).unwrap();
    wait(&w, &mut seen, "a rescan when it fits again", |b| b.rescan);
    fs::write(f.root.join("a/b/c/f"), b"x").unwrap();
    wait(
        &w,
        &mut seen,
        "a change below the cap again",
        reports("/a/b/c/f"),
    );
}

/// A 2,000-level chain, created after the watch starts: the watch must answer with one `rescan` and then leave the
/// tree alone (the scan used to take seconds per poll and repeat on every poll). Unix only: a host path 4,000 bytes
/// deep is not something Windows path APIs accept.
#[cfg(unix)]
#[test]
fn a_two_thousand_level_chain_is_one_rescan_not_a_hang() {
    let f = fixture();
    let w = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true))
        .unwrap();
    make_chain(&f.root, 2000);
    let mut seen = Vec::new();
    let started = Instant::now();
    wait(&w, &mut seen, "a rescan for the too-deep tree", |b| {
        b.rescan
    });
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the watch took {:?} to notice",
        started.elapsed()
    );
    assert!(
        w.recv_timeout(Duration::from_millis(300)).is_err(),
        "an over-deep tree is reported once, not on every poll"
    );
    // Refused up front too, and quickly.
    let started = Instant::now();
    let err = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true))
        .unwrap_err();
    assert_eq!(err.kind(), storage_kit::ns::NsErrorKind::TooLarge);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[test]
fn a_recursive_watch_never_follows_a_symlink_loop() {
    use std::os::unix::fs::symlink;
    let f = fixture();
    fs::create_dir_all(f.root.join("a/b")).unwrap();
    symlink(".", f.root.join("loop")).unwrap();
    symlink("..", f.root.join("a/up")).unwrap();
    symlink("../..", f.root.join("a/b/top")).unwrap();
    symlink(&f.root, f.root.join("abs")).unwrap();
    let started = Instant::now();
    let w = f
        .dir
        .watch(&NsPath::root(), fast().recursive(true))
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the scan did not terminate promptly"
    );
    fs::write(f.root.join("a/b/leaf"), b"x").unwrap();
    fs::write(f.root.join("sentinel"), b"x").unwrap();
    let mut seen = Vec::new();
    let mut got = (false, false);
    wait(&w, &mut seen, "the leaf and the sentinel", |b| {
        got.0 |= b.changed.iter().any(|c| c.as_str() == "/a/b/leaf");
        got.1 |= b.changed.iter().any(|c| c.as_str() == "/sentinel");
        got.0 && got.1
    });
    for b in &seen {
        for c in &b.changed {
            let s = c.as_str();
            assert!(
                !(s.contains("/loop")
                    || s.contains("/up")
                    || s.contains("/top")
                    || s.contains("/abs")),
                "a path through a symlink was reported: {s}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_for_an_in_root_symlink_during_a_scan_is_never_followed() {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let f = fixture();
    fs::create_dir(f.root.join("d")).unwrap();
    fs::write(f.root.join("d/ok.txt"), b"x").unwrap();
    fs::create_dir(f.root.join("elsewhere")).unwrap();
    fs::write(f.root.join("elsewhere/leak.txt"), b"x").unwrap();
    for i in 0..40 {
        fs::create_dir(f.root.join(format!("pad{i:02}"))).unwrap(); // give each scan something to do
    }
    let root = f.root.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                fs::rename(root.join("d"), root.join("parked")).unwrap();
                symlink("elsewhere", root.join("d")).unwrap();
                fs::remove_file(root.join("d")).unwrap();
                fs::rename(root.join("parked"), root.join("d")).unwrap();
            }
        })
    };
    let w = f
        .dir
        .watch(
            &NsPath::root(),
            WatchOpts::default()
                .interval(Duration::from_millis(10))
                .recursive(true),
        )
        .unwrap();
    let started = Instant::now();
    let mut leaked = Vec::new();
    let mut batches = 0;
    while started.elapsed() < Duration::from_secs(3) {
        if let Ok(b) = w.recv_timeout(Duration::from_millis(50)) {
            batches += 1;
            leaked.extend(
                b.changed
                    .iter()
                    .filter(|c| c.as_str() == "/d/leak.txt")
                    .cloned(),
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().unwrap();
    eprintln!("scan race: {batches} batches");
    assert!(
        batches > 10,
        "the flipping must have produced changes to report"
    );
    assert!(
        leaked.is_empty(),
        "the scan followed an in-root symlink into another directory: {leaked:?}"
    );
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
