//! `HostDir` confinement, tested against a real directory. Everything is a *named error kind*, never a message match.
//!
//! The tests that need a symlink, a FIFO, a hard link, Unix permission bits or Unix file names are `#[cfg(unix)]`; the
//! rest (collisions, limits, versions, errors that must not leak a host path, atomic replace) run on every platform,
//! Windows included. Every test that can hang (a blocking FIFO open, a watch that never stops) runs under a deadline, so
//! a regression FAILS fast instead of hanging CI.
#![cfg(feature = "ns")]

use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[cfg(unix)]
use storage_kit::ns::Kind;
use storage_kit::ns::{Backend, HostDir, NsErrorKind, NsPath, WriteOp};

#[cfg(unix)]
const OUTSIDE: &[u8] = b"OUTSIDE-SECRET";
#[cfg(unix)]
const INSIDE: &[u8] = b"inside";
#[cfg(unix)]
const OTHER_INSIDE: &[u8] = b"OTHER-INSIDE";

/// Run `f` on its own thread and fail (not hang) if it has not finished after `secs`. A panic inside `f` is re-raised.
#[cfg(unix)]
fn within<F: FnOnce() + Send + 'static>(secs: u64, what: &str, f: F) {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(()) => handle
            .join()
            .expect("the watched thread panicked after finishing"),
        Err(RecvTimeoutError::Timeout) => {
            panic!(
                "{what}: still running after {secs}s: something blocks or never stops (the thread is abandoned)"
            )
        }
        Err(RecvTimeoutError::Disconnected) => {
            if let Err(panic) = handle.join() {
                std::panic::resume_unwind(panic);
            }
        }
    }
}

/// A host layout: `<tmp>/root` is the mount; on Unix `<tmp>/outside` is what a symlink must never reach.
struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    #[cfg(unix)]
    outside: PathBuf,
    dir: HostDir,
}

fn fixture() -> Fixture {
    let tmp = tempfile::Builder::new()
        .prefix("HOSTSECRET-")
        .tempdir()
        .unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    let outside = {
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.txt"), OUTSIDE).unwrap();
        outside
    };
    let dir = HostDir::open_ambient(&root).unwrap();
    Fixture {
        _tmp: tmp,
        root,
        #[cfg(unix)]
        outside,
        dir,
    }
}

fn p(s: &str) -> NsPath {
    NsPath::parse(s).unwrap()
}

fn kind<T: std::fmt::Debug>(r: Result<T, storage_kit::ns::NsError>) -> NsErrorKind {
    match r {
        Ok(v) => panic!("expected an error, got Ok({v:?})"),
        Err(e) => e.kind(),
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_root_is_refused_on_read_write_and_walk() {
    let f = fixture();
    symlink(f.outside.join("secret.txt"), f.root.join("filelink")).unwrap();
    symlink(&f.outside, f.root.join("dirlink")).unwrap();

    // read
    assert_eq!(
        kind(f.dir.read(&p("/filelink"), 1024)),
        NsErrorKind::Escapes
    );
    assert_eq!(
        kind(f.dir.read(&p("/dirlink/secret.txt"), 1024)),
        NsErrorKind::Escapes
    );
    // write: onto the link, and through the link
    assert_eq!(
        kind(
            f.dir
                .write(&p("/filelink"), WriteOp::Replace, b"pwned", None)
        ),
        NsErrorKind::Escapes
    );
    assert_eq!(
        kind(
            f.dir
                .write(&p("/dirlink/new"), WriteOp::CreateExclusive, b"pwned", None)
        ),
        NsErrorKind::Escapes
    );
    assert_eq!(
        kind(
            f.dir
                .write(&p("/dirlink/secret.txt"), WriteOp::Replace, b"pwned", None)
        ),
        NsErrorKind::Escapes
    );
    assert_eq!(
        kind(f.dir.write(&p("/dirlink/d"), WriteOp::MakeDir, &[], None)),
        NsErrorKind::Escapes
    );
    assert_eq!(
        kind(
            f.dir
                .write(&p("/dirlink/secret.txt"), WriteOp::Remove, &[], None)
        ),
        NsErrorKind::Escapes
    );
    assert_eq!(
        kind(f.dir.write(&p("/filelink"), WriteOp::Remove, &[], None)),
        NsErrorKind::Escapes
    );
    // walk and stat
    assert_eq!(kind(f.dir.walk(&p("/dirlink"))), NsErrorKind::Escapes);
    assert_eq!(kind(f.dir.stat(&p("/filelink"))), NsErrorKind::Escapes);
    assert_eq!(
        kind(f.dir.stat(&p("/dirlink/secret.txt"))),
        NsErrorKind::Escapes
    );
    // watch
    assert_eq!(
        kind(f.dir.watch(&p("/dirlink"), Default::default())),
        NsErrorKind::Escapes
    );
    // rename out through a link
    fs::write(f.root.join("mine"), b"m").unwrap();
    assert_eq!(
        kind(f.dir.write(
            &p("/mine"),
            WriteOp::RenameWithinMount {
                to: p("/dirlink/mine")
            },
            &[],
            None
        )),
        NsErrorKind::Escapes
    );

    // Nothing outside changed, nothing leaked in.
    assert_eq!(fs::read(f.outside.join("secret.txt")).unwrap(), OUTSIDE);
    assert_eq!(fs::read_dir(&f.outside).unwrap().count(), 1);
    // The links are not listed: they cannot be named.
    let names: Vec<_> = f
        .dir
        .walk(&NsPath::root())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["mine"]);
}

#[cfg(unix)]
#[test]
fn a_symlink_that_stays_inside_the_root_is_refused_too() {
    let f = fixture();
    fs::write(f.root.join("real"), INSIDE).unwrap();
    fs::create_dir(f.root.join("realdir")).unwrap();
    fs::write(f.root.join("realdir/f"), INSIDE).unwrap();
    symlink("real", f.root.join("alias")).unwrap();
    symlink("realdir", f.root.join("diralias")).unwrap();
    symlink("does-not-exist", f.root.join("dangling")).unwrap();
    assert_eq!(kind(f.dir.read(&p("/alias"), 1024)), NsErrorKind::Escapes);
    assert_eq!(
        kind(f.dir.read(&p("/diralias/f"), 1024)),
        NsErrorKind::Escapes
    );
    assert_eq!(kind(f.dir.walk(&p("/diralias"))), NsErrorKind::Escapes);
    assert_eq!(kind(f.dir.stat(&p("/dangling"))), NsErrorKind::Escapes);
    assert_eq!(
        kind(f.dir.write(&p("/dangling"), WriteOp::Replace, b"x", None)),
        NsErrorKind::Escapes
    );
    assert!(
        !f.root.join("does-not-exist").exists(),
        "a write through a dangling link must not create its target"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_swapped_in_during_use_never_yields_outside_content() {
    let f = fixture();
    within(
        60,
        "a_symlink_swapped_in_during_use_never_yields_outside_content",
        move || {
            fs::write(f.root.join("f"), INSIDE).unwrap();
            let stop = AtomicBool::new(false);
            let (mut ok, mut escapes, mut other) = (0u64, 0u64, 0u64);

            std::thread::scope(|s| {
                // The attacker flips `f` between a regular file and a symlink to the outside secret, atomically, with rename.
                s.spawn(|| {
                    let mut i = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let _ = fs::remove_file(f.root.join("flip"));
                        symlink(f.outside.join("secret.txt"), f.root.join("flip")).unwrap();
                        fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                        fs::write(f.root.join("flip"), INSIDE).unwrap();
                        fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                        i += 1;
                    }
                    assert!(i > 0);
                });
                // The reader reads in a loop for a bounded time.
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(5)
                    && (started.elapsed() < Duration::from_millis(1500) || ok == 0 || escapes == 0)
                {
                    match f.dir.read(&p("/f"), 1024) {
                        Ok((bytes, _)) => {
                            assert_eq!(
                                bytes, INSIDE,
                                "read returned content that is not the inside file's"
                            );
                            assert!(!bytes.windows(OUTSIDE.len()).any(|w| w == OUTSIDE));
                            ok += 1;
                        }
                        Err(e) if e.kind() == NsErrorKind::Escapes => escapes += 1,
                        Err(_) => other += 1,
                    }
                }
                stop.store(true, Ordering::Relaxed);
            });
            eprintln!("symlink swap race: ok={ok} escapes={escapes} other={other}");
            assert!(
                ok > 0,
                "the race never let a read through; the test proved nothing"
            );
            assert!(
                escapes > 0,
                "the race never presented a symlink; the test proved nothing"
            );
        },
    );
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_symlink_never_yields_outside_content() {
    let f = fixture();
    within(
        60,
        "a_directory_swapped_for_a_symlink_never_yields_outside_content",
        move || {
            fs::create_dir(f.root.join("real")).unwrap();
            fs::write(f.root.join("real/secret.txt"), INSIDE).unwrap();
            fs::create_dir(f.root.join("d")).unwrap();
            fs::write(f.root.join("d/secret.txt"), INSIDE).unwrap();
            let stop = AtomicBool::new(false);
            let (mut ok, mut escapes) = (0u64, 0u64);

            std::thread::scope(|s| {
                s.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        // d: directory -> symlink to the outside directory ...
                        fs::rename(f.root.join("d"), f.root.join("parked")).unwrap();
                        symlink(&f.outside, f.root.join("d")).unwrap();
                        // ... and back.
                        fs::remove_file(f.root.join("d")).unwrap();
                        fs::rename(f.root.join("parked"), f.root.join("d")).unwrap();
                    }
                });
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(5)
                    && (started.elapsed() < Duration::from_millis(1500) || ok == 0 || escapes == 0)
                {
                    match f.dir.read(&p("/d/secret.txt"), 1024) {
                        Ok((bytes, _)) => {
                            assert_eq!(
                                bytes, INSIDE,
                                "read returned content from the outside directory"
                            );
                            ok += 1;
                        }
                        Err(e) if e.kind() == NsErrorKind::Escapes => escapes += 1,
                        Err(_) => {}
                    }
                    // Writes through the swapped path must never land outside either.
                    let _ = f
                        .dir
                        .write(&p("/d/dropped"), WriteOp::CreateExclusive, b"x", None);
                    let _ = f.dir.walk(&p("/d"));
                }
                stop.store(true, Ordering::Relaxed);
            });
            eprintln!("dir swap race: ok={ok} escapes={escapes}");
            assert!(
                ok > 0 && escapes > 0,
                "the race must exercise both states (ok={ok}, escapes={escapes})"
            );
            assert_eq!(fs::read(f.outside.join("secret.txt")).unwrap(), OUTSIDE);
            assert!(
                !f.outside.join("dropped").exists(),
                "a write escaped through a swapped directory"
            );
            assert_eq!(
                fs::read_dir(&f.outside).unwrap().count(),
                1,
                "something was created outside the root"
            );
        },
    );
}

#[cfg(unix)]
#[test]
fn a_replace_never_writes_through_a_symlink_swapped_in_underneath_it() {
    let f = fixture();
    within(
        60,
        "a_replace_never_writes_through_a_symlink_swapped_in_underneath_it",
        move || {
            fs::write(f.root.join("f"), INSIDE).unwrap();
            let stop = AtomicBool::new(false);
            std::thread::scope(|s| {
                s.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = fs::remove_file(f.root.join("flip"));
                        symlink(f.outside.join("secret.txt"), f.root.join("flip")).unwrap();
                        fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                        fs::write(f.root.join("flip"), INSIDE).unwrap();
                        fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                    }
                });
                let started = Instant::now();
                while started.elapsed() < Duration::from_millis(1500) {
                    let _ = f.dir.write(&p("/f"), WriteOp::Replace, b"REPLACED", None);
                }
                stop.store(true, Ordering::Relaxed);
            });
            assert_eq!(
                fs::read(f.outside.join("secret.txt")).unwrap(),
                OUTSIDE,
                "a replace wrote through a symlink"
            );
        },
    );
}

#[test]
fn case_collisions_are_refused_even_on_a_case_sensitive_volume() {
    let f = fixture();
    f.dir
        .write(&p("/Report.txt"), WriteOp::CreateExclusive, b"1", None)
        .unwrap();
    for (path, op, data) in [
        ("/report.txt", WriteOp::CreateExclusive, &b"2"[..]),
        ("/REPORT.TXT", WriteOp::Replace, &b"2"[..]),
        ("/rePort.txt", WriteOp::MakeDir, &b""[..]),
    ] {
        assert_eq!(
            kind(f.dir.write(&p(path), op, data, None)),
            NsErrorKind::CaseCollision,
            "{path}"
        );
    }
    fs::write(f.root.join("other"), b"x").unwrap();
    assert_eq!(
        kind(f.dir.write(
            &p("/other"),
            WriteOp::RenameWithinMount {
                to: p("/REPORT.txt")
            },
            &[],
            None
        )),
        NsErrorKind::CaseCollision
    );
    // The exact name is "taken", not a "collision": the two must be told apart on every platform, including the
    // case-insensitive volumes (macOS, Windows) whose lstat answers "exists" to either spelling.
    for (op, data) in [
        (WriteOp::CreateExclusive, &b"2"[..]),
        (WriteOp::MakeDir, &b""[..]),
    ] {
        assert_eq!(
            kind(f.dir.write(&p("/Report.txt"), op, data, None)),
            NsErrorKind::AlreadyExists
        );
    }
    f.dir
        .write(&p("/Report.txt"), WriteOp::Replace, b"3", None)
        .unwrap();
    // A collision that already exists on disk (made behind the Kit's back) is also noticed on the next create.
    fs::write(f.root.join("Pre.txt"), b"x").unwrap();
    assert_eq!(
        kind(
            f.dir
                .write(&p("/pre.txt"), WriteOp::CreateExclusive, b"y", None)
        ),
        NsErrorKind::CaseCollision
    );
    assert_eq!(
        kind(f.dir.write(&p("/PRE.TXT"), WriteOp::Replace, b"y", None)),
        NsErrorKind::CaseCollision
    );
    assert_eq!(fs::read(f.root.join("Pre.txt")).unwrap(), b"x");
    let names: Vec<_> = f
        .dir
        .walk(&NsPath::root())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(
        !names.iter().any(|n| n == "report.txt" || n == "REPORT.TXT"),
        "{names:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_hard_linked_file_is_refused_on_write() {
    let f = fixture();
    fs::write(f.root.join("a"), b"data").unwrap();
    fs::hard_link(f.root.join("a"), f.root.join("b")).unwrap();
    assert_eq!(
        kind(f.dir.write(&p("/a"), WriteOp::Replace, b"new", None)),
        NsErrorKind::HardLinked
    );
    assert_eq!(
        kind(f.dir.write(&p("/b"), WriteOp::Replace, b"new", None)),
        NsErrorKind::HardLinked
    );
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"data");
    assert_eq!(f.dir.stat(&p("/a")).unwrap().links, Some(2));
    // A hard link to a file outside the root. `Replace` renames over the NAME, so it would not change the outside file
    // even without this guard (the other name keeps the old inode and its contents); the refusal is kept because the
    // guard is what protects an in-place write the day `append` / `at_offset` exist, and a multiply-linked file in a
    // mount is worth refusing outright until then.
    fs::hard_link(f.outside.join("secret.txt"), f.root.join("alias")).unwrap();
    assert_eq!(
        kind(f.dir.write(&p("/alias"), WriteOp::Replace, b"pwned", None)),
        NsErrorKind::HardLinked
    );
    assert_eq!(fs::read(f.outside.join("secret.txt")).unwrap(), OUTSIDE);
    // Once the extra link is gone the file is writable again.
    fs::remove_file(f.root.join("b")).unwrap();
    f.dir
        .write(&p("/a"), WriteOp::Replace, b"new", None)
        .unwrap();
    assert_eq!(fs::read(f.root.join("a")).unwrap(), b"new");
}

/// The documented limit of a best-effort version (see the `hostdir` module docs): the version is mtime, size and file
/// identity, so an in-place edit that keeps the size AND the mtime is not told apart. A real edit only gets there by
/// landing in the same timestamp tick as the previous write; the test sets the mtime back by hand so it is deterministic
/// on every platform instead of depending on the clock.
#[test]
fn an_in_place_edit_with_the_same_size_and_mtime_is_not_detected() {
    let f = fixture();
    let path = f.root.join("f");
    fs::write(&path, b"0123456789").unwrap();
    let before = f.dir.stat(&p("/f")).unwrap();
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, b"abcdefghij").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(
        f.dir.stat(&p("/f")).unwrap().version,
        before.version,
        "same size, same mtime, same file: the version cannot tell"
    );
    f.dir
        .write(&p("/f"), WriteOp::Replace, b"new", Some(&before.version))
        .unwrap();
    // A change of size is always seen.
    let v = f.dir.stat(&p("/f")).unwrap().version;
    fs::write(&path, b"longer than before").unwrap();
    assert_eq!(
        kind(f.dir.write(&p("/f"), WriteOp::Replace, b"x", Some(&v))),
        NsErrorKind::VersionMismatch
    );
}

/// `read` does not refuse a file with more than one hard link (only writes do), and `stat` reports the count so an
/// embedder can. The module docs say exactly this; this test is what keeps them honest. A hard link from outside the
/// root is served. If a later release decides to refuse such reads, this test changes with that decision.
#[cfg(unix)]
#[test]
fn a_hard_linked_file_is_served_on_read_and_stat_reports_the_links() {
    let f = fixture();
    fs::hard_link(f.outside.join("secret.txt"), f.root.join("alias")).unwrap();
    let (bytes, _) = f.dir.read(&p("/alias"), 100).unwrap();
    assert_eq!(bytes, OUTSIDE);
    assert_eq!(f.dir.stat(&p("/alias")).unwrap().links, Some(2));
    // The write side of the same file is still refused.
    assert_eq!(
        kind(f.dir.write(&p("/alias"), WriteOp::Replace, b"x", None)),
        NsErrorKind::HardLinked
    );
    assert_eq!(fs::read(f.outside.join("secret.txt")).unwrap(), OUTSIDE);
}

/// What "refuses" means for a hard-linked file, pinned: `Replace` is refused, but `Remove` and `RenameWithinMount` act on
/// the NAME and are allowed, and none of them changes the contents of the file as reached through its other name. The
/// module docs say exactly this.
#[cfg(unix)]
#[test]
fn remove_and_rename_of_a_hard_linked_file_are_allowed_and_leave_the_other_name_intact() {
    let f = fixture();
    // A link to a file outside the root, and a link between two names inside it.
    fs::hard_link(f.outside.join("secret.txt"), f.root.join("alias")).unwrap();
    fs::write(f.root.join("a"), b"shared").unwrap();
    fs::hard_link(f.root.join("a"), f.root.join("b")).unwrap();

    assert_eq!(
        kind(f.dir.write(&p("/alias"), WriteOp::Replace, b"x", None)),
        NsErrorKind::HardLinked
    );
    // Rename acts on the name.
    f.dir
        .write(
            &p("/alias"),
            WriteOp::RenameWithinMount { to: p("/moved") },
            &[],
            None,
        )
        .unwrap();
    assert!(fs::symlink_metadata(f.root.join("alias")).is_err());
    assert_eq!(fs::read(f.root.join("moved")).unwrap(), OUTSIDE);
    assert_eq!(fs::read(f.outside.join("secret.txt")).unwrap(), OUTSIDE);
    // Remove acts on the name, too: the other name keeps its contents.
    f.dir
        .write(&p("/moved"), WriteOp::Remove, &[], None)
        .unwrap();
    assert!(fs::symlink_metadata(f.root.join("moved")).is_err());
    assert_eq!(fs::read(f.outside.join("secret.txt")).unwrap(), OUTSIDE);
    f.dir.write(&p("/a"), WriteOp::Remove, &[], None).unwrap();
    assert_eq!(fs::read(f.root.join("b")).unwrap(), b"shared");
    assert_eq!(f.dir.stat(&p("/b")).unwrap().links, Some(1));
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    let status = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo must be available to run this test");
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn a_fifo_is_refused_and_never_opened() {
    let f = fixture();
    within(30, "a_fifo_is_refused_and_never_opened", move || {
        mkfifo(&f.root.join("pipe"));
        // If any of these opened the FIFO for reading it would block forever with no writer; the test would hang.
        assert_eq!(kind(f.dir.read(&p("/pipe"), 1024)), NsErrorKind::NotRegular);
        assert_eq!(kind(f.dir.stat(&p("/pipe"))), NsErrorKind::NotRegular);
        assert_eq!(
            kind(f.dir.write(&p("/pipe"), WriteOp::Replace, b"x", None)),
            NsErrorKind::NotRegular
        );
        assert_eq!(
            kind(f.dir.write(&p("/pipe"), WriteOp::Remove, &[], None)),
            NsErrorKind::NotRegular
        );
        assert_eq!(kind(f.dir.walk(&p("/pipe"))), NsErrorKind::NotRegular);
        assert!(
            f.dir.walk(&NsPath::root()).unwrap().is_empty(),
            "a FIFO is not listed"
        );
        assert_eq!(
            kind(
                f.dir
                    .write(&p("/pipe"), WriteOp::CreateExclusive, b"x", None)
            ),
            NsErrorKind::AlreadyExists
        );
    });
}

#[cfg(unix)]
#[test]
fn a_fifo_swapped_in_after_the_check_cannot_hang_a_read() {
    // Race the swap: a regular file and a FIFO alternate under one name. A blocking open would hang this test.
    let f = fixture();
    within(
        60,
        "a_fifo_swapped_in_after_the_check_cannot_hang_a_read",
        move || {
            fs::write(f.root.join("f"), INSIDE).unwrap();
            let stop = AtomicBool::new(false);
            let mut fifo_seen = 0u64;
            let started = Instant::now();
            std::thread::scope(|s| {
                s.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = fs::remove_file(f.root.join("flip"));
                        mkfifo(&f.root.join("flip"));
                        fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                        fs::write(f.root.join("flip"), INSIDE).unwrap();
                        fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                    }
                });
                while started.elapsed() < Duration::from_millis(1500) {
                    match f.dir.read(&p("/f"), 1024) {
                        Ok((bytes, _)) => assert_eq!(bytes, INSIDE),
                        Err(e) if e.kind() == NsErrorKind::NotRegular => fifo_seen += 1,
                        Err(_) => {}
                    }
                }
                stop.store(true, Ordering::Relaxed);
            });
            eprintln!("fifo swap race: fifo seen {fifo_seen} times");
            assert!(started.elapsed() < Duration::from_secs(30));
        },
    );
}

#[test]
fn a_read_over_max_is_refused_not_truncated() {
    let f = fixture();
    fs::write(f.root.join("ten"), b"0123456789").unwrap();
    assert_eq!(f.dir.read(&p("/ten"), 10).unwrap().0, b"0123456789");
    assert_eq!(kind(f.dir.read(&p("/ten"), 9)), NsErrorKind::TooLarge);
    assert_eq!(kind(f.dir.read(&p("/ten"), 0)), NsErrorKind::TooLarge);
    // u64::MAX must not overflow the "max + 1" read bound.
    assert_eq!(f.dir.read(&p("/ten"), u64::MAX).unwrap().0.len(), 10);
}

#[cfg(unix)]
#[test]
fn names_outside_the_grammar_on_disk_are_not_listed_or_addressable() {
    let f = fixture();
    fs::write(f.root.join("fine"), b"x").unwrap();
    fs::write(f.root.join("e\u{301}"), b"nfd").unwrap(); // NFD name
    fs::write(f.root.join("CON"), b"reserved").unwrap();
    fs::write(f.root.join("trailing."), b"dot").unwrap();
    fs::write(f.root.join(".skns-tmp-leftover"), b"temp").unwrap();
    let names: Vec<_> = f
        .dir
        .walk(&NsPath::root())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["fine"]);
}

#[cfg(unix)]
#[test]
fn created_files_are_0600_and_directories_0700() {
    let f = fixture();
    f.dir
        .write(&p("/created"), WriteOp::CreateExclusive, b"x", None)
        .unwrap();
    f.dir
        .write(&p("/replaced"), WriteOp::Replace, b"x", None)
        .unwrap();
    f.dir.write(&p("/d"), WriteOp::MakeDir, &[], None).unwrap();
    for (name, want) in [("created", 0o600), ("replaced", 0o600), ("d", 0o700)] {
        let mode = fs::metadata(f.root.join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, want, "{name}");
    }
    // `Replace` of a more permissive file yields 0600 (documented): never wider than before.
    fs::set_permissions(f.root.join("replaced"), fs::Permissions::from_mode(0o666)).unwrap();
    f.dir
        .write(&p("/replaced"), WriteOp::Replace, b"y", None)
        .unwrap();
    assert_eq!(
        fs::metadata(f.root.join("replaced"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn stat_reports_owner_mode_links_and_the_caps_say_so() {
    let f = fixture();
    let caps = f.dir.caps();
    assert!(caps.owner_mode && caps.strict_confinement && caps.writable && caps.atomic_replace);
    assert!(
        !caps.exact_if_version,
        "HostDir versions are best effort and must say so"
    );
    assert_eq!(caps.watch, storage_kit::ns::WatchKind::Polling);
    f.dir
        .write(&p("/f"), WriteOp::Replace, b"abc", None)
        .unwrap();
    let st = f.dir.stat(&p("/f")).unwrap();
    assert_eq!(st.kind, Kind::File);
    assert_eq!(st.size, 3);
    assert_eq!(st.owner, Some(fs::metadata(&f.root).unwrap().uid()));
    assert_eq!(st.mode, Some(0o600));
    assert_eq!(st.links, Some(1));
    assert!(st.modified.is_some());
    let root = f.dir.stat(&NsPath::root()).unwrap();
    assert_eq!((root.kind, root.size), (Kind::Dir, 0));
}

#[test]
fn replace_is_atomic_for_concurrent_readers() {
    let f = fixture();
    let a = vec![b'a'; 256 * 1024];
    let b = vec![b'b'; 256 * 1024];
    f.dir.write(&p("/big"), WriteOp::Replace, &a, None).unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut flip = false;
            while !stop.load(Ordering::Relaxed) {
                f.dir
                    .write(
                        &p("/big"),
                        WriteOp::Replace,
                        if flip { &a } else { &b },
                        None,
                    )
                    .unwrap();
                flip = !flip;
            }
        });
        let started = Instant::now();
        let mut reads = 0;
        while started.elapsed() < Duration::from_secs(1) {
            let (bytes, _) = f.dir.read(&p("/big"), 1 << 20).unwrap();
            assert_eq!(bytes.len(), a.len(), "a reader saw a partial file");
            assert!(
                bytes.iter().all(|x| *x == bytes[0]),
                "a reader saw a mix of old and new content"
            );
            reads += 1;
        }
        stop.store(true, Ordering::Relaxed);
        assert!(reads > 10);
    });
    // And no temporary file is left behind.
    let leftovers: Vec<_> = fs::read_dir(&f.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n != "big")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files left behind: {leftovers:?}"
    );
}

#[test]
fn if_version_on_host_dir_detects_a_change_made_before_the_check() {
    // Best effort, as the caps say: a change that happened BEFORE the call is caught. (A change inside the
    // check-then-act window is not, and no test pretends otherwise.)
    let f = fixture();
    let v1 = f
        .dir
        .write(&p("/f"), WriteOp::Replace, b"one", None)
        .unwrap();
    // Another process (here: the test, directly on disk) changes it.
    std::thread::sleep(Duration::from_millis(20));
    fs::write(f.root.join("f"), b"changed behind our back").unwrap();
    assert_eq!(
        kind(f.dir.write(&p("/f"), WriteOp::Replace, b"two", Some(&v1))),
        NsErrorKind::VersionMismatch
    );
    // A replace by file swap (new inode, same size) is caught as well.
    let v2 = f.dir.stat(&p("/f")).unwrap().version;
    fs::write(f.root.join("tmp"), b"changed behind our back").unwrap();
    fs::rename(f.root.join("tmp"), f.root.join("f")).unwrap();
    assert_eq!(
        kind(f.dir.write(&p("/f"), WriteOp::Remove, &[], Some(&v2))),
        NsErrorKind::VersionMismatch
    );
    assert_eq!(
        fs::read(f.root.join("f")).unwrap(),
        b"changed behind our back"
    );
}

#[test]
fn no_host_path_appears_in_any_error() {
    let f = fixture();
    let root_str = f.root.to_string_lossy().to_string();
    let tmp_str = f.root.parent().unwrap().to_string_lossy().to_string();
    fs::write(f.root.join("file"), b"0123456789").unwrap();
    fs::write(f.root.join("full"), b"x").unwrap();
    fs::create_dir(f.root.join("dir")).unwrap();
    fs::write(f.root.join("dir/x"), b"x").unwrap();
    #[cfg(unix)]
    {
        symlink(&f.outside, f.root.join("link")).unwrap();
        fs::write(f.root.join("h1"), b"x").unwrap();
        fs::hard_link(f.root.join("h1"), f.root.join("h2")).unwrap();
        mkfifo(&f.root.join("pipe"));
    }
    let stale = f.dir.stat(&p("/file")).unwrap().version;
    // A DIFFERENT length, on purpose: a same-length rewrite of the same file right after the stat can land in the same
    // timestamp tick and leave the version unchanged (a documented limit, and exactly how this test once failed on the
    // Windows runner). The size is part of the version, so this change is seen on every platform.
    fs::write(f.root.join("file"), b"changed, and longer").unwrap();

    let mut errors = vec![
        f.dir.read(&p("/missing"), 10).unwrap_err(),
        f.dir.read(&p("/dir"), 10).unwrap_err(),
        f.dir.read(&p("/file"), 3).unwrap_err(),
        f.dir.read(&p("/file/inside"), 3).unwrap_err(),
        f.dir.walk(&p("/file")).unwrap_err(),
        f.dir.walk(&p("/nope")).unwrap_err(),
        f.dir.stat(&p("/nope/deeper")).unwrap_err(),
        f.dir
            .write(&p("/file"), WriteOp::CreateExclusive, b"x", None)
            .unwrap_err(),
        f.dir
            .write(&p("/FILE"), WriteOp::CreateExclusive, b"x", None)
            .unwrap_err(),
        f.dir
            .write(&p("/dir"), WriteOp::Remove, &[], None)
            .unwrap_err(),
        f.dir
            .write(&p("/dir"), WriteOp::Replace, b"x", None)
            .unwrap_err(),
        f.dir
            .write(&p("/file"), WriteOp::Replace, b"x", Some(&stale))
            .unwrap_err(),
        f.dir
            .write(&p("/file"), WriteOp::Remove, b"data", None)
            .unwrap_err(),
        f.dir
            .write(
                &p("/file"),
                WriteOp::RenameWithinMount { to: p("/full") },
                &[],
                None,
            )
            .unwrap_err(),
        f.dir
            .write(&NsPath::root(), WriteOp::Remove, &[], None)
            .unwrap_err(),
        f.dir.watch(&p("/file"), Default::default()).unwrap_err(),
        f.dir.watch(&p("/nope"), Default::default()).unwrap_err(),
        HostDir::open_ambient(f.root.join("no-such-root")).unwrap_err(),
        HostDir::open_ambient(f.root.join("file")).unwrap_err(),
    ];
    errors.push(NsPath::parse(&format!("{root_str}/../x")).unwrap_err());
    #[cfg(unix)]
    errors.extend([
        f.dir.read(&p("/link"), 3).unwrap_err(),
        f.dir.read(&p("/link/secret.txt"), 3).unwrap_err(),
        f.dir.read(&p("/pipe"), 3).unwrap_err(),
        f.dir.walk(&p("/link")).unwrap_err(),
        f.dir
            .write(&p("/h1"), WriteOp::Replace, b"x", None)
            .unwrap_err(),
    ]);
    assert!(errors.len() > 16);
    for e in &errors {
        for text in [e.to_string(), format!("{e:?}"), format!("{e:#?}")] {
            assert!(!text.contains(&root_str), "host path in an error: {text}");
            assert!(!text.contains(&tmp_str), "host path in an error: {text}");
            assert!(
                !text.contains("HOSTSECRET"),
                "host path fragment in an error: {text}"
            );
            assert!(
                !text.contains("outside"),
                "host path fragment in an error: {text}"
            );
        }
    }
    // The kinds were the ones intended, not just "some error".
    let kinds: Vec<_> = errors.iter().map(|e| e.kind()).collect();
    for want in [
        NsErrorKind::NotFound,
        NsErrorKind::IsADirectory,
        NsErrorKind::TooLarge,
        NsErrorKind::NotADirectory,
        NsErrorKind::AlreadyExists,
        NsErrorKind::CaseCollision,
        NsErrorKind::NotEmpty,
        NsErrorKind::VersionMismatch,
    ] {
        assert!(
            kinds.contains(&want),
            "no error of kind {want:?} was exercised: {kinds:?}"
        );
    }
    #[cfg(unix)]
    for want in [
        NsErrorKind::Escapes,
        NsErrorKind::NotRegular,
        NsErrorKind::HardLinked,
    ] {
        assert!(
            kinds.contains(&want),
            "no error of kind {want:?}: {kinds:?}"
        );
    }
    // A mount-relative error names the namespace path it was asked about.
    let e = f.dir.read(&p("/missing"), 10).unwrap_err();
    assert_eq!(e.path().map(NsPath::as_str), Some("/missing"));
    // Debug of the backend itself shows no path either.
    assert!(!format!("{:?}", f.dir).contains("HOSTSECRET"));
}

#[test]
fn from_dir_confines_to_the_handle_it_was_given() {
    let f = fixture();
    fs::create_dir(f.root.join("sub")).unwrap();
    fs::write(f.root.join("sub/f"), b"sub").unwrap();
    fs::write(f.root.join("top"), b"top").unwrap();
    let handle =
        cap_std::fs::Dir::open_ambient_dir(f.root.join("sub"), cap_std::ambient_authority())
            .unwrap();
    let sub = HostDir::from_dir(handle).unwrap();
    assert_eq!(sub.read(&p("/f"), 10).unwrap().0, b"sub");
    // The parent is unreachable from this mount: there is no such name, and `..` is not a path.
    assert_eq!(kind(sub.read(&p("/top"), 10)), NsErrorKind::NotFound);
    assert!(NsPath::parse("/../top").is_err());
}

#[test]
fn write_ops_return_the_version_stat_reports() {
    let f = fixture();
    let v = f
        .dir
        .write(&p("/f"), WriteOp::CreateExclusive, b"abc", None)
        .unwrap();
    assert_eq!(f.dir.stat(&p("/f")).unwrap().version, v);
    let v = f
        .dir
        .write(&p("/f"), WriteOp::Replace, b"abcdef", None)
        .unwrap();
    assert_eq!(f.dir.stat(&p("/f")).unwrap().version, v);
    assert_eq!(f.dir.read(&p("/f"), 100).unwrap().1, v);
    let d = f.dir.write(&p("/d"), WriteOp::MakeDir, &[], None).unwrap();
    assert_eq!(f.dir.stat(&p("/d")).unwrap().version, d);
}

/// Reads `path` in a loop against a flipper thread for a bounded time and counts what came back. `must_be` is the only
/// content a read may ever return; anything else (typically the content of the OTHER in-root file, reached through a
/// symlink the open should have refused) is a failure.
#[cfg(unix)]
fn race_reads(
    f: std::sync::Arc<Fixture>,
    flip: impl Fn(&Fixture) + Send + 'static,
    path: &'static str,
    must_be: &'static [u8],
) -> (u64, u64) {
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let flipper = {
        let (f, stop) = (f.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                flip(&f);
            }
        })
    };
    let (mut ok, mut refused) = (0u64, 0u64);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(8)
        && (started.elapsed() < Duration::from_millis(2500) || ok == 0 || refused == 0)
    {
        match f.dir.read(&p(path), 1024) {
            Ok((bytes, _)) => {
                assert_eq!(
                    bytes, must_be,
                    "a read through a swapped path returned another file's content: the open followed a symlink"
                );
                ok += 1;
            }
            Err(e) if e.kind() == NsErrorKind::Escapes => refused += 1,
            Err(_) => {}
        }
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().unwrap();
    (ok, refused)
}

#[cfg(unix)]
#[test]
fn a_file_swapped_for_a_symlink_to_another_file_inside_the_root_is_never_followed() {
    // The outside-the-root case is also stopped by cap-std's containment. A symlink to ANOTHER FILE INSIDE the root is
    // not: only the no-follow open stands between the `lstat` (which saw a regular file) and the content of `other`.
    // This is the test that fails if `FollowSymlinks::No` becomes `Yes` on the read open.
    let f = std::sync::Arc::new(fixture());
    fs::write(f.root.join("f"), INSIDE).unwrap();
    fs::write(f.root.join("other"), OTHER_INSIDE).unwrap();
    let f2 = f.clone();
    within(90, "in-root file swap", move || {
        let (ok, refused) = race_reads(
            f2,
            |f| {
                let _ = fs::remove_file(f.root.join("flip"));
                symlink("other", f.root.join("flip")).unwrap();
                fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
                fs::write(f.root.join("flip"), INSIDE).unwrap();
                fs::rename(f.root.join("flip"), f.root.join("f")).unwrap();
            },
            "/f",
            INSIDE,
        );
        eprintln!("in-root file swap: ok={ok} refused={refused}");
        assert!(
            ok > 0 && refused > 0,
            "the race must present both states (ok={ok}, refused={refused})"
        );
    });
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_symlink_to_another_directory_inside_the_root_is_never_followed() {
    let f = std::sync::Arc::new(fixture());
    fs::create_dir(f.root.join("d")).unwrap();
    fs::write(f.root.join("d/marker"), INSIDE).unwrap();
    fs::create_dir(f.root.join("elsewhere")).unwrap();
    fs::write(f.root.join("elsewhere/marker"), OTHER_INSIDE).unwrap();
    let f2 = f.clone();
    within(90, "in-root directory swap", move || {
        let (ok, refused) = race_reads(
            f2,
            |f| {
                fs::rename(f.root.join("d"), f.root.join("parked")).unwrap();
                symlink("elsewhere", f.root.join("d")).unwrap();
                fs::remove_file(f.root.join("d")).unwrap();
                fs::rename(f.root.join("parked"), f.root.join("d")).unwrap();
            },
            "/d/marker",
            INSIDE,
        );
        eprintln!("in-root dir swap: ok={ok} refused={refused}");
        assert!(
            ok > 0 && refused > 0,
            "the race must present both states (ok={ok}, refused={refused})"
        );
    });
}

#[cfg(unix)]
#[test]
fn creating_over_a_symlink_name_is_refused_and_never_writes_through() {
    let f = fixture();
    symlink("target-that-does-not-exist", f.root.join("dangling")).unwrap();
    fs::write(f.root.join("real"), b"real").unwrap();
    symlink("real", f.root.join("alias")).unwrap();
    for name in ["/dangling", "/alias"] {
        assert_eq!(
            kind(
                f.dir
                    .write(&p(name), WriteOp::CreateExclusive, b"pwned", None)
            ),
            NsErrorKind::AlreadyExists,
            "{name}"
        );
        assert_eq!(
            kind(f.dir.write(&p(name), WriteOp::Replace, b"pwned", None)),
            NsErrorKind::Escapes,
            "{name}"
        );
    }
    assert!(!f.root.join("target-that-does-not-exist").exists());
    assert_eq!(fs::read(f.root.join("real")).unwrap(), b"real");
}

#[test]
fn an_nfd_named_file_cannot_be_overwritten_by_its_nfc_twin() {
    // APFS and HFS+ treat the two spellings as one name. Whatever the platform, the Kit refuses to create the twin:
    // their fold keys are equal, and the comparison is against the names as listed.
    let f = fixture();
    fs::write(f.root.join("e\u{301}clair.txt"), b"the NFD original").unwrap();
    for (op, data) in [
        (WriteOp::CreateExclusive, &b"twin"[..]),
        (WriteOp::Replace, &b"twin"[..]),
        (WriteOp::MakeDir, &b""[..]),
    ] {
        assert_eq!(
            kind(f.dir.write(&p("/\u{e9}clair.txt"), op, data, None)),
            NsErrorKind::CaseCollision
        );
    }
    // The NFD name is not addressable (the grammar wants NFC), so it is not listed either, and nothing was overwritten.
    assert_eq!(
        fs::read(f.root.join("e\u{301}clair.txt")).unwrap(),
        b"the NFD original"
    );
}

#[test]
fn a_rename_onto_itself_is_refused_but_a_respelling_of_its_own_name_is_allowed() {
    let f = fixture();
    f.dir
        .write(&p("/Note.txt"), WriteOp::CreateExclusive, b"n", None)
        .unwrap();
    assert_eq!(
        kind(f.dir.write(
            &p("/Note.txt"),
            WriteOp::RenameWithinMount { to: p("/Note.txt") },
            &[],
            None
        )),
        NsErrorKind::AlreadyExists
    );
    f.dir
        .write(
            &p("/Note.txt"),
            WriteOp::RenameWithinMount { to: p("/NOTE.TXT") },
            &[],
            None,
        )
        .unwrap();
    f.dir
        .write(
            &p("/NOTE.TXT"),
            WriteOp::RenameWithinMount { to: p("/note.txt") },
            &[],
            None,
        )
        .unwrap();
    let names: Vec<_> = f
        .dir
        .walk(&NsPath::root())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["note.txt"]);
    assert_eq!(f.dir.read(&p("/note.txt"), 10).unwrap().0, b"n");
}

/// Respelling an entry while moving it between two spellings of one directory. Whether `/Dir` and `/dir` are one
/// directory or two depends on the volume, so the test asks the volume (a probe file, looked up under the other case) and
/// checks the right answer for each: on a case-insensitive volume the rename is the entry's own respelling and must not
/// be refused as a collision with itself; on a case-sensitive one `/dir` is a different directory, whose entries are
/// real siblings that must still be protected.
#[test]
fn a_rename_between_two_spellings_of_a_directory_is_decided_by_the_directory_not_the_spelling() {
    let f = fixture();
    fs::create_dir(f.root.join("Dir")).unwrap();
    fs::write(f.root.join("Dir/x"), b"mine").unwrap();
    let case_insensitive = f.root.join("dir").exists();
    let names_in = |dir: &str| -> Vec<String> {
        f.dir
            .walk(&p(dir))
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect()
    };

    if case_insensitive {
        // One directory under two spellings: `/Dir/x` becomes `/dir/X`, a respelling, allowed.
        f.dir
            .write(
                &p("/Dir/x"),
                WriteOp::RenameWithinMount { to: p("/dir/X") },
                &[],
                None,
            )
            .unwrap();
        assert_eq!(names_in("/Dir"), ["X"]);
        assert_eq!(f.dir.read(&p("/Dir/X"), 10).unwrap().0, b"mine");
        // It is still a rename onto an existing name when it really is one.
        fs::write(f.root.join("Dir/y"), b"other").unwrap();
        assert_eq!(
            kind(f.dir.write(
                &p("/Dir/y"),
                WriteOp::RenameWithinMount { to: p("/dir/x") },
                &[],
                None
            )),
            NsErrorKind::CaseCollision
        );
        assert_eq!(f.dir.read(&p("/Dir/y"), 10).unwrap().0, b"other");
    } else {
        // Two directories. `/dir` has its own `x`: the move must not replace it, and a case-only difference from it is
        // still a collision (the grammar is portable).
        fs::create_dir(f.root.join("dir")).unwrap();
        fs::write(f.root.join("dir/x"), b"theirs").unwrap();
        assert_eq!(
            kind(f.dir.write(
                &p("/Dir/x"),
                WriteOp::RenameWithinMount { to: p("/dir/x") },
                &[],
                None
            )),
            NsErrorKind::AlreadyExists
        );
        assert_eq!(
            kind(f.dir.write(
                &p("/Dir/x"),
                WriteOp::RenameWithinMount { to: p("/dir/X") },
                &[],
                None
            )),
            NsErrorKind::CaseCollision
        );
        assert_eq!(f.dir.read(&p("/dir/x"), 10).unwrap().0, b"theirs");
        assert_eq!(f.dir.read(&p("/Dir/x"), 10).unwrap().0, b"mine");
        // With nothing in the way, the move into the other directory works and keeps the new spelling.
        fs::remove_file(f.root.join("dir/x")).unwrap();
        f.dir
            .write(
                &p("/Dir/x"),
                WriteOp::RenameWithinMount { to: p("/dir/X") },
                &[],
                None,
            )
            .unwrap();
        assert_eq!(names_in("/dir"), ["X"]);
        assert!(names_in("/Dir").is_empty());
    }
}

#[test]
fn walk_is_sorted_by_utf8_bytes_on_a_real_directory() {
    let f = fixture();
    let given = [
        "zebra",
        "Zulu",
        "alpha",
        "\u{e9}clair",
        "\u{4e2d}\u{6587}",
        "Beta",
        "10",
        "9",
    ];
    for n in given {
        fs::write(f.root.join(n), b"x").unwrap();
    }
    let got: Vec<String> = f
        .dir
        .walk(&NsPath::root())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    let mut want: Vec<String> = given.iter().map(|s| s.to_string()).collect();
    want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(got, want);
    assert_eq!(got[0], "10");
    assert_eq!(got.last().unwrap(), "\u{4e2d}\u{6587}");
}
