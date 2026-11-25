//! A watch owns a thread, and dropping the watch must end it. This is its own test binary with one test so that no other
//! test's watches can be running and confuse the count.
#![cfg(all(feature = "ns", target_os = "linux"))]

use std::fs;
use std::time::{Duration, Instant};

use storage_kit::ns::{Backend, HostDir, NsPath, WatchOpts};

/// Live threads named like the poller, counted from `/proc`.
fn poller_threads() -> usize {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|e| fs::read_to_string(e.unwrap().path().join("comm")).ok())
        .filter(|name| name.trim() == "ns-watch-poll")
        .count()
}

/// Poll the count until it equals `want` or a deadline passes; returns the last count seen.
///
/// A fixed read right after `spawn` or `drop` is racy and was flaky: a new thread sets its own `comm` a moment after it
/// starts, and the `/proc` entry of a joined thread can outlive `join` briefly. The properties under test are "the
/// threads start" and "the threads end", so wait for them, with a generous bound so a real leak still fails.
fn settle(want: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let n = poller_threads();
        if n == want || Instant::now() >= deadline {
            return n;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn dropping_watches_ends_their_threads_and_leaks_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = HostDir::open_ambient(tmp.path()).unwrap();
    assert_eq!(settle(0), 0);

    for round in 0..3 {
        let watches: Vec<_> = (0..5)
            .map(|_| {
                dir.watch(
                    &NsPath::root(),
                    WatchOpts::default().interval(Duration::from_secs(60)),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(settle(5), 5, "round {round}: one thread per watch");
        drop(watches);
        // (That `Drop` joins its thread before returning is proven deterministically by the unit test in `watch.rs`;
        // here we only check, with a deadline, that no poller thread outlives its watch.)
        assert_eq!(
            settle(0),
            0,
            "round {round}: dropping the watches must end their threads"
        );
    }

    // A watch whose consumer simply stops reading does not grow without bound either: the queue is bounded, and what
    // does not fit is dropped (visible as a generation gap).
    let w = dir
        .watch(
            &NsPath::root(),
            WatchOpts::default().interval(Duration::from_millis(10)),
        )
        .unwrap();
    for i in 0..60 {
        fs::write(tmp.path().join(format!("f{i}")), b"x").unwrap();
        std::thread::sleep(Duration::from_millis(15));
    }
    // The queue kept the oldest batches, contiguous, and dropped the rest. The loss shows on the NEXT batch: a consumer
    // that has drained the queue and re-read gets a batch whose generation jumps.
    let mut cursor = storage_kit::ns::WatchCursor::new();
    let mut batches = 0;
    while let Ok(b) = w.try_recv() {
        batches += 1;
        assert!(!cursor.observe(&b), "the delivered prefix is contiguous");
    }
    assert!(
        batches <= storage_kit::ns::QUEUE_DEPTH,
        "{batches} batches were queued; the bound is {}",
        storage_kit::ns::QUEUE_DEPTH
    );
    fs::write(tmp.path().join("later"), b"x").unwrap();
    let next = w.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        cursor.observe(&next),
        "batches were dropped, so the next one must show a gap: {next:?}"
    );
    drop(w);
    assert_eq!(settle(0), 0);
}
