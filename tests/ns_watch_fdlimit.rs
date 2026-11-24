//! A recursive watch of a wide tree under a low file-descriptor limit. Its own test binary with one test, because it
//! lowers the process-wide `RLIMIT_NOFILE`.
//!
//! The scan used to hold an open directory handle for every directory still waiting to be visited, so a tree with more
//! directories than the limit exhausted descriptors, and the entries it could not open were silently omitted. It now
//! keeps *paths* and opens one directory at a time. (`ns_watch_fdpeak.rs` pins the same property without depending on
//! the limit being hit: it measures how many descriptors a scan holds at once.)
#![cfg(all(feature = "ns", unix))]

use std::fs;
use std::time::{Duration, Instant};

use storage_kit::ns::{Backend, HostDir, NsPath, WatchOpts};

const DIRS: usize = 700;
const LIMIT: libc::rlim_t = 64;

fn lower_descriptor_limit() {
    // SAFETY: plain libc calls on a local, correctly-sized struct. (The crate's `forbid(unsafe_code)` covers `ns`, not
    // this test binary.)
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        assert!(
            lim.rlim_max >= LIMIT,
            "the hard limit is already below the test's"
        );
        lim.rlim_cur = LIMIT;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
    }
}

#[test]
fn a_recursive_watch_of_a_tree_wider_than_the_descriptor_limit_is_complete() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..DIRS {
        let d = tmp.path().join(format!("d{i:04}"));
        fs::create_dir(&d).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
    }
    let dir = HostDir::open_ambient(tmp.path()).unwrap();
    lower_descriptor_limit();

    let w = dir
        .watch(
            &NsPath::root(),
            WatchOpts::default()
                .interval(Duration::from_millis(20))
                .max_entries(10_000)
                .recursive(true),
        )
        .expect("the baseline scan must complete under a low descriptor limit");

    // And every directory is really being watched, not just the first few the descriptor limit let a handle-per-pending
    // -directory scan open (which directories those were is arbitrary, so touch them all).
    for i in 0..DIRS {
        fs::write(tmp.path().join(format!("d{i:04}/new")), b"y").unwrap();
    }
    let mut missing: std::collections::BTreeSet<String> =
        (0..DIRS).map(|i| format!("/d{i:04}/new")).collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !missing.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        let b = w.recv_timeout(left).unwrap_or_else(|_| {
            panic!(
                "{} directories were never reported, e.g. {:?}",
                missing.len(),
                missing.iter().next()
            )
        });
        assert!(!b.rescan, "no rescan expected");
        for c in &b.changed {
            missing.remove(c.as_str());
        }
    }
}
