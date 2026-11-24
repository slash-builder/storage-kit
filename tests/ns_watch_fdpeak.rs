//! A recursive scan must hold a bounded number of file descriptors however many directories wait to be visited.
//! Linux only (it counts `/proc/self/fd`), and its own binary so no other test's descriptors are in the count.
//!
//! Measured directly rather than by exhausting a limit: a scan that keeps one open handle per pending directory holds
//! about one descriptor per subdirectory at its peak, which this notices at any `ulimit`.
#![cfg(all(feature = "ns", target_os = "linux"))]

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use storage_kit::ns::{Backend, HostDir, NsPath, WatchOpts};

#[test]
fn a_recursive_scan_holds_a_handful_of_descriptors_not_one_per_directory() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..400 {
        let d = tmp.path().join(format!("d{i:04}"));
        fs::create_dir(&d).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
    }
    let dir = HostDir::open_ambient(tmp.path()).unwrap();
    let baseline = fs::read_dir("/proc/self/fd").unwrap().count();

    let peak = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let (peak, stop) = (peak.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(rd) = fs::read_dir("/proc/self/fd") {
                    peak.fetch_max(rd.count(), Ordering::Relaxed);
                }
            }
        })
    };
    let w = dir
        .watch(
            &NsPath::root(),
            WatchOpts::default()
                .interval(Duration::from_millis(10))
                .recursive(true),
        )
        .unwrap();
    // Let a good number of scans run (each one visits all 400 directories).
    std::thread::sleep(Duration::from_millis(1500));
    stop.store(true, Ordering::Relaxed);
    sampler.join().unwrap();
    drop(w);

    let peak = peak.load(Ordering::Relaxed);
    eprintln!(
        "descriptors: {baseline} before, peak {peak} during recursive scans of 400 directories"
    );
    assert!(
        peak < baseline + 40,
        "a scan of 400 directories held {peak} descriptors at once (baseline {baseline}): it keeps a handle per pending directory"
    );
}
