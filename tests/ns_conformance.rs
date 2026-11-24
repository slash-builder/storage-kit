//! The conformance suite, run from outside the crate against every backend (needs the `conformance` feature).
#![cfg(feature = "conformance")]

use std::sync::Arc;

use storage_kit::ns::conformance::{run, ViaNamespace};
use storage_kit::ns::{Access, HostDir, Memory, MemoryOptions, Namespace, NsPath};

#[test]
fn memory_host_dir_and_a_two_mount_namespace_pass_the_same_cases() {
    let tmp = tempfile::tempdir().unwrap();

    let memory = run("memory", &Memory::new());
    let host = run("host-dir", &HostDir::open_ambient(tmp.path()).unwrap());

    let host2 = tempfile::tempdir().unwrap();
    let ns = Namespace::builder()
        .mount(
            NsPath::parse("/mem").unwrap(),
            Arc::new(Memory::new()),
            Access::ReadWrite,
        )
        .mount(
            NsPath::parse("/host").unwrap(),
            Arc::new(HostDir::open_ambient(host2.path()).unwrap()),
            Access::ReadWrite,
        )
        .build()
        .unwrap();
    let via_mem = run(
        "ns:/mem",
        &ViaNamespace::new(ns.clone(), NsPath::parse("/mem").unwrap()).unwrap(),
    );
    let via_host = run(
        "ns:/host",
        &ViaNamespace::new(ns, NsPath::parse("/host").unwrap()).unwrap(),
    );

    let frozen = Memory::with_options(MemoryOptions::default().writable(false));
    let read_only = run("memory(read-only)", &frozen);
    let limited = run(
        "memory(no atomic replace, no watch)",
        &Memory::with_options(MemoryOptions::default().atomic_replace(false).watch(false)),
    );

    for report in [&memory, &host, &via_mem, &via_host, &read_only, &limited] {
        println!("{report}");
        report.assert_ok();
        assert!(!report.passed.is_empty());
    }
    // The same case names ran everywhere a backend declares the capability.
    assert_eq!(
        memory.passed.len() + memory.skipped.len(),
        host.passed.len() + host.skipped.len()
    );
    assert!(
        host.skipped
            .iter()
            .any(|(c, _)| c == "if_version_is_exact_under_contention"),
        "HostDir declares inexact versions"
    );
    assert!(memory
        .passed
        .iter()
        .any(|c| c == "if_version_is_exact_under_contention"));
}
