//! The namespace layer must stay independent of the content-addressed engine: no engine types, no engine dependencies.
//! Checked on the source, because a `use` of any of them would compile fine with the default features and silently tie
//! the layer to the engine.
#![cfg(feature = "ns")]

use std::fs;
use std::path::Path;

/// Crates the engine depends on, plus the engine's own modules. None may appear in `src/ns`.
const FORBIDDEN: &[&str] = &[
    "blake3",
    "fastcdc",
    "zstd",
    "memmap2",
    "serde",
    "tokio",
    "async_trait",
    "async-trait",
    "chrono",
    "reqwest",
    "aws_sdk",
    "aws_config",
    "thiserror",
    "hex::",
    "crate::addressing",
    "crate::backend",
    "crate::error",
    "crate::fragment",
    "crate::partition",
    "crate::store",
    "crate::StorageError",
    "PartitionStore",
    "unsafe",
];

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn ns_source_uses_nothing_from_the_engine() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ns");
    let mut files = Vec::new();
    sources(&dir, &mut files);
    assert!(
        files.len() >= 8,
        "expected the ns source files, found {files:?}"
    );
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for word in FORBIDDEN {
                // `unsafe` may be *named* in the forbid attribute and in prose; it may not be used.
                if *word == "unsafe"
                    && (line.contains("forbid(unsafe_code)") || line.trim_start().starts_with("//"))
                {
                    continue;
                }
                assert!(
                    !code.contains(word),
                    "{}:{}: `{word}` is an engine type, engine dependency, or unsafe code: {line}",
                    file.display(),
                    n + 1
                );
            }
        }
    }
}
