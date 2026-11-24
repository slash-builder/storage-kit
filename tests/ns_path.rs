//! The portable name grammar, through `NsPath::parse` and `join`. Each refusal is checked for its *named* reason.
#![cfg(feature = "ns")]

use storage_kit::ns::{
    NsErrorKind, NsPath, PathReason, MAX_NAME_BYTES, MAX_PATH_BYTES, TEMP_PREFIX,
};

fn reason(input: &str) -> Option<PathReason> {
    match NsPath::parse(input) {
        Ok(_) => None,
        Err(e) => match e.kind() {
            NsErrorKind::InvalidPath(r) => Some(r),
            other => panic!("{input:?}: expected InvalidPath, got {other:?}"),
        },
    }
}

#[test]
fn dot_dot_is_refused_by_name() {
    for p in ["/..", "/a/..", "/../a", "/a/../b", "/a/b/.."] {
        assert_eq!(reason(p), Some(PathReason::DotDotComponent), "{p}");
    }
}

#[test]
fn dot_is_refused_by_name() {
    for p in ["/.", "/a/./b", "/./a"] {
        assert_eq!(reason(p), Some(PathReason::DotComponent), "{p}");
    }
}

#[test]
fn absolute_looking_host_input_is_refused() {
    // Not a namespace path: relative, a Windows drive, a UNC path, a bare name, the empty string.
    for p in [
        "a/b",
        "a",
        "",
        "C:\\Windows\\System32",
        "C:/Windows",
        "\\\\server\\share",
        "~/x",
        "./a",
    ] {
        assert_eq!(reason(p), Some(PathReason::NotAbsolute), "{p:?}");
    }
    // And the same shapes once they do start with '/'.
    assert_eq!(reason("/C:/Windows"), Some(PathReason::ForbiddenCharacter));
    assert_eq!(reason("/a\\b"), Some(PathReason::ForbiddenCharacter));
}

#[test]
fn empty_components_are_refused() {
    for p in ["//", "//a", "/a//b", "/a/"] {
        assert_eq!(reason(p), Some(PathReason::EmptyComponent), "{p}");
    }
}

#[test]
fn forbidden_and_control_characters_are_refused() {
    for c in ['\\', ':', '<', '>', '"', '|', '?', '*'] {
        assert_eq!(
            reason(&format!("/a{c}b")),
            Some(PathReason::ForbiddenCharacter),
            "{c:?}"
        );
    }
    for c in ['\0', '\n', '\t', '\r', '\u{1b}', '\u{7f}', '\u{85}'] {
        assert_eq!(
            reason(&format!("/a{c}b")),
            Some(PathReason::ControlCharacter),
            "{c:?}"
        );
    }
}

#[test]
fn trailing_dot_or_space_is_refused() {
    for p in ["/a.", "/a ", "/a/b.", "/a/b ", "/...", "/ "] {
        assert_eq!(reason(p), Some(PathReason::TrailingDotOrSpace), "{p:?}");
    }
    // A dot or space inside, or a leading dot, is fine.
    for p in ["/.hidden", "/a b", "/a.b", "/ a", "/.a.b"] {
        assert_eq!(reason(p), None, "{p:?}");
    }
}

#[test]
fn every_windows_reserved_name_is_refused_in_every_form() {
    let mut names: Vec<String> = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for n in 1..=9 {
        names.push(format!("COM{n}"));
        names.push(format!("LPT{n}"));
    }
    for sup in ['\u{b9}', '\u{b2}', '\u{b3}'] {
        names.push(format!("COM{sup}"));
        names.push(format!("LPT{sup}"));
    }
    assert!(
        names.len() >= 4 + 18,
        "the list under test must be complete"
    );
    for name in names {
        for variant in [
            name.clone(),
            name.to_lowercase(),
            // mixed case
            name.chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_lowercase()
                    } else {
                        c
                    }
                })
                .collect(),
            format!("{name}.txt"),
            format!("{}.TAR.GZ", name.to_lowercase()),
            format!("{name} .txt"),
        ] {
            assert_eq!(
                reason(&format!("/{variant}")),
                Some(PathReason::ReservedName),
                "{variant:?}"
            );
            assert_eq!(
                reason(&format!("/dir/{variant}")),
                Some(PathReason::ReservedName),
                "{variant:?} nested"
            );
        }
    }
    // Close neighbours are legal.
    for ok in [
        "COM",
        "COM0",
        "COM10",
        "LPT0",
        "CONSOLE",
        "NULL",
        "AUXILIARY",
        "my.con",
        "xcon.txt",
        "PRN2",
    ] {
        assert_eq!(reason(&format!("/{ok}")), None, "{ok}");
    }
}

#[test]
fn non_nfc_names_are_refused_not_normalised() {
    let nfd = "e\u{301}.txt"; // e + combining acute
    let nfc = "\u{e9}.txt";
    assert_eq!(reason(&format!("/{nfd}")), Some(PathReason::NotNfc));
    assert_eq!(reason(&format!("/{nfc}")), None);
    // The NFC form is kept verbatim, never rewritten.
    assert_eq!(
        NsPath::parse(&format!("/{nfc}")).unwrap().as_str(),
        format!("/{nfc}")
    );
    // Hangul jamo sequence is the classic non-NFC case.
    assert_eq!(
        reason("/\u{1112}\u{1161}\u{11ab}"),
        Some(PathReason::NotNfc)
    );
    assert_eq!(reason("/\u{d55c}"), None);
}

#[test]
fn name_and_path_length_limits() {
    let ok = "a".repeat(MAX_NAME_BYTES);
    assert_eq!(reason(&format!("/{ok}")), None);
    assert_eq!(reason(&format!("/{ok}a")), Some(PathReason::NameTooLong));
    // The limit is in bytes, not characters: 128 two-byte characters is 256 bytes.
    assert_eq!(
        reason(&format!("/{}", "\u{e9}".repeat(128))),
        Some(PathReason::NameTooLong)
    );
    assert_eq!(reason(&format!("/{}", "\u{e9}".repeat(127))), None);

    // 4096 bytes of path: 16 components of 255 bytes plus separators is 4096 exactly.
    let comp = "b".repeat(255);
    let at_limit = format!("/{}", vec![comp.as_str(); 16].join("/"));
    assert_eq!(at_limit.len(), 16 * 256);
    assert_eq!(at_limit.len(), MAX_PATH_BYTES);
    assert_eq!(reason(&at_limit), None);
    assert_eq!(
        reason(&format!("{at_limit}/x")),
        Some(PathReason::PathTooLong)
    );

    // `join` enforces the same limit.
    let base = NsPath::parse(&at_limit).unwrap();
    let err = base.join("x").unwrap_err();
    assert_eq!(
        err.kind(),
        NsErrorKind::InvalidPath(PathReason::PathTooLong)
    );
}

#[test]
fn the_temporary_prefix_is_reserved() {
    assert_eq!(
        reason(&format!("/{TEMP_PREFIX}1")),
        Some(PathReason::ReservedPrefix)
    );
    assert_eq!(
        reason(&format!("/a/{TEMP_PREFIX}")),
        Some(PathReason::ReservedPrefix)
    );
    assert_eq!(reason("/.skns"), None);
    assert_eq!(
        reason(&format!("/x{TEMP_PREFIX}")),
        None,
        "only a prefix is reserved"
    );
}

#[test]
fn accepted_paths_round_trip() {
    for p in [
        "/",
        "/a",
        "/a/b/c",
        "/config/apps.toml",
        "/with space/ok",
        "/\u{65e5}\u{672c}\u{8a9e}",
        "/a-b_c.d~e",
    ] {
        let parsed = NsPath::parse(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        assert_eq!(parsed.as_str(), p);
        assert_eq!(parsed.to_string(), p);
    }
}

#[test]
fn errors_do_not_echo_the_input() {
    let secret = "/very/secret/host/path/..";
    let e = NsPath::parse(secret).unwrap_err();
    assert!(!format!("{e}").contains("secret"));
    assert!(!format!("{e:?}").contains("secret"));
}
