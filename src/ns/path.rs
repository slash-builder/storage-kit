//! [`NsPath`]: a validated namespace path, and the portable name grammar every backend enforces through it.
//!
//! The grammar is one deliberately strict subset of what Linux, macOS and Windows each allow. The point is that a name
//! accepted here is legal, unambiguous and round-trippable on every platform, so "it worked on my Linux box and then
//! collided on the Mac" is refused at the namespace, not discovered at a backend. It is intentionally stricter than any
//! single OS: the rules below are not "what the host would accept".
//!
//! A path is absolute (`/a/b`), `/`-separated, and the root is `/`. There is no relative form, no `.`/`..`, no `//`, no
//! trailing `/`. A name is refused (never silently repaired) when it:
//!
//! - is empty, `.` or `..`;
//! - is not already in Unicode **NFC** (the namespace never normalises, because normalising silently changes which
//!   entry a caller addressed);
//! - contains a control character (`char::is_control`, so C0, DEL and C1), `\`, `:` or any of `<>"|?*`;
//! - ends in a dot or a space (Windows strips them, so the name would not round-trip);
//! - is a Windows reserved device name (`CON PRN AUX NUL COM1-9 LPT1-9`, plus `CONIN$`, `CONOUT$` and the superscript
//!   digit forms), case-insensitively, with or without an extension (`con.txt` is as reserved as `CON`);
//! - is longer than [`MAX_NAME_BYTES`] (255) UTF-8 bytes, or the whole path is longer than [`MAX_PATH_BYTES`] (4096);
//! - begins with [`TEMP_PREFIX`], which `HostDir` reserves for its atomic-replace temporary files.
//!
//! Two names that differ only by case are **distinct paths** but cannot *coexist* in one directory: creating the second
//! is refused with `CaseCollision` (see [`case_fold_key`]), on every backend, even a case-sensitive one.

use std::fmt;
use std::str::FromStr;

use super::error::{NsError, NsErrorKind};

/// Longest single path component, in UTF-8 bytes. Matches the limit of ext4, APFS, NTFS and most others.
pub const MAX_NAME_BYTES: usize = 255;

/// Longest whole path, in UTF-8 bytes, separators included.
pub const MAX_PATH_BYTES: usize = 4096;

/// The prefix `HostDir` gives its temporary files while it does an atomic replace.
///
/// Reserved so a temp file can never collide with, or be mistaken for, a name a caller created: the grammar refuses it
/// ([`PathReason::ReservedPrefix`]) and `HostDir`'s listing hides anything that starts with it. A temp file left behind
/// by a crash is therefore invisible to the namespace; it can be removed from the host directory by hand.
pub const TEMP_PREFIX: &str = ".skns-tmp-";

/// Why a path or name was refused. Carried by [`NsErrorKind::InvalidPath`].
///
/// Deliberately carries no part of the offending input: the input may be hostile or may be a host path, and an error
/// message is not the place to echo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathReason {
    /// The path does not start with `/`. Namespace paths are always absolute; a host path such as `C:\x` or `a/b` is not
    /// one.
    NotAbsolute,
    /// An empty component: `//`, or a trailing `/`.
    EmptyComponent,
    /// A `.` component.
    DotComponent,
    /// A `..` component. The namespace has no parent traversal; ask for the parent's path.
    DotDotComponent,
    /// A control character (C0, DEL or C1).
    ControlCharacter,
    /// One of `\ : < > " | ? *`.
    ForbiddenCharacter,
    /// The name is not in Unicode NFC. Normalise it before asking.
    NotNfc,
    /// The name ends in `.` or a space.
    TrailingDotOrSpace,
    /// A Windows reserved device name (`CON`, `NUL`, `COM1`, ...), with or without an extension.
    ReservedName,
    /// The name starts with [`TEMP_PREFIX`].
    ReservedPrefix,
    /// A component longer than [`MAX_NAME_BYTES`].
    NameTooLong,
    /// A path longer than [`MAX_PATH_BYTES`].
    PathTooLong,
}

impl PathReason {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            PathReason::NotAbsolute => {
                "a namespace path starts with '/' (a host path or a relative path is not one)"
            }
            PathReason::EmptyComponent => "an empty component ('//' or a trailing '/')",
            PathReason::DotComponent => "a '.' component",
            PathReason::DotDotComponent => {
                "a '..' component (there is no parent traversal; give the parent's path)"
            }
            PathReason::ControlCharacter => "a control character in a name",
            PathReason::ForbiddenCharacter => {
                "a character that is not portable in a name (one of \\ : < > \" | ? *)"
            }
            PathReason::NotNfc => "a name that is not Unicode NFC (normalise it first)",
            PathReason::TrailingDotOrSpace => "a name ending in '.' or a space",
            PathReason::ReservedName => "a Windows reserved device name (CON, NUL, COM1, ...)",
            PathReason::ReservedPrefix => "a name starting with the reserved temporary prefix",
            PathReason::NameTooLong => "a name longer than 255 bytes",
            PathReason::PathTooLong => "a path longer than 4096 bytes",
        }
    }
}

/// A validated namespace path: absolute, `/`-separated, every component inside the portable name grammar. See the
/// [module docs](self) for the grammar.
///
/// Holding an `NsPath` is proof the grammar was checked, so a backend does not re-parse strings and cannot be handed a
/// `..` or a host path by construction.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NsPath(String);

impl NsPath {
    /// The root, `/`.
    pub fn root() -> Self {
        NsPath("/".to_string())
    }

    /// Validate and wrap a namespace path.
    ///
    /// ```
    /// # #[cfg(feature = "ns")] {
    /// use storage_kit::ns::{NsPath, NsErrorKind, PathReason};
    /// assert!(NsPath::parse("/config/apps.toml").is_ok());
    /// let err = NsPath::parse("/config/../etc").unwrap_err();
    /// assert_eq!(err.kind(), NsErrorKind::InvalidPath(PathReason::DotDotComponent));
    /// # }
    /// ```
    pub fn parse(input: &str) -> Result<Self, NsError> {
        let invalid = |r| NsError::new(NsErrorKind::InvalidPath(r));
        if input.len() > MAX_PATH_BYTES {
            return Err(invalid(PathReason::PathTooLong));
        }
        let Some(rest) = input.strip_prefix('/') else {
            return Err(invalid(PathReason::NotAbsolute));
        };
        if rest.is_empty() {
            return Ok(Self::root());
        }
        for name in rest.split('/') {
            validate_name(name).map_err(invalid)?;
        }
        Ok(NsPath(input.to_string()))
    }

    /// The path as a string, e.g. `/a/b`. The root is `/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for `/`.
    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// Number of components; the root has 0.
    pub fn depth(&self) -> usize {
        self.components().count()
    }

    /// Append a **relative** path (`name` or `a/b`), validating every component.
    ///
    /// A leading `/` is refused (it reads as an empty first component): to combine two absolute namespace paths use
    /// [`NsPath::rebase`].
    pub fn join(&self, relative: &str) -> Result<NsPath, NsError> {
        let invalid = |r| NsError::new(NsErrorKind::InvalidPath(r));
        if relative.is_empty() {
            return Err(invalid(PathReason::EmptyComponent));
        }
        for name in relative.split('/') {
            validate_name(name).map_err(invalid)?;
        }
        let mut s = if self.is_root() {
            String::new()
        } else {
            self.0.clone()
        };
        s.push('/');
        s.push_str(relative);
        if s.len() > MAX_PATH_BYTES {
            return Err(invalid(PathReason::PathTooLong));
        }
        Ok(NsPath(s))
    }

    /// Append one component that the caller has already validated (a name read back from a backend that enforces the
    /// grammar). `None` if the result would exceed [`MAX_PATH_BYTES`].
    pub(crate) fn child(&self, name: &str) -> Option<NsPath> {
        debug_assert!(validate_name(name).is_ok());
        let mut s = if self.is_root() {
            String::new()
        } else {
            self.0.clone()
        };
        s.push('/');
        s.push_str(name);
        (s.len() <= MAX_PATH_BYTES).then_some(NsPath(s))
    }

    /// The parent directory, or `None` for the root.
    pub fn parent(&self) -> Option<NsPath> {
        if self.is_root() {
            return None;
        }
        let idx = self.0.rfind('/')?;
        Some(if idx == 0 {
            Self::root()
        } else {
            NsPath(self.0[..idx].to_string())
        })
    }

    /// The last component, or `None` for the root.
    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    /// The components, in order. Empty for the root.
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> + Clone {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// True if `base` is this path or one of its ancestors, compared by whole components (`/ab` does not start with
    /// `/a`). Every path starts with the root.
    pub fn starts_with(&self, base: &NsPath) -> bool {
        if base.is_root() || self == base {
            return true;
        }
        self.0
            .strip_prefix(base.0.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }

    /// The path below `base`, re-rooted at `/`: `/a/b/c` stripped of `/a` is `/b/c`; stripped of itself it is `/`.
    /// `None` if `base` is not a prefix. This is how a mount-relative path is derived.
    pub fn strip_prefix(&self, base: &NsPath) -> Option<NsPath> {
        if !self.starts_with(base) {
            return None;
        }
        if base.is_root() {
            return Some(self.clone());
        }
        let rest = &self.0[base.0.len()..];
        Some(if rest.is_empty() {
            Self::root()
        } else {
            NsPath(rest.to_string())
        })
    }

    /// The inverse of [`NsPath::strip_prefix`]: place this (mount-relative, `/`-rooted) path under `base`.
    pub fn rebase(&self, base: &NsPath) -> Result<NsPath, NsError> {
        if base.is_root() {
            return Ok(self.clone());
        }
        if self.is_root() {
            return Ok(base.clone());
        }
        let s = format!("{}{}", base.0, self.0);
        if s.len() > MAX_PATH_BYTES {
            return Err(NsError::new(NsErrorKind::InvalidPath(
                PathReason::PathTooLong,
            )));
        }
        Ok(NsPath(s))
    }
}

impl PartialOrd for NsPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Component-wise order, so a directory sorts before its contents and `/a/b` sorts before `/a-b` (a plain string
/// comparison would put `/a-b` first because `-` sorts before `/`).
impl Ord for NsPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.components().cmp(other.components())
    }
}

impl fmt::Display for NsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for NsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NsPath({:?})", self.0)
    }
}

impl FromStr for NsPath {
    type Err = NsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NsPath::parse(s)
    }
}

const FORBIDDEN: &[char] = &['\\', ':', '<', '>', '"', '|', '?', '*'];

/// Check one component against the portable grammar. This is the single validator: `NsPath` uses it, and a backend that
/// reads names back from a host directory uses it to decide which entries are addressable at all.
pub fn validate_name(name: &str) -> Result<(), PathReason> {
    if name.is_empty() {
        return Err(PathReason::EmptyComponent);
    }
    if name == "." {
        return Err(PathReason::DotComponent);
    }
    if name == ".." {
        return Err(PathReason::DotDotComponent);
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(PathReason::NameTooLong);
    }
    for c in name.chars() {
        if c.is_control() {
            return Err(PathReason::ControlCharacter);
        }
        if FORBIDDEN.contains(&c) {
            return Err(PathReason::ForbiddenCharacter);
        }
    }
    if !unicode_normalization::is_nfc(name) {
        return Err(PathReason::NotNfc);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(PathReason::TrailingDotOrSpace);
    }
    if is_reserved_device_name(name) {
        return Err(PathReason::ReservedName);
    }
    if name.starts_with(TEMP_PREFIX) {
        return Err(PathReason::ReservedPrefix);
    }
    Ok(())
}

/// Windows treats the part of a name before its first dot as the device name, ignoring trailing spaces in that part.
fn is_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let up = stem.to_uppercase();
    match up.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let digit = |rest: &str| {
                matches!(
                    rest,
                    "1" | "2"
                        | "3"
                        | "4"
                        | "5"
                        | "6"
                        | "7"
                        | "8"
                        | "9"
                        | "\u{b9}"
                        | "\u{b2}"
                        | "\u{b3}"
                )
            };
            up.strip_prefix("COM")
                .or_else(|| up.strip_prefix("LPT"))
                .is_some_and(digit)
        }
    }
}

/// The key under which two names count as "the same name differing only by case".
///
/// An approximation of full Unicode case folding (upper-case then lower-case, so `ß` meets `SS`). It is intentionally a
/// bit **stricter** than most volumes: a false collision costs a caller a rename, a missed one costs a file silently
/// overwriting another on macOS or Windows. It does not model locale rules (Turkish dotless i).
pub fn case_fold_key(name: &str) -> String {
    name.to_uppercase().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_basics() {
        let r = NsPath::root();
        assert!(r.is_root());
        assert_eq!(r.parent(), None);
        assert_eq!(r.file_name(), None);
        assert_eq!(r.depth(), 0);
        let p = NsPath::parse("/a/b/c").unwrap();
        assert_eq!(p.file_name(), Some("c"));
        assert_eq!(p.parent().unwrap().as_str(), "/a/b");
        assert_eq!(NsPath::parse("/a").unwrap().parent().unwrap(), r);
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b", "c"]);
    }

    #[test]
    fn prefix_ops_use_whole_components() {
        let a = NsPath::parse("/a").unwrap();
        let ab = NsPath::parse("/ab").unwrap();
        let a_b = NsPath::parse("/a/b").unwrap();
        assert!(a_b.starts_with(&a));
        assert!(!ab.starts_with(&a));
        assert!(a.starts_with(&a));
        assert!(a.starts_with(&NsPath::root()));
        assert_eq!(a_b.strip_prefix(&a).unwrap().as_str(), "/b");
        assert!(a.strip_prefix(&a).unwrap().is_root());
        assert_eq!(ab.strip_prefix(&a), None);
        assert_eq!(a_b.strip_prefix(&NsPath::root()).unwrap(), a_b);
        let b = NsPath::parse("/b").unwrap();
        assert_eq!(b.rebase(&a).unwrap().as_str(), "/a/b");
        assert_eq!(NsPath::root().rebase(&a).unwrap(), a);
    }

    #[test]
    fn order_is_by_component() {
        let mut v = [
            NsPath::parse("/a-b").unwrap(),
            NsPath::parse("/a/b").unwrap(),
            NsPath::parse("/a").unwrap(),
        ];
        v.sort();
        let s: Vec<_> = v.iter().map(NsPath::as_str).collect();
        assert_eq!(s, ["/a", "/a/b", "/a-b"]);
    }

    #[test]
    fn join_validates_each_component() {
        let a = NsPath::parse("/a").unwrap();
        assert_eq!(a.join("b/c").unwrap().as_str(), "/a/b/c");
        assert_eq!(NsPath::root().join("x").unwrap().as_str(), "/x");
        assert!(a.join("/b").is_err());
        assert!(a.join("b/../c").is_err());
        assert!(a.join("").is_err());
    }
}
