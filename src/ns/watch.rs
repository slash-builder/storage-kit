//! Watching a directory: [`Watch`], [`WatchBatch`], [`WatchOpts`], and the std-only polling engine `HostDir` uses.
//!
//! The contract, in one paragraph: a batch is **a hint to re-read, not a log**. Each batch carries an `epoch` (chosen
//! when the watch starts) and a `generation` (one more than the previous batch). **A gap in `generation`, or a
//! different `epoch`, means batches were lost, and is the same as `rescan`.** So a consumer that ignores everything but
//! "something changed, go and look" is always correct, and [`WatchCursor`] does the bookkeeping for one that wants to
//! know whether it *must* look at everything.
//!
//! Events carry **namespace paths** only. A host path never reaches the consumer.
//!
//! Watch a directory, not a file: editors replace files (write a temp, rename over), so the file's identity changes
//! and a watch on it would be watching a name that no longer exists.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{
    Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::backend::Kind;
use super::path::NsPath;

/// The default poll interval.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(250);
/// The smallest interval a poll is allowed (a smaller request is raised to this).
pub const MIN_INTERVAL: Duration = Duration::from_millis(10);
/// The default cap on paths per batch.
pub const DEFAULT_MAX_ENTRIES: usize = 1024;
/// How many undelivered batches a watch queues before it starts dropping them (which shows up as a generation gap).
/// Bounded so a consumer that stops reading cannot make the producer grow without limit.
pub const QUEUE_DEPTH: usize = 16;

/// Options for [`Backend::watch`](super::Backend::watch).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WatchOpts {
    /// Also report changes below subdirectories. Default `false`: direct children only.
    pub recursive: bool,
    /// Poll interval for polling backends. Default 250 ms; values under 10 ms are raised to 10 ms. Ignored by backends
    /// that are not polling.
    pub interval: Duration,
    /// At most this many paths in one batch. Past it the batch is `rescan: true` with an empty `changed`.
    pub max_entries: usize,
}

impl Default for WatchOpts {
    fn default() -> Self {
        WatchOpts {
            recursive: false,
            interval: DEFAULT_INTERVAL,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

impl WatchOpts {
    /// Set [`WatchOpts::recursive`].
    #[must_use]
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Set [`WatchOpts::interval`].
    #[must_use]
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set [`WatchOpts::max_entries`].
    #[must_use]
    pub fn max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    pub(crate) fn effective_interval(&self) -> Duration {
        self.interval.max(MIN_INTERVAL)
    }
}

/// One notification. See the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WatchBatch {
    /// Chosen when the watch starts. A different epoch than the last batch means the watch was restarted: rescan.
    pub epoch: u64,
    /// One more than the previous batch's. The first batch is 1. A gap means batches were dropped: rescan.
    pub generation: u64,
    /// The namespace paths that changed: deduplicated, sorted, and empty when `rescan` is set.
    pub changed: Vec<NsPath>,
    /// Events were lost or the watched directory went away or came back: re-read everything you care about.
    pub rescan: bool,
}

impl WatchBatch {
    /// Build a batch. For backend authors.
    pub fn new(epoch: u64, generation: u64, changed: Vec<NsPath>, rescan: bool) -> Self {
        WatchBatch {
            epoch,
            generation,
            changed,
            rescan,
        }
    }
}

/// Tracks `(epoch, generation)` across batches and says when a rescan is required.
///
/// ```
/// # #[cfg(feature = "ns")] {
/// use storage_kit::ns::{WatchBatch, WatchCursor};
/// let mut cursor = WatchCursor::new();
/// assert!(!cursor.observe(&WatchBatch::new(7, 1, vec![], false)));
/// assert!(!cursor.observe(&WatchBatch::new(7, 2, vec![], false)));
/// assert!(cursor.observe(&WatchBatch::new(7, 4, vec![], false)), "generation 3 was lost");
/// assert!(cursor.observe(&WatchBatch::new(8, 5, vec![], false)), "a new epoch");
/// # }
/// ```
#[derive(Debug, Default, Clone)]
pub struct WatchCursor {
    last: Option<(u64, u64)>,
}

impl WatchCursor {
    /// A cursor that has seen nothing; the first batch must be generation 1.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `batch`. Returns true if the consumer must rescan: the batch says so, the epoch changed, or the
    /// generation did not advance by exactly one (the first batch must be generation 1).
    pub fn observe(&mut self, batch: &WatchBatch) -> bool {
        let continuous = match self.last {
            None => batch.generation == 1,
            Some((epoch, generation)) => {
                epoch == batch.epoch && generation.checked_add(1) == Some(batch.generation)
            }
        };
        self.last = Some((batch.epoch, batch.generation));
        batch.rescan || !continuous
    }
}

type Mapper = Arc<dyn Fn(&NsPath) -> Option<NsPath> + Send + Sync>;

/// A running watch. Owns the receiving end of the batch channel.
///
/// **Dropping it stops the watch**, and for a backend with a worker thread, ends and joins that thread before `drop`
/// returns. Nothing keeps running after it.
pub struct Watch {
    rx: Receiver<WatchBatch>,
    mapper: Option<Mapper>,
    on_drop: Option<Box<dyn FnOnce() + Send>>,
}

impl std::fmt::Debug for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watch").finish_non_exhaustive()
    }
}

impl Watch {
    /// Build a watch from a receiver and the action that stops its producer. For backend authors: `on_drop` runs once
    /// when the `Watch` is dropped and must stop (and, for a thread, join) whatever feeds `rx`.
    pub fn new(rx: Receiver<WatchBatch>, on_drop: impl FnOnce() + Send + 'static) -> Self {
        Watch {
            rx,
            mapper: None,
            on_drop: Some(Box::new(on_drop)),
        }
    }

    /// Rewrite every path in every batch with `f` as it is received. `f` returns `None` for a path that cannot be
    /// represented; the batch is then marked `rescan` (a path was lost, so the consumer must look). The
    /// [`Namespace`](super::Namespace) uses this to turn mount-relative paths into namespace paths.
    #[must_use]
    pub fn map_paths(
        mut self,
        f: impl Fn(&NsPath) -> Option<NsPath> + Send + Sync + 'static,
    ) -> Self {
        self.mapper = Some(match self.mapper.take() {
            None => Arc::new(f),
            Some(prev) => Arc::new(move |p: &NsPath| prev(p).and_then(|q| f(&q))),
        });
        self
    }

    fn map(&self, mut batch: WatchBatch) -> WatchBatch {
        if let Some(m) = &self.mapper {
            let mut lost = false;
            let mut out: Vec<NsPath> = batch
                .changed
                .iter()
                .filter_map(|p| {
                    let mapped = m(p);
                    lost |= mapped.is_none();
                    mapped
                })
                .collect();
            out.sort();
            out.dedup();
            if lost {
                batch.rescan = true;
                out.clear();
            }
            batch.changed = out;
        }
        batch
    }

    /// Block until the next batch. `Err` means the watch's producer is gone.
    pub fn recv(&self) -> Result<WatchBatch, RecvError> {
        self.rx.recv().map(|b| self.map(b))
    }

    /// Block for at most `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<WatchBatch, RecvTimeoutError> {
        self.rx.recv_timeout(timeout).map(|b| self.map(b))
    }

    /// Return a batch if one is ready.
    pub fn try_recv(&self) -> Result<WatchBatch, TryRecvError> {
        self.rx.try_recv().map(|b| self.map(b))
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        if let Some(stop) = self.on_drop.take() {
            stop();
        }
    }
}

/// A fresh epoch: unpredictable enough that two watches (or two runs) do not share one, which is all it is for.
pub(crate) fn new_epoch() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    RandomState::new().build_hasher().finish() ^ nanos
}

/// Sort, deduplicate and cap a changed set. Past `max_entries` the result is `(empty, true)`.
pub(crate) fn finish_changed(mut changed: Vec<NsPath>, max_entries: usize) -> (Vec<NsPath>, bool) {
    changed.sort();
    changed.dedup();
    if changed.len() > max_entries {
        (Vec::new(), true)
    } else {
        (changed, false)
    }
}

/// Producer-side bookkeeping shared by the polling thread and the `Memory` backend: numbering and non-blocking send.
pub(crate) struct BatchSender {
    tx: SyncSender<WatchBatch>,
    epoch: u64,
    generation: u64,
}

impl BatchSender {
    pub(crate) fn channel() -> (BatchSender, Receiver<WatchBatch>) {
        let (tx, rx) = mpsc::sync_channel(QUEUE_DEPTH);
        (
            BatchSender {
                tx,
                epoch: new_epoch(),
                generation: 0,
            },
            rx,
        )
    }

    /// Number and send a batch. A full queue drops it but still consumes the generation number, so the consumer sees
    /// the gap. Returns false once the receiver is gone.
    pub(crate) fn send(&mut self, changed: Vec<NsPath>, rescan: bool, max_entries: usize) -> bool {
        let (changed, over) = if rescan {
            (Vec::new(), true)
        } else {
            finish_changed(changed, max_entries)
        };
        self.generation += 1;
        let batch = WatchBatch::new(self.epoch, self.generation, changed, over);
        !matches!(self.tx.try_send(batch), Err(TrySendError::Disconnected(_)))
    }
}

/// What a poll records about one entry. Equal fingerprints mean "unchanged".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    pub kind: Kind,
    pub len: u64,
    pub mtime_ns: u128,
    pub inode: u64,
}

pub(crate) type Snapshot = BTreeMap<NsPath, Fingerprint>;

/// Paths that differ between two snapshots: created, removed, or fingerprint changed.
pub(crate) fn diff(old: &Snapshot, new: &Snapshot) -> Vec<NsPath> {
    let mut out = Vec::new();
    for (p, fp) in new {
        if old.get(p) != Some(fp) {
            out.push(p.clone());
        }
    }
    for p in old.keys() {
        if !new.contains_key(p) {
            out.push(p.clone());
        }
    }
    out
}

/// Start the polling thread. `initial` is the baseline (taken synchronously by the caller, so a bad path is an error
/// from `watch()`, not a silent dead thread); `scan` returns the current snapshot, or `None` when the directory is
/// missing or unreadable.
///
/// Behaviour: a change seen on one poll is reported on that poll; any number of writes between two polls are one
/// batch; if the directory vanishes or becomes unreadable exactly one `rescan` batch is sent, the watch keeps running,
/// and another `rescan` batch is sent when it is readable again.
pub(crate) fn spawn_poller<S>(
    initial: Snapshot,
    mut scan: S,
    opts: &WatchOpts,
) -> std::io::Result<Watch>
where
    S: FnMut() -> Option<Snapshot> + Send + 'static,
{
    let interval = opts.effective_interval();
    let max_entries = opts.max_entries;
    let stop = Arc::new(AtomicBool::new(false));
    let (mut sender, rx) = BatchSender::channel();

    let thread_stop = Arc::clone(&stop);
    let handle: JoinHandle<()> =
        thread::Builder::new()
            .name("ns-watch-poll".into())
            .spawn(move || {
                let mut previous: Option<Snapshot> = Some(initial);
                loop {
                    // Sleep for one interval, but wake at once when the Watch is dropped (unpark).
                    let deadline = Instant::now() + interval;
                    loop {
                        if thread_stop.load(Ordering::Acquire) {
                            return;
                        }
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        thread::park_timeout(deadline - now);
                    }
                    let current = scan();
                    let alive = match (&previous, &current) {
                        (Some(old), Some(new)) => {
                            let changed = diff(old, new);
                            changed.is_empty() || sender.send(changed, false, max_entries)
                        }
                        (Some(_), None) | (None, Some(_)) => {
                            sender.send(Vec::new(), true, max_entries)
                        }
                        (None, None) => true,
                    };
                    if !alive {
                        return;
                    }
                    previous = current;
                }
            })?;

    let stopper = Arc::clone(&stop);
    let thread_handle = handle.thread().clone();
    Ok(Watch::new(rx, move || {
        stopper.store(true, Ordering::Release);
        thread_handle.unpark();
        let _ = handle.join();
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> NsPath {
        NsPath::parse(s).unwrap()
    }

    #[test]
    fn cursor_flags_gaps_epochs_and_rescans() {
        let mut c = WatchCursor::new();
        assert!(
            c.observe(&WatchBatch::new(1, 2, vec![], false)),
            "first batch must be generation 1"
        );
        let mut c = WatchCursor::new();
        assert!(!c.observe(&WatchBatch::new(1, 1, vec![], false)));
        assert!(c.observe(&WatchBatch::new(1, 2, vec![], true)));
        assert!(!c.observe(&WatchBatch::new(1, 3, vec![], false)));
        assert!(c.observe(&WatchBatch::new(2, 4, vec![], false)));
    }

    #[test]
    fn cap_turns_into_rescan() {
        let many: Vec<_> = (0..5).map(|i| p(&format!("/f{i}"))).collect();
        assert_eq!(finish_changed(many.clone(), 5).0.len(), 5);
        assert_eq!(finish_changed(many, 4), (Vec::new(), true));
        let dup = vec![p("/b"), p("/a"), p("/b")];
        assert_eq!(finish_changed(dup, 10).0, vec![p("/a"), p("/b")]);
    }

    #[test]
    fn queue_overflow_shows_as_a_generation_gap() {
        let (mut s, rx) = BatchSender::channel();
        for _ in 0..QUEUE_DEPTH + 3 {
            assert!(s.send(vec![p("/x")], false, 10));
        }
        let mut c = WatchCursor::new();
        let got: Vec<_> = rx.try_iter().collect();
        assert_eq!(got.len(), QUEUE_DEPTH);
        assert!(
            got.iter().all(|b| !c.observe(b)),
            "the delivered prefix is contiguous"
        );
        s.send(vec![p("/y")], false, 10);
        let last = rx.try_recv().unwrap();
        assert!(c.observe(&last), "dropped batches must surface as a gap");
    }

    #[test]
    fn dropping_the_watch_joins_the_poller_thread() {
        // The closure owns a token; once the thread has been joined the closure is gone and only our clone remains.
        let token = Arc::new(());
        let held = Arc::clone(&token);
        let watch = spawn_poller(
            Snapshot::new(),
            move || {
                let _keep = &held;
                Some(Snapshot::new())
            },
            &WatchOpts::default().interval(Duration::from_secs(30)),
        )
        .unwrap();
        assert_eq!(Arc::strong_count(&token), 2);
        let started = Instant::now();
        drop(watch);
        assert_eq!(
            Arc::strong_count(&token),
            1,
            "the poller thread (and its scan closure) must be gone"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "drop must not wait out the 30 s interval"
        );
    }

    #[test]
    fn mapper_composes_and_flags_lost_paths() {
        let (mut s, rx) = BatchSender::channel();
        let w = Watch::new(rx, || {})
            .map_paths(|p| p.rebase(&p_("/m")).ok())
            .map_paths(|p| {
                if p.as_str() == "/m/bad" {
                    None
                } else {
                    Some(p.clone())
                }
            });
        s.send(vec![p("/a")], false, 10);
        let b = w.recv().unwrap();
        assert_eq!(b.changed, vec![p("/m/a")]);
        s.send(vec![p("/a"), p("/bad")], false, 10);
        let b = w.recv().unwrap();
        assert!(b.rescan && b.changed.is_empty());
    }

    fn p_(s: &str) -> NsPath {
        p(s)
    }
}
