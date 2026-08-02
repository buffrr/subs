//! In-memory log capture for the UI.
//!
//! A tracing layer that mirrors every event into a bounded ring buffer, so the
//! Logs page can tail what would otherwise only exist on the operator's
//! terminal. Everything running in-process is captured — subs, spaced and the
//! test-rig relay all log through the same subscriber. bitcoind is a separate
//! process and writes to its own stdout, so it is not.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// How many entries to retain. This is a live tail, not a log store — old
/// entries are dropped rather than paged out.
const CAPACITY: usize = 5000;

#[derive(Clone, Serialize)]
pub struct LogEntry {
    /// Monotonic cursor so the UI can poll for "everything after N" without
    /// relying on timestamps, which collide at this volume.
    pub seq: u64,
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Bounded ring buffer of recent log events.
pub struct LogBuffer {
    entries: Mutex<VecDeque<LogEntry>>,
    next_seq: AtomicU64,
}

/// The process-wide buffer. A singleton because the subscriber it feeds is
/// one per process — threading an Arc from main() down through the server
/// setup into AppState would touch four signatures for no gain.
static BUFFER: OnceLock<Arc<LogBuffer>> = OnceLock::new();

/// Build the capture layer, initialising the global buffer.
pub fn capture_layer() -> LogCaptureLayer {
    LogCaptureLayer::new(global())
}

/// The global buffer, created on first use.
pub fn global() -> Arc<LogBuffer> {
    BUFFER.get_or_init(LogBuffer::new).clone()
}

impl LogBuffer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            next_seq: AtomicU64::new(0),
        })
    }

    fn push(&self, timestamp: String, level: String, target: String, message: String) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back(LogEntry {
            seq,
            timestamp,
            level,
            target,
            message,
        });
    }

    /// Entries with `seq >= after`, oldest first, capped at `limit`.
    ///
    /// Returns the newest `limit` when the caller has fallen behind, so a slow
    /// poller sees recent activity rather than a stale window.
    pub fn since(&self, after: u64, limit: usize) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        let matching: Vec<&LogEntry> = entries.iter().filter(|e| e.seq >= after).collect();
        let start = matching.len().saturating_sub(limit);
        matching[start..].iter().map(|e| (*e).clone()).collect()
    }

    /// Cursor one past the newest entry.
    pub fn head(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed)
    }
}

/// Collects the `message` field plus any structured fields into one string.
///
/// Crates that log through the `log` crate (subs_core does) arrive bridged by
/// tracing-log: the event target is literally "log" and the real one is in a
/// `log.target` field. Capture that separately so the UI shows
/// `subs_core::app` rather than `log` with the target inlined in the text.
struct MessageVisitor {
    message: String,
    log_target: Option<String>,
}

impl MessageVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            log_target: None,
        }
    }

    /// The bridge also emits log.module_path / log.file / log.line, which are
    /// noise next to the message.
    fn is_bridge_field(name: &str) -> bool {
        name.starts_with("log.")
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if name == "message" {
            let _ = write!(self.message, "{:?}", value);
        } else if Self::is_bridge_field(name) {
            if name == "log.target" {
                self.log_target = Some(format!("{:?}", value).trim_matches('"').to_string());
            }
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            let _ = write!(self.message, "{}={:?}", name, value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message.push_str(value);
        } else if Self::is_bridge_field(name) {
            if name == "log.target" {
                self.log_target = Some(value.to_string());
            }
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            let _ = write!(self.message, "{}={}", name, value);
        }
    }
}

/// Tracing layer that mirrors events into a [`LogBuffer`].
pub struct LogCaptureLayer {
    buffer: Arc<LogBuffer>,
}

impl LogCaptureLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for LogCaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::new();
        event.record(&mut visitor);

        let metadata = event.metadata();
        let target = visitor
            .log_target
            .unwrap_or_else(|| metadata.target().to_string());

        self.buffer.push(
            // Second precision: this is a human-facing tail, and `seq` already
            // provides exact ordering.
            chrono_like_now(),
            metadata.level().to_string(),
            target,
            visitor.message,
        );
    }
}

/// `HH:MM:SS` in UTC without pulling in a date library.
fn chrono_like_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}
