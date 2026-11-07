//! What the daemon makes of its Babel router's reports of conflicts over prefixes (see
//! [Duplicate addresses](crate::babel::State#duplicate-addresses)): it logs them, backing off
//! exponentially while one goes on, and keeps those that go on for `cynet show`.

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

use gotatun::x25519::PublicKey;
use ipnet::IpNet;

use crate::{babel::ConflictAlertKind, config::encode_key};

/// How long after logging a conflict it is logged again at first, if it goes on. Each time, the
/// wait doubles, up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_mins(1);

/// The longest wait between two lines about a conflict that goes on.
const MAX_BACKOFF: Duration = Duration::from_hours(1);

/// How a node knows of a conflict.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Seen {
    /// It rejects the neighbour's updates, as the neighbour's route leads to another origin: the
    /// routes from the two origins meet here.
    Directly,
    /// The neighbour's alerts tell it of a node further on that rejects updates: the routes meet
    /// beyond the neighbour.
    Learnt,
}

/// What a conflict is: a prefix, how this node knows of it, and the neighbour it came from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConflictKey {
    /// The prefix in conflict.
    pub prefix: IpNet,
    /// How this node knows of it.
    pub seen: Seen,
    /// The neighbour that the rejected updates or the alerts came from.
    pub from: PublicKey,
}

impl ConflictKey {
    /// Says how this node knows of the conflict, with the routes meeting `hops` away, naming the
    /// neighbour as `from`.
    pub fn describe(&self, hops: u8, from: &str) -> String {
        match self.seen {
            Seen::Directly => format!("directly with {from}"),
            Seen::Learnt => {
                let plural = if hops == 1 { "" } else { "s" };
                format!("{hops} hop{plural} away via {from}")
            }
        }
    }

    /// Names the conflict in a sentence, with the neighbour's whole key, for the log.
    fn sentence(&self, hops: u8) -> String {
        let from = encode_key(self.from.as_bytes());
        format!(
            "conflict over {}, {}",
            self.prefix,
            self.describe(hops, &from)
        )
    }
}

/// A conflict that goes on, as `cynet show` lists it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ongoing {
    /// What it is.
    pub key: ConflictKey,
    /// How many hops away the routes meet, at the nearest seen while it goes on: 0 if this node
    /// knows of it directly.
    pub hops: u8,
    /// When its first report came.
    pub since: Instant,
}

/// A line to log about a conflict, with how many hops away the routes meet, at the nearest seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLine {
    /// The first report of a conflict.
    Started {
        /// What it is.
        key: ConflictKey,
        /// How many hops away the routes meet.
        hops: u8,
    },
    /// More reports of a conflict that goes on.
    Continues {
        /// What it is.
        key: ConflictKey,
        /// How many hops away the routes meet.
        hops: u8,
        /// How many reports came since the last line.
        reports: u64,
        /// How long since the last line.
        over: Duration,
    },
    /// A conflict with no report for the expiry time, which no longer seems to go on.
    Ended {
        /// What it was.
        key: ConflictKey,
        /// How many hops away the routes met.
        hops: u8,
    },
}

impl LogLine {
    /// Logs the line: a warning while a conflict goes on, and information once it ends.
    pub fn log(&self) {
        match self {
            Self::Started { .. } | Self::Continues { .. } => tracing::warn!("{self}"),
            Self::Ended { .. } => tracing::info!("{self}"),
        }
    }
}

impl fmt::Display for LogLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Started { key, hops } => write!(f, "{}", key.sentence(hops)),
            Self::Continues {
                key,
                hops,
                reports,
                over,
            } => write!(
                f,
                "{}: {reports} more reports in {} s",
                key.sentence(hops),
                over.as_secs()
            ),
            Self::Ended { key, hops } => write!(f, "{}: no longer reported", key.sentence(hops)),
        }
    }
}

struct Entry {
    /// How many hops away the routes meet, at the nearest reported.
    hops: u8,
    /// When its first report came.
    first: Instant,
    /// When its last report came.
    last: Instant,
    /// When it was last logged.
    logged: Instant,
    /// How many reports came since then.
    unlogged: u64,
    /// How long after `logged` it may be logged again.
    backoff: Duration,
}

/// The conflicts reported, and what has been logged of them. Like the rest of the daemon's
/// helpers, it reads no clock, and is given the time instead.
pub struct ConflictLog {
    /// How long after its last report a conflict is over.
    expiry: Duration,
    entries: HashMap<ConflictKey, Entry>,
}

impl ConflictLog {
    /// Creates an empty log, in which a conflict is over `expiry` after its last report. That
    /// needs to be longer than the gaps between reports, even with one lost.
    pub fn new(expiry: Duration) -> Self {
        Self {
            expiry,
            entries: HashMap::new(),
        }
    }

    /// Records a report of a conflict over `prefix` from neighbour `from` at `now`, returning a
    /// line to log, if any: for the first report of a conflict, and then for those of each
    /// backoff, which doubles every time.
    pub fn record(
        &mut self,
        prefix: IpNet,
        kind: ConflictAlertKind,
        from: PublicKey,
        now: Instant,
    ) -> Option<LogLine> {
        let (seen, hops) = match kind {
            ConflictAlertKind::Rejected => (Seen::Directly, 0),
            ConflictAlertKind::Alerted { hops } => (Seen::Learnt, hops.get()),
        };
        let key = ConflictKey { prefix, seen, from };

        let Some(entry) = self.entries.get_mut(&key) else {
            self.entries.insert(
                key,
                Entry {
                    hops,
                    first: now,
                    last: now,
                    logged: now,
                    unlogged: 0,
                    backoff: FIRST_BACKOFF,
                },
            );
            return Some(LogLine::Started { key, hops });
        };

        entry.hops = entry.hops.min(hops);
        entry.last = now;
        entry.unlogged += 1;
        let over = now.saturating_duration_since(entry.logged);
        if over < entry.backoff {
            return None;
        }
        let reports = entry.unlogged;
        entry.logged = now;
        entry.unlogged = 0;
        entry.backoff = (entry.backoff * 2).min(MAX_BACKOFF);
        Some(LogLine::Continues {
            key,
            hops: entry.hops,
            reports,
            over,
        })
    }

    /// Ends the conflicts with no report for the expiry time by `now`, returning a line for
    /// each, in order. A later report of one starts it again.
    pub fn expire(&mut self, now: Instant) -> Vec<LogLine> {
        let expiry = self.expiry;
        let mut ended: Vec<_> = (self.entries)
            .extract_if(|_, entry| now.saturating_duration_since(entry.last) >= expiry)
            .map(|(key, entry)| (key, entry.hops))
            .collect();
        ended.sort_unstable_by_key(|&(key, hops)| order(&key, hops));
        (ended.into_iter())
            .map(|(key, hops)| LogLine::Ended { key, hops })
            .collect()
    }

    /// Returns the conflicts that go on at `now`: in order of prefix, then those this node knows
    /// of directly before the others, then by distance, nearest first, and then by neighbour.
    pub fn ongoing(&self, now: Instant) -> Vec<Ongoing> {
        let mut ongoing: Vec<_> = (self.entries.iter())
            .filter(|(_, entry)| now.saturating_duration_since(entry.last) < self.expiry)
            .map(|(&key, entry)| Ongoing {
                key,
                hops: entry.hops,
                since: entry.first,
            })
            .collect();
        ongoing.sort_unstable_by_key(|ongoing| order(&ongoing.key, ongoing.hops));
        ongoing
    }
}

/// Returns what conflicts are ordered by.
fn order(key: &ConflictKey, hops: u8) -> (IpNet, Seen, u8, [u8; 32]) {
    (key.prefix, key.seen, hops, *key.from.as_bytes())
}
