use std::{
    num::NonZeroU8,
    time::{Duration, Instant},
};

use gotatun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;

use super::{ConflictKey, ConflictLog, LogLine, Ongoing, Seen};
use crate::{babel::ConflictAlertKind, config::encode_key};

const EXPIRY: Duration = Duration::from_secs(56);

fn prefix() -> IpNet {
    "fd42::/64".parse().unwrap()
}

fn neighbour(n: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([n; 32]))
}

fn alerted(hops: u8) -> ConflictAlertKind {
    ConflictAlertKind::Alerted {
        hops: NonZeroU8::new(hops).unwrap(),
    }
}

fn key(n: u8, seen: Seen) -> ConflictKey {
    ConflictKey {
        prefix: prefix(),
        seen,
        from: neighbour(n),
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn a_conflict_is_logged_at_once_then_less_and_less_often() {
    let start = Instant::now();
    let mut log = ConflictLog::new(EXPIRY);
    let direct = key(1, Seen::Directly);

    // A report every 16 s, as rejections of full dumps come, for 3 hours.
    let mut lines = Vec::new();
    for i in 0..(3 * 3600 / 16) {
        let at = secs(16 * i);
        let rejected = ConflictAlertKind::Rejected;
        if let Some(line) = log.record(prefix(), rejected, neighbour(1), start + at) {
            lines.push((at, line));
        }
    }

    assert_eq!(
        lines[0],
        (
            secs(0),
            LogLine::Started {
                key: direct,
                hops: 0
            }
        )
    );
    // Then at the first report after 1, 2, 4, ... minutes, up to an hour, with the reports since.
    let continues: Vec<_> = (lines[1..].iter())
        .map(|&(at, line)| match line {
            LogLine::Continues {
                key,
                hops: 0,
                reports,
                over,
            } => {
                assert_eq!(key, direct);
                (at.as_secs(), reports, over.as_secs())
            }
            line => panic!("unexpected {line:?}"),
        })
        .collect();
    assert_eq!(
        continues,
        [
            (64, 4, 64),
            (192, 8, 128),
            (432, 15, 240),
            (912, 30, 480),
            (1872, 60, 960),
            (3792, 120, 1920),
            (7392, 225, 3600),
        ]
    );
}

#[test]
fn a_conflict_ends_with_no_report_for_the_expiry_time() {
    let start = Instant::now();
    let mut log = ConflictLog::new(EXPIRY);
    let (direct, learnt) = (key(1, Seen::Directly), key(2, Seen::Learnt));

    log.record(prefix(), ConflictAlertKind::Rejected, neighbour(1), start);
    log.record(prefix(), alerted(3), neighbour(2), start + secs(30));
    assert_eq!(log.expire(start + secs(55)), []);
    assert_eq!(
        log.ongoing(start + secs(55)),
        [
            Ongoing {
                key: direct,
                hops: 0,
                since: start
            },
            Ongoing {
                key: learnt,
                hops: 3,
                since: start + secs(30)
            },
        ]
    );

    // Once the expiry time has passed, it no longer shows, even before it is ended.
    assert_eq!(log.ongoing(start + secs(56)).len(), 1);
    assert_eq!(
        log.expire(start + secs(60)),
        [LogLine::Ended {
            key: direct,
            hops: 0
        }]
    );

    // A later report starts it again, logged at once, with its backoff from the start.
    let rejected = ConflictAlertKind::Rejected;
    assert_eq!(
        log.record(prefix(), rejected, neighbour(1), start + secs(100)),
        Some(LogLine::Started {
            key: direct,
            hops: 0
        })
    );
    assert_eq!(
        log.record(prefix(), rejected, neighbour(1), start + secs(150)),
        None
    );
    assert!(matches!(
        log.record(prefix(), rejected, neighbour(1), start + secs(160)),
        Some(LogLine::Continues { reports: 2, .. })
    ));
    assert_eq!(log.ongoing(start + secs(160))[0].since, start + secs(100));
}

#[test]
fn the_nearest_distance_reported_is_kept() {
    let start = Instant::now();
    let mut log = ConflictLog::new(EXPIRY);
    let learnt = key(1, Seen::Learnt);

    // Alerts from one neighbour, from nodes at several distances behind it, are one conflict.
    assert_eq!(
        log.record(prefix(), alerted(4), neighbour(1), start),
        Some(LogLine::Started {
            key: learnt,
            hops: 4
        })
    );
    log.record(prefix(), alerted(2), neighbour(1), start + secs(10));
    log.record(prefix(), alerted(5), neighbour(1), start + secs(20));
    assert_eq!(log.ongoing(start + secs(20))[0].hops, 2);
    assert!(matches!(
        log.record(prefix(), alerted(3), neighbour(1), start + secs(60)),
        Some(LogLine::Continues { hops: 2, .. })
    ));
}

#[test]
fn conflicts_known_directly_come_first_then_the_nearest() {
    let start = Instant::now();
    let mut log = ConflictLog::new(EXPIRY);
    log.record(prefix(), alerted(1), neighbour(4), start);
    log.record(prefix(), alerted(3), neighbour(2), start);
    log.record(prefix(), ConflictAlertKind::Rejected, neighbour(3), start);
    let q: IpNet = "10.42.0.9/32".parse().unwrap();
    log.record(q, alerted(7), neighbour(1), start);

    let ongoing: Vec<_> = (log.ongoing(start).into_iter())
        .map(|o| (o.key.prefix, o.key.seen, o.hops, o.key.from))
        .collect();
    assert_eq!(
        ongoing,
        [
            (q, Seen::Learnt, 7, neighbour(1)),
            (prefix(), Seen::Directly, 0, neighbour(3)),
            (prefix(), Seen::Learnt, 1, neighbour(4)),
            (prefix(), Seen::Learnt, 3, neighbour(2)),
        ]
    );
}

#[test]
fn lines_say_what_goes_on() {
    let from = encode_key(neighbour(1).as_bytes());
    let direct = key(1, Seen::Directly);
    let learnt = key(1, Seen::Learnt);
    assert_eq!(
        LogLine::Started {
            key: direct,
            hops: 0
        }
        .to_string(),
        format!("conflict over fd42::/64, directly with {from}")
    );
    assert_eq!(
        LogLine::Started {
            key: learnt,
            hops: 1
        }
        .to_string(),
        format!("conflict over fd42::/64, 1 hop away via {from}")
    );
    assert_eq!(
        LogLine::Continues {
            key: learnt,
            hops: 2,
            reports: 4,
            over: secs(64)
        }
        .to_string(),
        format!(
            "conflict over fd42::/64, 2 hops away via {from}: \
             4 more reports in 64 s"
        )
    );
    assert_eq!(
        LogLine::Ended {
            key: direct,
            hops: 0
        }
        .to_string(),
        format!("conflict over fd42::/64, directly with {from}: no longer reported")
    );
}
