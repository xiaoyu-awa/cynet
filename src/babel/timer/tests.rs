use std::collections::HashMap;

use rand::{RngExt, SeedableRng, rngs::StdRng};

use super::*;

/// Random insertions, resets, changes of value, removals and passing time give the same
/// timers, in the same order of deadline, as a map of their deadlines.
#[test]
fn timers_match_a_model() {
    let base = Instant::now();
    let at = |ms: u64| base + Duration::from_millis(ms);
    let timeout = |rng: &mut StdRng| {
        Duration::from_millis(match rng.random_range(0..4) {
            0 => rng.random_range(0..100),
            1 => rng.random_range(0..10_000),
            2 => rng.random_range(0..400_000),
            _ => rng.random_range(0..20_000_000),
        })
    };

    for seed in 0..8 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut timers = TimerQueue::new(base);
        // The id and deadline of each timer.
        let mut model: HashMap<TimerKey, (u64, Instant)> = HashMap::new();
        let mut keys: Vec<TimerKey> = Vec::new();
        let mut now = 0;

        for id in 0..8_000 {
            match rng.random_range(0..10) {
                0..=3 => {
                    let timeout = timeout(&mut rng);
                    let key = timers.insert(id, timeout);
                    model.insert(key, (id, at(now) + timeout));
                    keys.push(key);
                }
                4..=5 if !keys.is_empty() => {
                    let i = rng.random_range(0..keys.len());
                    let key = &mut keys[i];
                    let (id, _) = model.remove(&*key).unwrap();
                    let timeout = timeout(&mut rng);
                    timers.reset(key, timeout);
                    model.insert(*key, (id, at(now) + timeout));
                }
                6 if !keys.is_empty() => {
                    let key = keys.swap_remove(rng.random_range(0..keys.len()));
                    assert_eq!(timers.remove(key), model.remove(&key).unwrap().0);
                }
                7 if !keys.is_empty() => {
                    let key = keys[rng.random_range(0..keys.len())];
                    timers.set(key, id);
                    model.get_mut(&key).unwrap().0 = id;
                }
                _ => {
                    now += match rng.random_range(0..3) {
                        0 => rng.random_range(0..5),
                        1 => rng.random_range(0..2_000),
                        _ => rng.random_range(0..200_000),
                    };
                    timers.set_now(at(now));
                    let mut popped = Vec::new();
                    while let Some(id) = timers.pop_expired() {
                        popped.push(id);
                    }
                    let deadlines: HashMap<_, _> = model.values().copied().collect();
                    let popped_deadlines: Vec<_> = popped.iter().map(|id| deadlines[id]).collect();
                    assert!(
                        popped_deadlines.is_sorted(),
                        "seed {seed}: popped out of order"
                    );
                    popped.sort();
                    let mut expired: Vec<_> = (model.values())
                        .filter(|&&(_, when)| when <= at(now))
                        .map(|&(id, _)| id)
                        .collect();
                    expired.sort();
                    assert_eq!(popped, expired, "seed {seed}: expired timers");
                    model.retain(|_, &mut (_, when)| when > at(now));
                    keys.retain(|key| model.contains_key(key));
                }
            }

            let earliest = model.values().map(|&(_, when)| when).min();
            assert_eq!(
                timers.next_deadline(),
                earliest,
                "seed {seed}: next deadline"
            );
            if let Some(&key) = keys.first() {
                assert_eq!(timers.deadline(key), model[&key].1);
            }
        }
    }
}

/// A timer moved earlier and then later is left with a single item in the heap.
#[test]
fn timers_moved_earlier_then_later_keep_one_item() {
    let base = Instant::now();
    let mut timers = TimerQueue::new(base);
    let mut key = timers.insert((), Duration::from_secs(2));
    timers.reset(&mut key, Duration::from_secs(1));
    timers.reset(&mut key, Duration::from_secs(3));
    assert_eq!(timers.next_deadline(), Some(base + Duration::from_secs(3)));
    assert_eq!(timers.heap.len(), 1);
}

/// Timers pushed back again and again keep a single item each in the heap.
#[test]
fn pushed_back_timers_keep_one_item() {
    let base = Instant::now();
    let mut timers = TimerQueue::new(base);
    let mut keys: Vec<_> = (0..100)
        .map(|i| timers.insert(i, Duration::from_secs(56)))
        .collect();
    for s in 1..=300 {
        timers.set_now(base + Duration::from_secs(s));
        for key in &mut keys {
            timers.reset(key, Duration::from_secs(56));
        }
        assert_eq!(timers.pop_expired(), None);
        assert_eq!(
            timers.next_deadline(),
            Some(timers.now() + Duration::from_secs(56))
        );
    }
    assert_eq!(timers.heap.len(), keys.len());
}
