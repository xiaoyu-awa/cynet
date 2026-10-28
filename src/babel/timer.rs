#[cfg(test)]
mod tests;

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, binary_heap::PeekMut},
    time::{Duration, Instant},
};

use slotmap::SlotMap;

slotmap::new_key_type! {
    /// Identifies a timer.
    pub struct TimerKey;
}

/// A queue of timers, each with a value and a deadline, along with the current time,
/// which timeouts count from and is updated with [`set_now`](Self::set_now).
pub struct TimerQueue<T> {
    timers: SlotMap<TimerKey, (T, Instant)>,
    heap: BinaryHeap<Reverse<(Instant, TimerKey)>>,
    now: Instant,
}

impl<T> TimerQueue<T> {
    /// Creates an empty queue of timers, with `now` as the current time.
    pub fn new(now: Instant) -> Self {
        Self {
            timers: SlotMap::with_key(),
            heap: BinaryHeap::new(),
            now,
        }
    }

    /// Returns the current time, as last set.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Sets the current time.
    pub fn set_now(&mut self, now: Instant) {
        self.now = now;
    }

    /// Inserts a timer with a deadline `timeout` from now.
    pub fn insert(&mut self, value: T, timeout: Duration) -> TimerKey {
        self.insert_at(value, self.now + timeout)
    }

    /// Inserts a timer with a deadline at `when`.
    fn insert_at(&mut self, value: T, when: Instant) -> TimerKey {
        let key = self.timers.insert((value, when));
        self.heap.push(Reverse((when, key)));
        key
    }

    /// Moves the deadline of a timer to `timeout` from now (see [`reset_at`](Self::reset_at)).
    pub fn reset(&mut self, key: &mut TimerKey, timeout: Duration) {
        self.reset_at(key, self.now + timeout);
    }

    /// Moves the deadline of a timer.
    ///
    /// A timer moved earlier is removed and inserted again, with `key` set to its new key.
    pub fn reset_at(&mut self, key: &mut TimerKey, when: Instant) {
        let deadline = &mut self.timers[*key].1;
        if when < *deadline {
            // An earlier deadline needs a new key. With the same key, the old item stays in
            // the heap until the timer fires or is removed. If the deadline is then moved past
            // the old item, `settle` moves the old item to the deadline too, rather than
            // dropping it. The timer then keeps the extra item for as long as it lives, and
            // `settle` has to move both items each time the deadline is moved later.
            let value = self.remove(*key);
            *key = self.insert_at(value, when);
        } else {
            // A later deadline is reached through the item already in the heap.
            *deadline = when;
        }
    }

    /// Removes a timer, returning its value.
    pub fn remove(&mut self, key: TimerKey) -> T {
        self.timers.remove(key).expect("timer should exist").0
    }

    /// Returns the deadline of a timer.
    pub fn deadline(&self, key: TimerKey) -> Instant {
        self.timers[key].1
    }

    /// Returns the earliest deadline, if any.
    pub fn next_deadline(&mut self) -> Option<Instant> {
        self.settle().map(|(when, _)| when)
    }

    /// Removes a timer whose deadline has passed and returns its value, if any.
    pub fn pop_expired(&mut self) -> Option<T> {
        let (when, key) = self.settle()?;
        if when > self.now {
            return None;
        }
        self.heap.pop();
        Some(self.timers.remove(key).unwrap().0)
    }

    /// Pops stale items off the top and moves early ones to their deadlines, until the
    /// top item is at its timer's deadline, returning it, if any.
    fn settle(&mut self) -> Option<(Instant, TimerKey)> {
        loop {
            let mut top = self.heap.peek_mut()?;
            let Reverse((when, key)) = *top;
            match self.timers.get(key) {
                Some(&(_, deadline)) if deadline == when => return Some((when, key)),
                // The deadlines don't match, so the item is early.
                Some(&(_, deadline)) => {
                    debug_assert!(deadline > when);
                    *top = Reverse((deadline, key));
                }
                // The timer is removed.
                None => {
                    PeekMut::pop(top);
                }
            }
        }
    }
}
