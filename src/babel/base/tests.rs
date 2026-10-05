use super::*;

#[test]
fn hello_history() {
    let mut history = HelloHistory::new();

    // Each step receives a Hello with the given seqno, or misses one if `None`,
    // and is followed by the expected effect, history bits and expected seqno.
    let steps = [
        // An empty history accepts any seqno.
        (Some(100), HelloEffect::None, 0b1, 101),
        (Some(101), HelloEffect::None, 0b11, 102),
        // Two Hellos were lost: fast-forward.
        (Some(104), HelloEffect::None, 0b11001, 105),
        (None, HelloEffect::None, 0b110010, 106),
        // The missed Hello was only late: undo history.
        (Some(105), HelloEffect::None, 0b110011, 106),
        // A difference of 16 is still within the history.
        (Some(122), HelloEffect::None, 0b1, 123),
        // A larger one restarts the history with this Hello.
        (Some(140), HelloEffect::Flush, 0b1, 141),
    ];

    for (i, (seqno, effect, bits, expected_seqno)) in steps.into_iter().enumerate() {
        let actual_effect = match seqno {
            Some(seqno) => history.received(Seqno::new(seqno)),
            None => history.missed(),
        };
        assert_eq!(
            (actual_effect, history.bits(), history.expected_seqno()),
            (effect, bits, Seqno::new(expected_seqno)),
            "step {i}"
        );
    }

    // The 16th missed Hello empties the history, which then accepts any seqno again.
    for _ in 0..15 {
        assert_eq!(history.missed(), HelloEffect::None);
    }
    assert_eq!(history.missed(), HelloEffect::Flush);
    assert_eq!(history.bits(), 0);
    assert_eq!(history.received(Seqno::new(9)), HelloEffect::None);
    assert_eq!(history.bits(), 0b1);
}
