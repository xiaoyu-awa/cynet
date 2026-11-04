use std::net::SocketAddr;

use super::{endpoint_to_set, needs_lookup, random_router_id};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn quiet_peers_are_looked_up() {
    // The first time, there is nothing to go by.
    assert!(needs_lookup(None, 0));
    assert!(needs_lookup(None, 100));
    // Bytes received since the last look: the endpoint is in use.
    assert!(!needs_lookup(Some(0), 1));
    assert!(!needs_lookup(Some(100), 200));
    // None received.
    assert!(needs_lookup(Some(100), 100));
}

#[test]
fn endpoint_is_replaced_only_when_it_is_not_among_the_results() {
    let resolved = [addr("203.0.113.5:51820"), addr("[2001:db8::5]:51820")];

    // No endpoint yet: take the first result.
    assert_eq!(endpoint_to_set(None, &resolved), Some(resolved[0]));

    // Among the results, in any position.
    assert_eq!(endpoint_to_set(Some(resolved[0]), &resolved), None);
    assert_eq!(endpoint_to_set(Some(resolved[1]), &resolved), None);

    // The right address on another port, as NAT can make it, is replaced: only the endpoint of a
    // quiet peer is looked at, so that port isn't working.
    assert_eq!(
        endpoint_to_set(Some(addr("203.0.113.5:40000")), &resolved),
        Some(resolved[0])
    );

    // A mapped form of the same address is the same address.
    assert_eq!(
        endpoint_to_set(Some(addr("[::ffff:203.0.113.5]:51820")), &resolved),
        None
    );
    assert_eq!(
        endpoint_to_set(Some(addr("[::ffff:203.0.113.5]:40000")), &resolved),
        Some(resolved[0])
    );

    // Gone from the results.
    assert_eq!(
        endpoint_to_set(Some(addr("198.51.100.7:51820")), &resolved),
        Some(resolved[0])
    );

    // An empty answer leaves it alone.
    assert_eq!(endpoint_to_set(Some(addr("198.51.100.7:51820")), &[]), None);
    assert_eq!(endpoint_to_set(None, &[]), None);
}

#[test]
fn router_ids_are_random() {
    assert_ne!(random_router_id(), random_router_id());
}
