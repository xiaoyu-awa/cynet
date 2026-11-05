#!/usr/bin/env bash
# Runs real cynet daemons in network namespaces, with kernel forwarding off everywhere but on the
# one node with a LAN behind it. It needs no root: it re-executes itself in a user namespace, and
# only needs ping, ip, nsenter, script and unshare. It changes nothing outside its namespaces.
#
#   cargo build && tests/netns.sh
#
# The mesh is a diamond, with a LAN host behind D, and A's MTU larger than the others':
#
#        B
#       / \
#      A   D --- L
#       \ /
#        C
#
# A second mesh is a chain, X - Y - Z, whose Y has no addresses of its own. W joins it at Y, as a
# gateway with no addresses, and a host M behind it:
#
#      X - Y - Z
#          |
#          W --- M
#
# A lone node, V, has addresses but no kernel routes.
#
# Two pairs, P - Q and R - S, go silent for long enough that WireGuard gives up on their sessions:
# P and Q in a network outage, and R and S with R stopped. That happens behind everything else, so
# the wait costs little.

set -u

if [[ -z ${CYNET_NETNS_INNER:-} ]]; then
    # The PID namespace takes every process down with this script, however it ends.
    exec env CYNET_NETNS_INNER=1 unshare --user --map-root-user --mount --net \
        --pid --fork --kill-child --mount-proc -- "$0" "$@"
fi

CYNET=$(realpath "${CYNET:-target/debug/cynet}")
if [[ ! -x $CYNET ]]; then
    echo "no cynet binary at $CYNET: run cargo build first" >&2
    exit 2
fi

WORK=$(mktemp -d)
FAILED=0

declare -A NS_PID DAEMON_PID PUBLIC

cleanup() {
    for pid in "${DAEMON_PID[@]}" "${NS_PID[@]}"; do
        kill -KILL "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    if [[ ${KEEP_LOGS:-} ]]; then
        echo "logs are in $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# For the sockets of `cynet show`, in this mount namespace only.
mount -t tmpfs tmpfs /run || exit 2

pass() { echo "  ok    $1"; }
fail() {
    echo "  FAIL  $1"
    [[ $# -gt 1 ]] && echo "$2" | sed 's/^/        /'
    FAILED=1
}

# Checks that the output of a command so far matches a pattern.
expect() {
    local name=$1 pattern=$2 output=$3
    if grep -qE -- "$pattern" <<<"$output"; then
        pass "$name"
    else
        fail "$name" "$output"
    fi
}

expect_not() {
    local name=$1 pattern=$2 output=$3
    if grep -qE -- "$pattern" <<<"$output"; then
        fail "$name" "$output"
    else
        pass "$name"
    fi
}

expect_empty() {
    local name=$1 output=$2
    if [[ -z $output ]]; then
        pass "$name"
    else
        fail "$name" "$output"
    fi
}

in_ns() {
    local ns=$1
    shift
    nsenter --net="/proc/${NS_PID[$ns]}/ns/net" -- "$@"
}

new_ns() {
    local ns=$1
    unshare --net -- sleep infinity &
    NS_PID[$ns]=$!
    # Wait until it's in its own namespace.
    while [[ $(readlink "/proc/${NS_PID[$ns]}/ns/net") == "$(readlink /proc/self/ns/net)" ]]; do
        sleep 0.01
    done
    in_ns "$ns" ip link set lo up
    # A new namespace can inherit this from the host.
    in_ns "$ns" sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv6/conf/all/forwarding'
    in_ns "$ns" sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter'
}

# Links two namespaces, with a /30 subnet numbered by the given number.
link() {
    local a=$1 b=$2 n=$3
    ip link add "v$a$b" netns "${NS_PID[$a]}" type veth peer name "v$b$a" netns "${NS_PID[$b]}"
    in_ns "$a" ip addr add "172.16.$n.1/30" dev "v$a$b"
    in_ns "$b" ip addr add "172.16.$n.2/30" dev "v$b$a"
    in_ns "$a" ip link set "v$a$b" up
    in_ns "$b" ip link set "v$b$a" up
}

new_key() {
    local node=$1
    "$CYNET" genkey >"$WORK/$node.key"
    PUBLIC[$node]=$("$CYNET" pubkey <"$WORK/$node.key")
}

# Writes the start of a node's config: its name, MTU, and as TOML lists its addresses, attached
# networks, and mesh prefixes.
write_config() {
    local node=$1 mtu=$2 addresses=$3 attached=$4 mesh=$5
    cat >"$WORK/cyn-$node.toml" <<EOF
[interface]
mtu = $mtu
addresses = [$addresses]

[wireguard]
private_key_file = "$WORK/$node.key"
listen_port = 51820

[routing]
mesh = [$mesh]
attached = [$attached]

EOF
    chmod 600 "$WORK/cyn-$node.toml" "$WORK/$node.key"
}

add_peer() {
    local node=$1 peer=$2 endpoint_ip=$3
    cat >>"$WORK/cyn-$node.toml" <<EOF
[[peer]]
public_key = "${PUBLIC[$peer]}"
endpoint = "$endpoint_ip:51820"

EOF
}

start() {
    local node=$1
    # gotatun's timers log when a session is given up on, which nothing else shows.
    RUST_LOG=${RUST_LOG:-info},gotatun::noise::timers=debug nsenter --net="/proc/${NS_PID[$node]}/ns/net" -- \
        "$CYNET" run "$WORK/cyn-$node.toml" >"$WORK/$node.log" 2>&1 &
    DAEMON_PID[$node]=$!
}

# Waits until a command succeeds, up to a number of seconds, and prints how long it took.
wait_until() {
    local seconds=$1
    shift
    local start=$SECONDS
    while ((SECONDS - start < seconds)); do
        if "$@" >/dev/null 2>&1; then
            echo $((SECONDS - start))
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Checks that a command succeeds within a number of seconds, and says how long it took.
expect_within() {
    local seconds=$1 name=$2 took
    shift 2
    if took=$(wait_until "$seconds" "$@"); then
        pass "$name, after ${took}s"
    else
        fail "$name"
    fi
}

ping_ok() {
    local ns=$1 destination=$2
    in_ns "$ns" ping -c1 -W1 "$destination"
}

# Reads a counter of a namespace's kernel, from /proc/net/snmp, by table and name.
snmp() {
    local ns=$1 table=$2 field=$3
    in_ns "$ns" awk -v table="$table:" -v field="$field" '
        $1 == table {
            if (!column) {
                for (i = 2; i <= NF; i++) if ($i == field) column = i
            } else {
                print $column
                exit
            }
        }' /proc/net/snmp
}

# Reads a counter of a namespace's kernel, from /proc/net/snmp6, by name.
snmp6() {
    local ns=$1 field=$2
    in_ns "$ns" awk -v field="$field" '$1 == field { print $2 }' /proc/net/snmp6
}

MESH='"10.42.0.0/16", "fd42::/48", "192.168.7.0/24"'

echo "starting the diamond mesh"
for node in a b c d l; do new_ns "$node"; done
for node in a b c d; do new_key "$node"; done

link a b 1
link a c 2
link b d 3
link c d 4
link d l 5
in_ns d ip addr add 192.168.7.1/24 dev vdl
in_ns l ip addr add 192.168.7.5/24 dev vld
in_ns l ip route add default via 192.168.7.1
in_ns d sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

write_config a 1420 '"10.42.0.1", "fd42::1"' '' "$MESH"
write_config b 1400 '"10.42.0.2", "fd42::2"' '' "$MESH"
write_config c 1400 '"10.42.0.3", "fd42::3"' '' "$MESH"
write_config d 1400 '"10.42.0.4", "fd42::4"' '"192.168.7.0/24"' "$MESH"
add_peer a b 172.16.1.2
add_peer a c 172.16.2.2
add_peer b a 172.16.1.1
add_peer b d 172.16.3.2
add_peer c a 172.16.2.1
add_peer c d 172.16.4.2
add_peer d b 172.16.3.1
add_peer d c 172.16.4.1

for node in a b c d; do start "$node"; done

echo "waiting for the routes to converge"
expect_within 60 "A reaches D across two hops, with kernel forwarding off on A, B and C" ping_ok a 10.42.0.4
expect_within 30 "the same over IPv6" ping_ok a fd42::4

for node in p q r s; do
    new_ns "$node"
    new_key "$node"
done
link p q 10
link r s 11
write_config p 1400 '"10.70.0.1"' '' '"10.70.0.0/16"'
write_config q 1400 '"10.70.0.2"' '' '"10.70.0.0/16"'
write_config r 1400 '"10.71.0.1"' '' '"10.71.0.0/16"'
write_config s 1400 '"10.71.0.2"' '' '"10.71.0.0/16"'
add_peer p q 172.16.10.2
add_peer q p 172.16.10.1
add_peer r s 172.16.11.2
add_peer s r 172.16.11.1
for node in p q r s; do start "$node"; done
if ! wait_until 60 ping_ok p 10.70.0.2 >/dev/null || ! wait_until 60 ping_ok r 10.71.0.2 >/dev/null; then
    fail "the pairs that will go silent should converge first"
fi
in_ns p ip link set vpq down
in_ns q ip link set vqp down
kill -TERM "${DAEMON_PID[r]}"
wait "${DAEMON_PID[r]}" 2>/dev/null
unset "DAEMON_PID[r]"
silence_start=$SECONDS

echo "ICMP errors"
output=$(in_ns a ping -c1 -W2 -t1 10.42.0.4 2>&1)
expect "a TTL of 1 runs out at the transit node" 'From 10\.42\.0\.[23] .*Time to live exceeded' "$output"
output=$(in_ns a ping -c1 -W2 -t2 10.42.0.4 2>&1)
expect "a TTL of 2 reaches D" '1 received' "$output"
output=$(in_ns a ping -c1 -W2 -t1 fd42::4 2>&1)
expect "a hop limit of 1 runs out at the transit node" 'From fd42::[23] .*Time exceeded' "$output"
# Waiting for the routes above drew errors from A to itself, which can use up its rate limit.
sleep 2
output=$(in_ns a ping -c1 -W2 10.42.9.9 2>&1)
expect "no route: the local host hears it from its own tun address" 'From 10\.42\.0\.1 .*Destination Net Unreachable' "$output"
output=$(in_ns a ping -c1 -W2 fd42:0:0:9::9 2>&1)
expect "the same over IPv6" 'From fd42::1 .*(Destination unreachable|No route)' "$output"
output=$(in_ns a ping -c1 -W2 -M do -s 1385 10.42.0.4 2>&1)
expect "too big for the transit node's MTU" 'From 10\.42\.0\.[23] .*mtu = 1400' "$output"
# IPv6's header is 20 octets longer, so the same size wouldn't fit A's own MTU.
output=$(in_ns a ping -c1 -W2 -M do -s 1365 fd42::4 2>&1)
expect "the same over IPv6" 'From fd42::[23] .*(too big|mtu=1400)' "$output"
output=$(in_ns a ping -c1 -W2 -s 1300 10.42.0.4 2>&1)
expect "what fits goes through" '1 received' "$output"

# Counted by the kernel that receives them, with a new socket per packet: ping stops short, as a
# pending error on its socket fails its next send. The errors above, and the polling before them,
# have spent tokens, which come back at one per second, up to the burst of 6.
sleep 7
before=$(snmp a Icmp InDestUnreachs)
in_ns a bash -c 'for _ in {1..30}; do echo x >/dev/udp/10.42.0.8/9; done'
sleep 0.2
count=$(($(snmp a Icmp InDestUnreachs) - before))
if ((count >= 6 && count <= 7)); then
    pass "errors to one destination are rate limited: $count for 30 packets"
else
    fail "errors to one destination are rate limited: $count for 30 packets"
fi

echo "the attached network"
expect_within 30 "a LAN host behind D reaches A, through D's kernel and the mesh" ping_ok l 10.42.0.1
output=$(in_ns a ping -c1 -W2 192.168.7.5 2>&1)
expect "A reaches the LAN host" '1 received' "$output"
output=$(in_ns l ping -c1 -W2 10.42.9.9 2>&1)
expect "the LAN host hears of no route from D's tun address" 'From 10\.42\.0\.4 .*Destination Net Unreachable' "$output"

echo "the interface"
output=$(in_ns a ip -6 addr show dev cyn-a 2>&1)
expect_not "no link-local address on the interface" 'fe80' "$output"
expect "the IPv6 address is assigned as a /128" 'fd42::1/128' "$output"
output=$(in_ns a ip -4 addr show dev cyn-a 2>&1)
expect "the IPv4 address is assigned as a /32" '10\.42\.0\.1/32' "$output"
output=$(in_ns a ip route show dev cyn-a 2>&1)
expect "a kernel route for each mesh prefix" '192\.168\.7\.0/24' "$output"
expect_not "and no warning of a skipped one" 'skipping the kernel route' "$(cat "$WORK/a.log")"
expect "including the one that the addresses are in" '10\.42\.0\.0/16' "$output"
expect_not "no routes for individual mesh nodes" '10\.42\.0\.4' "$output"
output=$(in_ns a sysctl -n net.ipv4.ip_forward 2>&1 || in_ns a cat /proc/sys/net/ipv4/ip_forward)
expect "kernel forwarding is off on A" '^0$' "$output"
output=$(in_ns b cat /proc/sys/net/ipv4/ip_forward)
expect "kernel forwarding is off on B" '^0$' "$output"

echo "cynet show"
output=$(in_ns a "$CYNET" show cyn-a 2>&1)
expect_not "has no colors when piped" $'\x1b' "$output"
expect "names the interface" '^interface: cyn-a' "$output"
expect "lists peer B" "peer: ${PUBLIC[b]//+/\\+}" "$output"
expect "lists peer C" "peer: ${PUBLIC[c]//+/\\+}" "$output"
expect "shows a handshake" 'latest handshake: [0-9]+' "$output"
expect "shows a link cost" 'link cost: [0-9]+' "$output"
expect "lists injected routes" '10\.42\.0\.1/32 +injected' "$output"
expect "lists the selected route to D" '10\.42\.0\.4/32 +via .*, metric [0-9]+$' "$output"
expect "shows how long it has been up" 'uptime: [0-9]+' "$output"
expect_not "leaves Babel's details to -v" 'seqno|router-id| rid [0-9a-f]|metric [0-9a-z]+ \(|rxcost|hello history|feasible' "$output"
# Not at once: a node may have selected a longer route it heard first, and hysteresis keeps it there
# for up to a minute or so, during which split horizon keeps it from advertising the route to A.
has_unselected() { in_ns a "$CYNET" show cyn-a | grep -qE 'not via .*, metric [0-9]'; }
if took=$(wait_until 120 has_unselected); then
    pass "lists the unselected route to D, after a further ${took}s"
else
    fail "lists the unselected route to D" "$(in_ns a "$CYNET" show cyn-a)"
fi
expect "lists the attached network behind D" '192\.168\.7\.0/24 +via' "$output"
output=$(in_ns a "$CYNET" show -v cyn-a 2>&1)
expect "-v adds this node's seqno" '^  router-id: [0-9a-f]{16}, seqno: [0-9]+$' "$output"
expect "-v adds what makes up a link's cost" 'rxcost: [0-9]+, txcost: [0-9]+, rtt penalty: [0-9]+$' "$output"
expect "-v adds the Hello history" 'hello history: [01]{16} ' "$output"
expect "-v puts a route on its own line, with more details" '^    via .*, metric [0-9]+ \([0-9]+\), rid [0-9a-f]{16}, seqno [0-9]+$' "$(grep -A1 '10\.42\.0\.4/32$' <<<"$output")"
expect "-v adds details of the unselected route" '^    not via .*, metric [0-9]+ \([0-9]+\), rid [0-9a-f]{16}, seqno [0-9]+, (un)?feasible$' "$output"
# A pseudo-terminal, which is the one place for colors.
output=$(in_ns a script -qec "'$CYNET' show cyn-a" /dev/null 2>&1)
expect "has colors in a terminal" $'\x1b\\[32m\x1b\\[1minterface\x1b\\[0m: \x1b\\[32mcyn-a' "$output"
expect "including peers" $'\x1b\\[33m\x1b\\[1mpeer\x1b\\[0m: ' "$output"
expect "and it says the same as when piped" 'link cost: [0-9]+' "$(sed $'s/\x1b\\[[0-9;]*m//g' <<<"$output")"
output=$(in_ns a "$CYNET" show 2>&1)
expect "with no name, shows every running interface" '^interface: cyn-' "$output"
output=$(in_ns a "$CYNET" show nonexistent 2>&1)
expect "an unknown interface is an error" 'not running' "$output"

echo "what the kernels made of it"
for node in a b c d l; do
    for counter in "Icmp InCsumErrors" "Ip InHdrErrors"; do
        # shellcheck disable=SC2086
        value=$(snmp "$node" $counter)
        if [[ $value == 0 ]]; then
            pass "${node^^}: no $counter"
        else
            fail "${node^^}: $value $counter"
        fi
    done
    for counter in Icmp6InCsumErrors Ip6InHdrErrors; do
        value=$(snmp6 "$node" "$counter")
        if [[ $value == 0 ]]; then
            pass "${node^^}: no $counter"
        else
            fail "${node^^}: $value $counter"
        fi
    done
done

echo "failures"
# Whichever transit node carries the traffic now, kill it without warning.
selected=$(in_ns a "$CYNET" show cyn-a | grep -E '10\.42\.0\.4/32 +via' | sed -E 's/.*via ([^… ]+).*/\1/')
if [[ ${PUBLIC[b]} == "$selected"* ]]; then
    victim=b survivor=c
else
    victim=c survivor=b
fi
kill -KILL "${DAEMON_PID[$victim]}"
wait "${DAEMON_PID[$victim]}" 2>/dev/null
unset "DAEMON_PID[$victim]"
if [[ -S /run/cynet/cyn-$victim.sock ]]; then
    pass "a crash leaves ${victim^^}'s socket behind"
else
    fail "a crash leaves ${victim^^}'s socket behind"
fi
if output=$(in_ns a "$CYNET" show 2>&1); then
    pass "with a socket left behind, showing every interface still succeeds"
else
    fail "with a socket left behind, showing every interface still succeeds" "$output"
fi
expect "which lists those running" "^interface: cyn-$survivor\$" "$output"
expect_not "and not the one that crashed" "^interface: cyn-$victim\$" "$output"
output=$(in_ns a "$CYNET" show "cyn-$victim" 2>&1)
expect "showing it by name reports that it is not running" 'not running' "$output"
expect_within 60 "after a crash of ${victim^^}, A reaches D through ${survivor^^}" ping_ok a 10.42.0.4

# The last path goes away gracefully, so its goodbye should spread quickly.
kill -TERM "${DAEMON_PID[$survivor]}"
if ! wait "${DAEMON_PID[$survivor]}"; then
    fail "${survivor^^} exits cleanly on SIGTERM"
else
    pass "${survivor^^} exits cleanly on SIGTERM"
fi
unset "DAEMON_PID[$survivor]"
held() { in_ns a "$CYNET" show cyn-a | grep -qE '10\.42\.0\.4/32 +unreachable'; }
if took=$(wait_until 10 held); then
    pass "its goodbye has A hold the route to D, after ${took}s"
else
    fail "its goodbye has A hold the route to D" "$(in_ns a "$CYNET" show cyn-a)"
fi
output=$(in_ns a ping -c1 -W2 10.42.0.4 2>&1)
expect "a held route gives host unreachable" 'From 10\.42\.0\.1 .*Destination Host Unreachable' "$output"

output=$(in_ns "$survivor" ip link show "cyn-$survivor" 2>&1)
expect "the interface is gone after SIGTERM" 'does not exist' "$output"
if [[ -e /run/cynet/cyn-$survivor.sock ]]; then
    fail "the socket is gone after SIGTERM"
else
    pass "the socket is gone after SIGTERM"
fi

echo "a node with no addresses of its own"
for node in x y z w; do
    new_ns "$node"
    new_key "$node"
done
new_ns m
link x y 6
link y z 7
link y w 8
link w m 9
in_ns m ip route add default via 172.16.9.1
in_ns w sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

SECOND_MESH='"10.50.0.0/16", "fd50::/48", "172.16.9.0/30"'
write_config x 1400 '"10.50.0.1", "fd50::1"' '' "$SECOND_MESH"
write_config y 1400 '' '' "$SECOND_MESH"
write_config z 1400 '"10.50.0.3", "fd50::3"' '' "$SECOND_MESH"
write_config w 1400 '' '"172.16.9.0/30"' "$SECOND_MESH"
add_peer x y 172.16.6.2
add_peer y x 172.16.6.1
add_peer y z 172.16.7.2
add_peer z y 172.16.7.1
add_peer y w 172.16.8.2
add_peer w y 172.16.8.1
for node in x y z w; do start "$node"; done

expect_within 60 "X reaches Z across Y" ping_ok x 10.50.0.3
output=$(in_ns y ip -4 route show dev cyn-y 2>&1; in_ns y ip -6 route show dev cyn-y 2>&1)
expect_empty "with no local prefixes, Y has no routes to its interface in either family" "$output"
output=$(in_ns y ip route get 10.50.0.3 2>&1)
expect_not "so its host's traffic to the mesh stays out of the interface" 'dev cyn-y' "$output"
output=$(cat "$WORK/y.log")
expect "Y warns of the IPv4 route it skips" 'skipping the kernel route for 10\.50\.0\.0/16' "$output"
expect "and of the IPv6 one" 'skipping the kernel route for fd50::/48' "$output"
wait_until 30 ping_ok x fd50::3 >/dev/null
output=$(in_ns x ping -c1 -W2 -t1 10.50.0.3 2>&1)
expect "IPv4 errors from Y come from the dummy address" 'From 192\.0\.0\.8 .*Time to live exceeded' "$output"
output=$(in_ns x ping -c1 -W2 -t1 fd50::3 2>&1)
expect "IPv6 errors from Y come from the dummy prefix" 'From 100::1:[0-9a-f:]+ .*Time exceeded' "$output"
router_id=$(in_ns y "$CYNET" show -v cyn-y | sed -nE 's/^  router-id: ([0-9a-f]+), .*/\1/p')
tail=$(sed -E 's/.*From 100::1:([0-9a-f:]+).*/\1/' <<<"$(grep -E 'From 100::1' <<<"$output")")
as_hex=$(tr -d ':' <<<"$(sed -E 's/(^|:)([0-9a-f]{3})(:|$)/\10\2\3/g; s/(^|:)([0-9a-f]{2})(:|$)/\100\2\3/g; s/(^|:)([0-9a-f])(:|$)/\1000\2\3/g' <<<"$tail")")
if [[ $as_hex == "$router_id" ]]; then
    pass "that address carries Y's router-id, as cynet show -v reports it"
else
    fail "that address carries Y's router-id" "from ping: $tail, from cynet show -v: $router_id"
fi

echo "a gateway with no addresses"
output=$(in_ns w ip -4 route show dev cyn-w 2>&1)
expect "an attached IPv4 network keeps W's IPv4 mesh routes" '10\.50\.0\.0/16' "$output"
output=$(in_ns w ip -6 route show dev cyn-w 2>&1)
expect_empty "with no local IPv6 prefix, W has no IPv6 routes" "$output"
output=$(cat "$WORK/w.log")
expect "W warns of the IPv6 route it skips" 'skipping the kernel route for fd50::/48' "$output"
expect_not "and not of the IPv4 ones it keeps" 'skipping the kernel route for (10\.50|172\.16)' "$output"
expect_within 60 "M reaches X through W's kernel routes" ping_ok m 10.50.0.1
expect_within 30 "X reaches M" ping_ok x 172.16.9.2

echo "a node with addresses and no kernel routes"
new_ns v
new_key v
write_config v 1400 '"10.60.0.1", "fd60::1"' '' '"10.60.0.0/16", "fd60::/48"'
sed -i '/^\[routing\]/a kernel_routes = false' "$WORK/cyn-v.toml"
add_peer v x 172.16.6.1
start v
wait_until 10 in_ns v "$CYNET" show cyn-v >/dev/null
output=$(in_ns v ip -4 route show dev cyn-v 2>&1; in_ns v ip -6 route show dev cyn-v 2>&1)
expect_empty "with kernel_routes = false, V has no routes to its interface in either family" "$output"
output=$(in_ns v ip addr show dev cyn-v 2>&1)
expect_not "and it warns of no skipped ones" 'skipping the kernel route' "$(cat "$WORK/v.log")"
expect "its IPv4 address is assigned" '10\.60\.0\.1/32' "$output"
expect "its IPv6 address is assigned" 'fd60::1/128' "$output"
if ping_ok v 10.60.0.1 >/dev/null 2>&1 && ping_ok v fd60::1 >/dev/null 2>&1; then
    pass "and this host still answers on them"
else
    fail "and this host still answers on them"
fi

echo "long silences"
# WireGuard asks again 15 s after the last reply, for 90 s, and then forgets the session.
left=$((112 - (SECONDS - silence_start)))
if ((left > 0)); then
    sleep "$left"
fi
for node in p q s; do
    output=$(in_ns "$node" "$CYNET" show "cyn-$node" 2>&1)
    expect "${node^^} has no session left" 'CONNECTION_EXPIRED' "$(cat "$WORK/$node.log")"
    expect "but still knows when its last handshake was" 'latest handshake: [0-9]+ minute' "$output"
    expect "and its neighbour is still there, with an infinite cost" 'link cost: infinite' "$output"
    expect_not "and no route through it" ' via ' "$output"
done

rtt_ms() {
    in_ns "$1" "$CYNET" show "cyn-$1" | sed -nE 's/.*rtt: ([0-9.]+) ms$/\1/p'
}
has_rtt() {
    [[ -n $(rtt_ms "$1") ]]
}

# Checks that each of the given nodes measures an RTT, and that it is a sensible one.
check_rtts() {
    local when=$1 node rtt
    shift
    for node in "$@"; do
        if ! wait_until 30 has_rtt "$node" >/dev/null; then
            fail "${node^^} measures an RTT $when"
        elif rtt=$(rtt_ms "$node") && ((${rtt%.*} < 1000)); then
            pass "${node^^} measures a sensible RTT $when: $rtt ms"
        else
            fail "${node^^} measures a sensible RTT $when: $rtt ms"
        fi
    done
}

# WireGuard has stopped asking on either side, so this takes a Hello to start a handshake.
in_ns p ip link set vpq up
in_ns q ip link set vqp up
expect_within 30 "after the outage, P reaches Q again" ping_ok p 10.70.0.2
start r
expect_within 30 "after R comes back, it reaches S again" ping_ok r 10.71.0.2
# Hellos stamped during the silence would make for an RTT of many seconds here.
check_rtts "after the silence" p q r s

echo "a quick restart"
# An echo from the old process would make for a false RTT here, on the restarted node, if it passed
# the check of its age. The acknowledged startup packet keeps it from being taken in at all.
kill -TERM "${DAEMON_PID[s]}"
wait "${DAEMON_PID[s]}" 2>/dev/null
start s
expect_within 30 "after S restarts, R reaches it again" ping_ok r 10.71.0.2
check_rtts "after the restart" r s

if ((FAILED)); then
    echo "FAILED"
    exit 1
fi
echo "all passed"
