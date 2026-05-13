libbgp
---

`libbgp` is a C11 library for working with BGP-4 packets and small BGP control
plane building blocks. It provides public C APIs for packet parsing and
encoding, path attributes, incremental stream framing, IPv4 and IPv6 RIBs,
route filters, an event bus, output handlers, and a BGP finite state machine
(FSM).

The project is intended for applications that need to embed BGP protocol
handling, inspect or generate BGP messages, maintain a local route table, or
build simple peering tools. It is not a complete router daemon by itself: it
does not provide a production multi-peer process, configuration language,
policy engine, kernel FIB programming, persistence, or an operational CLI. The
examples show how to connect the library to TCP sockets, but long-running
process management remains the application's responsibility.

Public headers live under `include/libbgp/`. Applications can include the
umbrella header:

```c
#include <libbgp/libbgp.h>
```

## Features

- BGP message parsing and encoding for OPEN, UPDATE, KEEPALIVE, and
  NOTIFICATION packets.
- Incremental stream framing with `libbgp_sink`, including fragmented packet
  reassembly and queued packet delivery.
- OPEN capability support for four-octet ASN and MP-BGP capability objects,
  with unknown capability preservation.
- UPDATE support for classic IPv4 withdrawn routes and IPv4 NLRI.
- Path attribute support for ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF,
  ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITY, AS4_PATH, AS4_AGGREGATOR,
  MP_REACH_NLRI for IPv6 unicast, MP_UNREACH_NLRI for IPv6 unicast, and
  unknown optional attributes.
- Four-octet ASN helpers for AS_PATH/AS4_PATH and AGGREGATOR/AS4_AGGREGATOR
  downgrade and restore workflows.
- IPv4 and IPv6 prefix helpers for wire-format parse/write, comparison, and
  prefix containment.
- IPv4 and IPv6 RIB storage with insert, local insert, withdraw, discard,
  route count, longest-prefix lookup, scoped lookup, and best-path selection.
- Route filtering for IPv4 and IPv6 prefixes, AS path contains/origin matches,
  community matches, negative matches, and ordered permit/deny rules.
- Event bus for session, route, collision, and custom events.
- FSM support for BGP session state transitions, OPEN/KEEPALIVE negotiation,
  hold/keepalive timers, soft/hard reset, collision handling, route import into
  RIBs, route advertisement from RIB/event sources, inbound/outbound filters,
  next-hop checks and rewrites, and optional IPv6 unicast MP-BGP.
- Output handling through either POSIX file descriptors or caller-provided
  send/receive callbacks.
- Custom global allocator hooks and a configurable logging API.
- Optional `THREADSAFE=1` build that enables pthread-backed locks in stateful
  handles such as RIBs, sinks, filters, event buses, output handlers, logging,
  and the FSM.

### Current Scope and Limits

- `libbgp` has FSM/session components, but it is still a library, not a
  complete BGP speaker daemon.
- IPv4 unicast is supported through classic UPDATE NLRI. MP-BGP IPv4
  capability negotiation exists in the FSM, but public UPDATE storage is still
  classic IPv4 NLRI.
- IPv6 unicast is supported through MP_REACH_NLRI and MP_UNREACH_NLRI
  attributes and the IPv6 RIB/FSM paths. Other AFI/SAFI combinations are not
  implemented as typed attributes and are preserved as unknown attributes where
  applicable.
- RIB lookup APIs return borrowed internal route pointers. They remain valid
  only until the next mutating operation on the same RIB or until destroy.
  In `THREADSAFE=1` builds, callers still need external synchronization if
  they keep borrowed route pointers while another thread may mutate the RIB.
- The thread-safe build protects library handle internals; it does not make an
  application-level BGP design automatically race-free.

## Build

`libbgp` uses the root `Makefile`. There is no CMake or Meson build file in
the current tree.

Requirements:

- C11 compiler, such as GCC or Clang
- `make`
- POSIX socket APIs for the bundled examples
- Doxygen, optional, for API documentation generation

On Debian-based systems:

```sh
sudo apt install gcc make doxygen
```

Build static and shared libraries:

```sh
make
```

The default build writes:

- `build/threadsafe-0/libbgp.a`
- `build/threadsafe-0/libbgp.so`
- compatibility copies at `build/libbgp.a` and `build/libbgp.so`

The installed library name is `bgp`, so installed consumers typically link with
`-lbgp` and include headers from `-I<PREFIX>/include`.

Build the pthread-backed variant:

```sh
make THREADSAFE=1
```

Add compiler or linker flags with `CFLAGS_EXTRA` and `LDFLAGS_EXTRA`:

```sh
make CFLAGS_EXTRA="-O2 -g"
```

Install headers and libraries:

```sh
sudo make install
```

Use `PREFIX` and `DESTDIR` for staged installs:

```sh
make PREFIX=/usr DESTDIR="$PWD/pkg" install
```

Clean generated build outputs:

```sh
make clean
```

## Test and Verification

Run all unit tests:

```sh
make test
```

Compile-check every public header:

```sh
make headers
```

Build examples:

```sh
make examples
```

Run the benchmark binary:

```sh
make bench
build/threadsafe-0/bench/bench
```

Run the full project verification target:

```sh
make verify
```

`make verify` performs a clean build, builds libraries, compile-checks public
headers, runs normal tests, runs `THREADSAFE=1` tests, runs address/undefined
behavior sanitizer tests through `CFLAGS_EXTRA`/`LDFLAGS_EXTRA`, builds
examples, and checks exported symbols. `make release-check` is an alias for the
same verification flow.

There is no dedicated coverage or fuzz target in the current Makefile.

## Examples

Examples are under `examples/` and build with:

```sh
make examples
```

The binaries are written to `build/threadsafe-$(THREADSAFE)/examples/`.

Current examples:

- `peer_and_print.c`: accepts one TCP peer, parses incoming bytes with
  `libbgp_sink`, feeds packets to `libbgp_fsm`, and prints packet type names.
- `route_server.c`: accepts one TCP peer using a shared IPv4 RIB and event bus,
  then prints session and route events produced by the FSM.

Both examples default to TCP port 1179 so they can run without root:

```sh
build/threadsafe-0/examples/peer_and_print --port 1179
build/threadsafe-0/examples/route_server --port 1179
```

Use `--help` on either binary for options. To listen on the standard BGP port,
pass `--port 179` and run with the privileges required by your system.

## Minimal API Sketch

Parse a complete BGP packet:

```c
#include <libbgp/libbgp.h>

int parse_packet(const uint8_t *buf, size_t len)
{
    libbgp_packet_t pkt;
    size_t consumed = 0;
    libbgp_err_t err;

    libbgp_packet_init(&pkt);
    err = libbgp_packet_parse(&pkt, buf, len, &consumed);
    if (err != LIBBGP_OK) {
        libbgp_packet_destroy(&pkt);
        return -1;
    }

    /* Inspect pkt.type and pkt.data here. */

    libbgp_packet_destroy(&pkt);
    return 0;
}
```

Use a stream sink when reading from TCP:

```c
libbgp_sink_t sink;

libbgp_sink_init(&sink);
libbgp_sink_feed(&sink, bytes, byte_count);

while (libbgp_sink_packet_count(&sink) > 0) {
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    if (libbgp_sink_pop(&sink, &pkt) == LIBBGP_OK) {
        /* Pass pkt to libbgp_fsm_on_packet() or inspect it directly. */
    }
    libbgp_packet_destroy(&pkt);
}

libbgp_sink_destroy(&sink);
```

## Documentation

API documentation can be generated with Doxygen from the repository root:

```sh
doxygen
```

`Doxyfile` writes generated documentation under `docs/`, including HTML output
under `docs/html`.

## C++ Compatibility Notes

The C11 API preserves the core protocol behavior of the legacy C++ library,
including MP-BGP IPv4/IPv6 route-family gating, IPv6 global plus link-local
nexthop handling, FSM collision controls, soft/hard reset behavior, negotiated
hold-time access, and state-change notifications.

Some legacy C++ convenience APIs are intentionally represented differently in C.
Textual prefix construction is handled by the prefix parse APIs, parser details
are returned through parse/write result codes, and UPDATE mutation remains
available through public message/path-attribute structs plus lower-level helper
functions instead of one wrapper per C++ mutator.

The legacy `BgpFsm::run(buffer, size)` auto-tick wrapper is split into explicit
sink parsing, `libbgp_fsm_on_packet()`, and `libbgp_fsm_tick()` calls. The C API
therefore does not need a `no_autotick` switch. Sink/output failures are returned
as errors instead of exposing the legacy `BROKEN` state. Logging remains the
standalone C logging API rather than per-object logger injection.

`libbgp_fsm_init(fsm, NULL)` uses the legacy 120 second hold timer and 40 second
keepalive defaults. When callers pass their own `struct libbgp_fsm_config`, the
C API uses the field values exactly as provided; it does not merge zero-valued
fields with legacy defaults. A zero-initialized custom config therefore keeps
`hold_time` and `keepalive_time` at 0 unless the caller passes `NULL` or fills
those fields explicitly.

## License

MIT
