libbgp C Examples
---

Build the examples with:

```sh
make examples
```

The binaries are written to `build/threadsafe-$(THREADSAFE)/examples/`.

Both examples default to TCP port 1179 so they can be run without root:

```sh
build/threadsafe-0/examples/peer_and_print --port 1179
build/threadsafe-0/examples/route_server --port 1179
```

Use `--help` to see the available options. To listen on the standard BGP port,
pass `--port 179` and run with the privileges required by your system.

Available examples:

- `sink_fragmented_stream.c`: feeds a KEEPALIVE packet to `libbgp_sink` in
  fragments, then pops the completed packet.
- `open_capabilities.c`: builds an OPEN with four-octet ASN and IPv6 unicast
  MP-BGP capabilities, encodes it, then parses the capabilities back.
- `ipv6_mp_update.c`: constructs an IPv6 unicast MP_REACH_NLRI UPDATE and
  parses the encoded packet.
- `out_handler_callback.c`: sends an encoded packet through caller-provided
  output callbacks instead of a file descriptor.
- `event_bus_publish_subscribe.c`: subscribes event handlers, publishes route
  events, and unsubscribes one handler.
- `custom_allocator.c`: installs allocator hooks, exercises libbgp allocation,
  and restores the default allocator.
- `route_withdraw.c`: encodes an IPv4 withdraw UPDATE and applies the withdraw
  to an IPv4 RIB.
- `packet_roundtrip.c`: parses a complete BGP KEEPALIVE packet, writes it back
  to wire format, and checks that the bytes round-trip.
- `update_builder.c`: constructs an IPv4 UPDATE with ORIGIN, AS_PATH,
  NEXT_HOP, and NLRI, encodes it, then parses the encoded packet.
- `rib_filter_walkthrough.c`: builds a small IPv4 RIB, performs longest-prefix
  lookup, and applies a prefix filter decision to the selected route.
- `peer_and_print.c`: accepts one TCP peer, parses incoming bytes with
  `libbgp_sink`, feeds packets to `libbgp_fsm`, and prints packet type names.
- `route_server.c`: accepts one TCP peer using a shared IPv4 RIB and event bus,
  then prints session and route events produced by the FSM.

The examples use only the C11 public API via `<libbgp/libbgp.h>`.
