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

- `peer_and_print.c`: accepts one TCP peer, parses incoming bytes with
  `libbgp_sink`, feeds packets to `libbgp_fsm`, and prints packet type names.
- `route_server.c`: accepts one TCP peer using a shared IPv4 RIB and event bus,
  then prints session and route events produced by the FSM.

The examples use only the C11 public API via `<libbgp/libbgp.h>`.
