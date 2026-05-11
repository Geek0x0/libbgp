libbgp
---
`libbgp` is a C11 BGP (Border Gateway Protocol) library. It provides C APIs
for BGP message serialization/deserialization, packet parsing, route attributes,
RIB storage, filtering, events, and a BGP finite state machine.

Public headers live under `include/libbgp/`. Applications can include the
umbrella header:

```c
#include <libbgp/libbgp.h>
```

For simple usage and quick start, refer to the C examples. For detailed API
usage, refer to the generated documentation.

### Install

`libbgp` builds from the root `Makefile`. In general, you need the following
build dependencies:

- a C11 compiler
- make
- Doxygen (optional, for generating documentation)

If you use a Debian based operating system, you should be able to install these
with the following apt command:

```
# apt install gcc make doxygen
```

Once you have the dependencies installed, use the following commands to build,
test, and install libbgp:

```
$ make
$ make test
$ make headers
$ make examples
# make install
```

Set `THREADSAFE=1` to build the thread-safe variant:

```
$ make THREADSAFE=1
$ make test THREADSAFE=1
```

Additional compiler and linker flags can be supplied with `CFLAGS_EXTRA` and
`LDFLAGS_EXTRA`, for example when running sanitizer builds:

```
$ make test CFLAGS_EXTRA="-fsanitize=address,undefined -g" LDFLAGS_EXTRA="-fsanitize=address,undefined"
```

### Document

libbgp documentation is available online at <https://lab.nat.moe/libbgp-doc>.
You may also build the documentation by running `doxygen` under the project root
directory, where `Doxyfile` is located. The generated output is written under
`docs/`.

### Examples

Examples are available under the `examples/` directory and build with:

```
$ make examples
```

Current examples include `examples/peer_and_print.c` and
`examples/route_server.c`. See `examples/README.md` for run commands and
available options.

### C++ Compatibility Notes

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

### License

MIT
