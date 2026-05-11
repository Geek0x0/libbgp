# TODO

## Blocking correctness gaps

- [x] Fix filter rule priority to match the original C++ behavior.
  - Current C code applies the first added matching rule.
  - Original C++ applies the last added matching rule.
  - Code: `src/filter.c:257`
  - Test currently encoding wrong behavior: `tests/test_filter.c:87`

- [x] Fix FSM/RIB best-route AS_PATH metrics to count only AS_SEQUENCE segments.
  - Current `fsm_as_path_len_and_origin_as()` counts every AS_PATH segment.
  - Plan and original C++ compare shorter AS_SEQUENCE only.
  - Affects RIB4 and RIB6 route ranking and MED same-origin-AS logic.
  - Code: `src/fsm.c:814`, `src/fsm.c:864`, `src/fsm.c:898`

- [x] Fix path-attribute flag validation.
  - Unknown well-known/transitive attributes should be rejected.
  - Known optional-transitive attributes with the Partial bit should be accepted where valid.
  - Code: `src/pattr.c:160`, `src/pattr.c:575`, `src/pattr.c:648`

- [x] Complete UPDATE AS4 compatibility behavior.
  - Add or otherwise expose equivalents for AS_PATH/AS4_PATH restore/downgrade/prepend behavior.
  - Add AGGREGATOR/AS4_AGGREGATOR restore/downgrade behavior.
  - Ensure 4-byte-ASN session context is handled; AS_PATH is currently parsed as 2-byte ASN unconditionally.
  - Code: `include/libbgp/update.h:20`, `src/pattr.c:589`, `src/update.c`

- [x] Restore standalone UPDATE validation semantics or document the intentional split.
  - `libbgp_update_add_attr()` allows duplicate semantic attributes.
  - `libbgp_update_parse()` does not validate mandatory attributes for UPDATEs carrying NLRI.
  - FSM validates some cases later, but the standalone UPDATE API is weaker than old C++ behavior.
  - Code: `src/update.c:67`, `src/update.c:141`, `src/update.c:223`

- [x] Decide and fix OPEN unknown optional parameter behavior.
  - Current C parser silently skips optional parameters other than Capability.
  - Original C++ rejected unknown optional parameter types.
  - Code: `src/open.c:144`

## Important semantic differences

- [x] Align local duplicate RIB insert behavior with old C++ or document the new behavior.
  - Current `insert_local` replaces duplicate local prefixes through normal insert.
  - Original C++ rejected duplicate local prefixes.
  - Code: `src/rib4.c:390`, `src/rib6.c:400`, `src/rib4.c:446`, `src/rib6.c:456`
  - Fixed: local source-0 duplicate prefixes now return `LIBBGP_ERR_EXISTS` and preserve the original route.

- [x] Decide whether event bus must preserve old publisher-exclusion semantics.
  - Current C API has no publisher parameter and returns matching callback count.
  - Original C++ skipped the publisher and counted successful receiver handling.
  - Code: `include/libbgp/event.h:213`, `src/event.c:477`
  - Fixed: added `libbgp_event_bus_publish_from()` to skip the publisher subscription by ID; callbacks remain void, so the return value is the delivered callback count.

## Build, ABI, and release hygiene

- [x] Fix final symbol-gate path or provide a stable archive alias.
  - Plan references `build/libbgp.a`.
  - Current Makefile writes `build/threadsafe-$(THREADSAFE)/libbgp.a`.
  - Code: `Makefile:6`, `Makefile:11`
  - Fixed: `make all` now copies stable aliases to `build/libbgp.a` and `build/libbgp.so`.

- [x] Add a single aggregate release verification target.
  - Suggested target: `make verify` or `make release-check`.
  - Should run clean build, headers, tests, THREADSAFE tests, sanitizer tests, examples, and symbol checks.
  - Code: `Makefile:89`
  - Fixed: added `verify`, `release-check`, and `symbol-check` targets.

- [x] Rename or hide private RIB helper symbols.
  - Internal helper APIs use public-looking `libbgp_` names in `src/rib_internal.h`.
  - Dynamic export checks hide them, but static archive globals remain confusing.
  - Code: `src/rib_internal.h`, `src/rib4.c`, `src/rib6.c`
  - Fixed: private helper types/functions now use `bgp_rib*` names, and `symbol-check` rejects regressions.

- [x] Decide POSIX out-handler API scope.
  - Public header exposes `ssize_t`, `<sys/types.h>`, and fd helpers.
  - Acceptable for POSIX, but not fully freestanding C11/DPDK-neutral.
  - Code: `include/libbgp/out_handler.h:6`
  - Fixed: public callbacks now return `libbgp_io_result_t` (`ptrdiff_t`); POSIX types stay in the `.c` implementation.

## Test gaps to add

- [x] Regression test for last-added filter rule priority.
- [x] Regression test for mixed AS_SET/AS_SEQUENCE best-route comparison.
- [x] Regression tests for Partial bit handling on optional-transitive attributes.
- [x] Regression tests for unknown well-known/transitive attributes.
- [x] Regression tests for AS4 restore/downgrade/prepend and aggregator compatibility.
- [x] Regression tests for duplicate UPDATE attributes and missing mandatory attributes.
- [x] Regression tests for duplicate local RIB insert behavior.

## C++ parity follow-ups

- [x] Restore AS4-aware sink parsing context.
  - Added `libbgp_sink_init_as4()` and regression coverage for 4-byte AS_PATH UPDATE parsing through the sink.

- [x] Restore FSM route-event outbound propagation.
  - FSMs attached to an event bus now subscribe to route add/withdraw events and send UPDATEs while ESTABLISHED.
  - Inbound route events published by the FSM exclude the FSM's own subscriptions to avoid echoing learned routes back to the same peer.
  - Outbound UPDATEs are cloned and prepared with AS4 restore/downgrade and eBGP local-AS prepend.

- [x] Restore key FSM policy controls from legacy `BgpConfig`.
  - Added expected peer-AS enforcement (`libbgp_fsm_set_expected_peer_asn()`).
  - Added local-AS loop allowance (`libbgp_fsm_set_allow_local_as()`).
  - Added per-session route weight (`libbgp_fsm_set_route_weight()`).
  - Added IPv4 in/out filter hooks (`libbgp_fsm_set_in_filter4()`, `libbgp_fsm_set_out_filter4()`).

- [x] Restore default internal RIB ownership/getter behavior.
  - FSM now creates internal RIB4/RIB6 instances by default.
  - Added `libbgp_fsm_get_rib4()` and `libbgp_fsm_get_rib6()`.
  - External attached RIBs remain supported; passing `NULL` to `set_rib4/6` returns to the internal RIB.

- [x] Expand filter expressiveness toward legacy C++.
  - Added IPv4 exact/more-specific/less-specific/or-equal prefix operators.
  - Added AS_PATH negative and origin match operators.
  - Added COMMUNITY negative match operator.

## Remaining C++ parity gaps found after the first follow-up pass

- [x] High: restore local RIB route attributes and initial FSM RIB advertisement.
  - Legacy `BgpRib4::insert()` creates ORIGIN, NEXT_HOP, and empty AS_PATH for local routes.
  - Legacy FSM sends pre-existing eligible RIB4/RIB6 routes after session establishment.
  - Current C local RIB routes store only scalar route fields and FSM does not dump existing RIB routes on establishment.
  - Fixed: RIB4 local routes create ORIGIN/NEXT_HOP/AS_PATH; RIB6 local routes create ORIGIN/AS_PATH; FSM advertises existing eligible RIB4/RIB6 routes after establishment.

- [x] High: restore IPv4 next-hop policy checks and egress next-hop rewrite.
  - Legacy `BgpConfig` validates inbound IPv4 NEXT_HOP against valid-address rules and peering LAN unless disabled.
  - Legacy egress UPDATE preparation rewrites NEXT_HOP to the configured default when missing, forced, or outside the peering LAN.
  - Current C accepts/re-advertises IPv4 NEXT_HOP without these policy controls.
  - Fixed: added IPv4 peering LAN, no-check, default-nexthop, force-default, and iBGP alter controls with ingress and egress regression coverage.

- [x] High: mark learned iBGP routes as iBGP in the RIB.
  - Legacy RIB entries record `SRC_IBGP` plus peer ASN for iBGP sessions.
  - Current C route insertion path stores all learned routes as eBGP-style routes, affecting best-route ranking and re-advertisement decisions.
  - Fixed: learned IPv4/IPv6 routes now set `is_ibgp` for iBGP sessions.

- [x] Medium: restore collision-detection event behavior.
  - Legacy FSM publishes collision probes on OPEN and resolves duplicate sessions through `RouteCollisionEvent`.
  - Current C event bus has no collision event type and FSM does not resolve connection collisions.
  - Fixed: added `LIBBGP_EVENT_COLLISION` and FSM collision handling for duplicate OPEN sessions.

- [x] Medium: add IPv6 filter API/FSM hooks.
  - Legacy `BgpFilterRuleRoute6`, `in_filters6`, and `out_filters6` support IPv6 ingress/egress filtering.
  - Current C filter public API and FSM hooks are IPv4-only.
  - Fixed: added IPv6 prefix match operators, `libbgp_filter_apply_route6()`, and FSM in/out filter6 hooks.

- [x] Medium: restore IPv6 next-hop policy and link-local nexthop preservation.
  - Legacy `BgpConfig` exposes IPv6 peering LAN/default nexthop controls, and `BgpRib6Entry` preserves global plus link-local nexthops.
  - Current C only kept the global IPv6 nexthop and did not expose IPv6 nexthop policy controls.
  - Fixed: added IPv6 peering LAN/no-check/default/force controls, ingress validation, egress MP_REACH rewrite, and RIB6 link-local nexthop storage.

- [x] Low: document or replace legacy print/debug serialization helpers.
  - Legacy classes had `print`/`doPrint`-style debugging output.
  - Current C API intentionally exposes parsed structs but has no equivalent human-readable serialization API.
  - Fixed: added `libbgp_pattr_format()` for human-readable path attribute debug strings.

## Residual C++ parity differences found in the second comparison pass

- [x] Medium: restore legacy MP-BGP IPv4/IPv6 route-family gating semantics.
  - Legacy `BgpConfig::mp_bgp_ipv6=true` disables IPv4 route exchange unless `mp_bgp_ipv4=true`.
  - Current C config exposes only `enable_mpbgp_ipv6`; inbound IPv4 NLRI and initial RIB4 advertisement remain active with no equivalent `mp_bgp_ipv4`/IPv4-family gate.
  - Legacy refs: `src/bgp-config.h:162`, `src/bgp-config.h:171`, `src/bgp-fsm.cc:395`.
  - C refs: `include/libbgp/fsm.h:26`, `src/fsm.c:1532`, `src/fsm.c:2413`.
  - Fixed: added `libbgp_fsm_set_mpbgp_ipv4()` and negotiated IPv4/IPv6 send-family gates for inbound UPDATEs, initial RIB advertisements, and route-event advertisements.

- [x] Medium: restore configurable IPv6 default link-local nexthop.
  - Legacy config has both `default_nexthop6_global` and `default_nexthop6_linklocal`.
  - Current C only exposes `libbgp_fsm_set_default_nexthop6()` for the global nexthop; default rewrite clears the link-local half and emits a 16-byte MP_REACH nexthop.
  - Legacy refs: `src/bgp-config.h:263`, `src/bgp-config.h:277`, `src/bgp-fsm.cc:738`.
  - C refs: `include/libbgp/fsm.h:66`, `src/fsm.c:1086`, `src/fsm.c:1111`.
  - Fixed: added `libbgp_fsm_set_default_nexthop6_linklocal()` and preserve configured global + link-local defaults during MP_REACH rewrite.

- [x] Low: restore ability to disable FSM collision detection.
  - Legacy `BgpConfig::no_collision_detection` disables collision probes/resolution.
  - Current C always performs collision publication/resolution when an event bus is attached; there is no public setter to disable it per FSM.
  - Legacy refs: `src/bgp-config.h:142`, `src/bgp-fsm.cc:365`.
  - C refs: `include/libbgp/fsm.h:52`, `src/fsm.c:2538`, `src/fsm.c:3342`.
  - Fixed: added `libbgp_fsm_set_no_collision_detection()` and bypass collision publication/resolution when enabled.

- [x] Low: restore explicit soft/hard reset API semantics.
  - Legacy `resetSoft()` sends Cease/Admin Reset and drains the packet buffer; `resetHard()` returns to IDLE without notification.
  - Current C exposes `libbgp_fsm_stop()`, which sends Cease with subcode 0 and tears down, but there is no explicit hard reset or Administrative Reset variant.
  - Legacy refs: `src/bgp-fsm.h:178`, `src/bgp-fsm.h:187`, `src/bgp-fsm.cc:313`.
  - C refs: `include/libbgp/fsm.h:72`, `src/fsm.c:3219`, `src/fsm.c:3240`.
  - Fixed: added `libbgp_fsm_reset_soft()` with Cease/Admin Reset and `libbgp_fsm_reset_hard()` with notification-free teardown.

- [x] Low/API: document or restore legacy observability hooks.
  - Legacy FSM exposes `getHoldTimer()` and per-FSM `BgpOutHandler::notifyStateChange()`.
  - Current C has peer getters and session up/down events, but no negotiated hold-time getter and no callback for every FSM state transition.
  - Legacy refs: `src/bgp-fsm.h:88`, `src/bgp-out-handler.h:42`.
  - C refs: `include/libbgp/fsm.h:41`, `include/libbgp/event.h:12`, `include/libbgp/out_handler.h:24`.
  - Fixed: added `libbgp_fsm_negotiated_hold_time()` and `libbgp_fsm_set_state_change_cb()`.

- [x] Low/API: document remaining API-shape differences that are not core protocol gaps.
  - Legacy has textual prefix constructors/helpers, parser error detail accessors, and convenience UPDATE mutators such as `dropAttrib`, `setNextHop`, and `setNlri6`.
  - Current C keeps equivalent data writable through public structs and lower-level parse/write APIs, but does not expose all convenience wrappers.
  - Fixed: documented the intentional C API shape differences in `README.md`; these are wrapper/convenience differences, not remaining protocol behavior gaps.

## Remaining C++ parity differences found in the third comparison pass

- [x] High: make FSM route-event publication best-route aware and prefix scoped.
  - Legacy C++ publishes route add/withdraw events only when the RIB best route changes:
    - `BgpRib4::insertPriv()` / `BgpRib6::insertPriv()` return whether the inserted route became best or exposed another best route.
    - `BgpRib4::withdraw()` / `BgpRib6::withdraw()` return whether the withdrawn route made the prefix unreachable or exposed a replacement.
    - `BgpFsm::fsmEvalEstablished()` publishes only `new_routes`, `changed_entries`, and true unreachable withdrawals.
  - Current C publishes one route event for every accepted UPDATE NLRI/withdrawn prefix, independent of whether the RIB best route changed.
  - Current C attaches the original full UPDATE to every per-prefix event, so receivers can resend duplicate full UPDATEs and filters can permit one prefix while still advertising other prefixes in the same UPDATE.
  - Code: `src/fsm.c:1794`, `src/fsm.c:1820`, `src/fsm.c:1839`, `src/fsm.c:1863`, `src/fsm.c:1890`, `src/fsm.c:2198`.
  - Fixed: FSM inbound UPDATE journaling now snapshots the per-prefix best route before/after RIB mutation and publishes route events only when the effective best route changes. Published add/replacement events are rebuilt from the selected route snapshot, so each event is prefix scoped instead of carrying the original multi-prefix UPDATE.
  - Review fix: journaled route events now carry an application-order sequence number, so a single UPDATE that withdraws and re-adds a prefix publishes withdraw before add, matching the mutation order.

- [x] High: publish route withdraw/replacement events when an ESTABLISHED session discards learned routes.
  - Legacy `BgpFsm::dropAllRoutes()` calls RIB discard and publishes withdraw events for lost best routes plus add events for replacement best routes.
  - Current C `fsm_discard_peer_routes()` only removes learned RIB4/RIB6 entries and separately publishes `SESSION_DOWN`; FSM route-event subscribers do not consume `SESSION_DOWN` as route withdrawals.
  - This can leave other peers without the required withdraw or replacement advertisement after a peer session goes down.
  - Code: `src/fsm.c:422`, `src/fsm.c:2632`, `src/fsm.c:3456`, `src/fsm.c:3843`, `src/fsm.c:3914`, `src/fsm.c:4026`.
  - Fixed: ESTABLISHED teardown uses RIB discard-collection helpers to publish withdraw events for removed best routes and add events for replacement best routes before publishing `SESSION_DOWN`.
  - Review fix: `libbgp_fsm_stop()` now publishes route discard events before sending the shutdown Cease notification, matching legacy `stop()` / `setState(IDLE)` ordering; soft reset keeps the legacy notification-before-hard-reset behavior.

- [x] Medium: advertise only best/active RIB routes during initial post-establishment RIB dump.
  - Legacy initial advertisement skips `RS_STANDBY` entries and advertises only active best routes from the shared RIB.
  - Current C `bgp_rib4_foreach_route()` / `bgp_rib6_foreach_route()` iterate every stored route entry, and `fsm_advertise_existing_rib4()` / `fsm_advertise_existing_rib6()` send each eligible entry.
  - With multiple sources for the same prefix, the C FSM can advertise non-best alternate routes on session establishment.
  - Code: `src/fsm.c:2545`, `src/fsm.c:2590`, `src/rib4.c:643`, `src/rib6.c:649`.
  - Fixed: added best-route foreach helpers for RIB4/RIB6 and switched initial FSM RIB advertisement to iterate only the current best route for each prefix.
  - Review fix: best-route foreach helpers snapshot selected routes while holding the RIB lock, then invoke callbacks after unlocking so output-handler I/O and reentrant callbacks do not run under the RIB lock.

- [x] Medium: drop optional non-transitive attributes before outbound UPDATE propagation.
  - Legacy `BgpFsm::prepareUpdateMessage()` calls `BgpUpdateMessage::dropNonTransitive()` before AS4 restore/downgrade and AS prepend.
  - Current C `fsm_send_prepared_update()` does AS4 restore/downgrade and AS prepend, but does not remove non-transitive attributes such as MED from propagated UPDATEs.
  - Code: `src/fsm.c:2064`, `src/fsm.c:2086`.
  - Fixed: outbound UPDATE preparation now removes optional non-transitive attributes before nexthop/AS4/prepend handling, while preserving MP_REACH/MP_UNREACH attributes required to carry MP-BGP route families.

- [x] Low/API: decide whether to restore or document remaining FSM driver/default differences.
  - Legacy `BgpFsm::run(buffer, size)` combines sink feed, optional auto tick, and packet processing; `BgpConfig::no_autotick` disables that automatic tick.
  - Current C exposes sink parsing, `libbgp_fsm_on_packet()`, and `libbgp_fsm_tick()` separately with no single `run(buffer)` wrapper or `no_autotick` equivalent.
  - Legacy has a `BROKEN` FSM state for sink/output failure paths; current C uses error returns and teardown/IDLE behavior.
  - Legacy `BgpConfig` default hold/keepalive timers are 120/40 seconds; current C `fsm_default_config()` and `libbgp_fsm_init(fsm, NULL)` now match those defaults, while caller-provided configs still use their field values exactly.
  - Legacy objects carry per-object/per-FSM log handlers; current C logging is standalone/global and not wired through parsers/FSM internals.
  - Fixed/documented: `libbgp_fsm_init(fsm, NULL)` now uses the legacy 120/40 hold/keepalive defaults through the internal default config path. Passing a custom zero-initialized `struct libbgp_fsm_config` still leaves `hold_time`/`keepalive_time` at 0 unless callers fill them explicitly. Remaining `run(buffer)`, `no_autotick`, `BROKEN`, and per-object logger differences are documented as intentional C API shape/runtime-integration differences rather than protocol behavior gaps.

## Final-review C++ parity differences found after the third comparison pass

- [x] High: apply IPv6 MP_UNREACH before MP_REACH regardless of UPDATE attribute order.
  - Legacy `BgpFsm::fsmEvalEstablished()` handles `MP_UNREACH_NLRI` first and `MP_REACH_NLRI` second.
  - Current C walked `update->attrs` once, so a packet carrying `MP_REACH` before `MP_UNREACH` for the same prefix added and then withdrew the route.
  - Legacy refs: `src/bgp-fsm.cc:1118`, `src/bgp-fsm.cc:1137`.
  - C refs: `src/fsm.c:1862`, `src/fsm.c:1885`.
  - Fixed: IPv6 UPDATE apply now uses two passes, all `MP_UNREACH` first and all `MP_REACH` second. Added a regression where `MP_REACH` appears before `MP_UNREACH` for the same prefix and the final RIB keeps the reached route.

- [x] Medium: stop initial RIB dump after reentrant session changes.
  - Legacy initial advertisement is tied to the current established session; a reentrant teardown must not continue writing later initial routes to the stale session.
  - Current C checked `session_generation` only after the full RIB4/RIB6 dump, so an output callback that stopped the FSM during the first initial UPDATE could still receive later routes.
  - C refs: `src/fsm.c:2888`, `src/fsm.c:2947`, `src/fsm.c:2995`.
  - Fixed: initial RIB4/RIB6 callbacks check `session_generation` before and after each route send, stop iteration when stale, and skip later RIB families plus `SESSION_UP` publication after reentrant teardown.

- [x] Medium: align RIB update_id tie-break with legacy best-route ordering.
  - Legacy `BgpRibEntry::operator<()` prefers lower/older `update_id` when all higher-priority metrics tie.
  - Current C `rib4_better()` and `rib6_better()` preferred higher/newer `update_id`, changing the active route and best-only event behavior for otherwise equivalent paths.
  - Legacy ref: `src/bgp-rib.h:203`.
  - C refs: `src/rib4.c:217`, `src/rib6.c:221`.
  - Fixed: RIB4/RIB6 now prefer lower `update_id`; added IPv4 and IPv6 regression tests for otherwise equivalent routes.
