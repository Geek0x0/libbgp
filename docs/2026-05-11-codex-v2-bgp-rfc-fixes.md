# codex_v2 BGP RFC Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Fix `worktrees/codex_v2` BGP behavior so route propagation, AS4 handling, FSM errors, and path-attribute forwarding follow RFC semantics rather than merely matching historical C++ quirks.

**Architecture:** Keep the public C API stable unless a task explicitly says otherwise. Add internal RIB best-path result helpers in `src/rib_internal.h` and use them from `src/fsm.c` so UPDATE side effects are driven by selected-route changes, not raw inbound NLRI. Keep message/attribute fixes localized to `src/update.c`, `src/pattr.c`, and OPEN/FSM validation paths.

**Tech Stack:** C11, project Makefile, existing `LIBBGP_TEST` test harness, RFC 4271 core BGP-4, RFC 4760 MP-BGP, RFC 6793 AS4, RFC 4486 Cease subcodes.

---

## File Map

- Modify: `worktrees/codex_v2/src/rib_internal.h`
  - Add internal result structs/enums for insert/withdraw best-path changes.
  - Add best-route-only iterators for IPv4 and IPv6.
- Modify: `worktrees/codex_v2/src/rib4.c`
  - Implement IPv4 best-change insert/withdraw helpers.
  - Align tie-break behavior to RFC-oriented deterministic ordering.
  - Implement best-route-only iteration.
- Modify: `worktrees/codex_v2/src/rib6.c`
  - Mirror IPv4 RIB fixes for MP-BGP IPv6 routes.
- Modify: `worktrees/codex_v2/src/fsm.c`
  - Consume RIB best-change results when publishing route events.
  - Rebuild outbound UPDATEs from selected routes/prefixes instead of re-sending mixed inbound UPDATEs.
  - Validate peer BGP Identifier with full RFC/project constraints.
  - Send Cease/Admin Shutdown on administrative stop.
  - Apply inbound filters per prefix rather than per packet.
- Modify: `worktrees/codex_v2/src/update.c`
  - Fix AS4_PATH prepend to retain true 4-byte ASN.
  - Implement RFC 6793 suffix-based AS_PATH reconstruction.
  - Avoid unnecessary AS4_PATH on downgrade when no information is lost.
- Modify: `worktrees/codex_v2/src/pattr.c`
  - Ensure learned unknown optional transitive attributes are forwarded with Partial set.
- Modify: `worktrees/codex_v2/include/libbgp/pattr.h`
  - Only if needed: add an internal/public flag marker for learned unknown attrs; prefer avoiding public API changes if existing `flags` is sufficient.
- Modify: `worktrees/codex_v2/tests/test_rib.c`
  - Add best-change and best-only iterator tests.
- Modify: `worktrees/codex_v2/tests/test_fsm.c`
  - Add route-event, mixed UPDATE filter, BGP ID, and stop NOTIFICATION tests.
- Modify: `worktrees/codex_v2/tests/test_update.c`
  - Add AS4 prepend/restore/downgrade tests.
- Modify: `worktrees/codex_v2/tests/test_pattr.c`
  - Add unknown optional transitive Partial-bit forwarding test.
- Verify: `worktrees/codex_v2/Makefile`
  - Use existing `test`, `verify`, sanitizer, and `THREADSAFE=1` targets.

---

## RFC Policy Decisions

Use these decisions without further clarification:

1. Prefer RFC-correct protocol behavior over historical C++ behavior where they conflict.
2. Default hold-time differences are not part of the first implementation unless a failing RFC test demonstrates a protocol issue; RFC 4271 permits configurable negotiated hold time.
3. MP_REACH/MP_UNREACH parser strictness should follow RFC 4760 field validity while preserving interoperability only where RFC behavior is explicitly tolerant.
4. Administrative `stop()` should send Cease/Admin Shutdown when a NOTIFICATION is sent.
5. Route advertisement should reflect selected best routes only; no add-path semantics unless the project explicitly implements Add-Path later.

---

### Task 1: Add RIB Best-Path Change Primitives

**Files:**
- Modify: `worktrees/codex_v2/src/rib_internal.h`
- Modify: `worktrees/codex_v2/src/rib4.c`
- Modify: `worktrees/codex_v2/src/rib6.c`
- Test: `worktrees/codex_v2/tests/test_rib.c`

- [x] **Step 1: Write failing IPv4 RIB best-change tests**

Append these tests near the existing RIB4 tests in `worktrees/codex_v2/tests/test_rib.c`:

```c
#include "../src/rib_internal.h"

LIBBGP_TEST(rib4_insert_reports_only_best_path_changes)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(198u, 51u, 100u, 0u, 24u);
    libbgp_rib4_route_t best = route4(prefix, 1u);
    libbgp_rib4_route_t worse = route4(prefix, 2u);
    bgp_rib4_change_t change;
    uint64_t update_id = 0u;

    best.local_pref = 200u;
    worse.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &best, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, change.best->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &worse, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, change.best->source_router_id);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_withdraw_reports_replacement_vs_unreachable)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_rib4_route_t primary = route4(prefix, 1u);
    libbgp_rib4_route_t backup = route4(prefix, 2u);
    bgp_rib4_change_t change;
    uint64_t update_id = 0u;

    primary.local_pref = 200u;
    backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &primary, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &backup, &change, &update_id));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_track_best(&rib, 1u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, change.best->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_track_best(&rib, 2u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_UNREACHABLE, change.kind);
    LIBBGP_ASSERT(change.best == NULL);

    libbgp_rib4_destroy(&rib);
}
```

Register both tests in the `tests[]` table in `test_rib.c`.

- [x] **Step 2: Run the targeted test and verify it fails**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_rib
```

Expected: compile failure because `bgp_rib4_change_t`, `BGP_RIB_CHANGE_*`, `bgp_rib4_insert_track_best()`, and `bgp_rib4_withdraw_track_best()` do not exist.

- [x] **Step 3: Add internal result types and declarations**

Add to `worktrees/codex_v2/src/rib_internal.h` after the iterator typedefs:

```c
typedef enum bgp_rib_change_kind {
    BGP_RIB_CHANGE_NO_BEST_CHANGE = 0,
    BGP_RIB_CHANGE_NEW_BEST,
    BGP_RIB_CHANGE_REPLACEMENT_BEST,
    BGP_RIB_CHANGE_UNREACHABLE
} bgp_rib_change_kind_t;

typedef struct bgp_rib4_change {
    bgp_rib_change_kind_t kind;
    const libbgp_rib4_route_t *best;
} bgp_rib4_change_t;

typedef struct bgp_rib6_change {
    bgp_rib_change_kind_t kind;
    const libbgp_rib6_route_t *best;
} bgp_rib6_change_t;

libbgp_err_t bgp_rib4_insert_track_best(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_change_t *change,
    uint64_t *update_id);
libbgp_err_t bgp_rib6_insert_track_best(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_change_t *change,
    uint64_t *update_id);

libbgp_err_t bgp_rib4_withdraw_track_best(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_change_t *change);
libbgp_err_t bgp_rib6_withdraw_track_best(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_rib6_change_t *change);
```

- [x] **Step 4: Implement IPv4 best-change helpers**

In `worktrees/codex_v2/src/rib4.c`, implement helpers using the existing insert/withdraw/lookup primitives:

```c
static const libbgp_rib4_route_t *rib4_lookup_exact_best(
    const libbgp_rib4_t *rib,
    const libbgp_prefix4_t *prefix)
{
    const libbgp_rib4_route_t *best = NULL;

    if (rib == NULL || prefix == NULL) {
        return NULL;
    }
    if (libbgp_rib4_lookup(rib, prefix->addr, &best) != LIBBGP_OK) {
        return NULL;
    }
    if (best == NULL || !libbgp_prefix4_eq(&best->prefix, prefix)) {
        return NULL;
    }
    return best;
}

libbgp_err_t bgp_rib4_insert_track_best(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_change_t *change,
    uint64_t *update_id)
{
    const libbgp_rib4_route_t *before;
    const libbgp_rib4_route_t *after;
    libbgp_err_t err;

    if (rib == NULL || route == NULL || change == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    before = rib4_lookup_exact_best(rib, &route->prefix);
    err = libbgp_rib4_insert(rib, route);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (update_id != NULL) {
        err = bgp_rib4_exact_update_id(rib, route->source_router_id, &route->prefix, update_id);
        if (err != LIBBGP_OK) {
            return err;
        }
    }

    after = rib4_lookup_exact_best(rib, &route->prefix);
    change->best = after;
    if (before == after) {
        change->kind = BGP_RIB_CHANGE_NO_BEST_CHANGE;
    } else if (before == NULL && after != NULL) {
        change->kind = BGP_RIB_CHANGE_NEW_BEST;
    } else {
        change->kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
    }
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib4_withdraw_track_best(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_change_t *change)
{
    const libbgp_rib4_route_t *before;
    const libbgp_rib4_route_t *after;
    bool was_best;
    libbgp_err_t err;

    if (rib == NULL || prefix == NULL || change == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    before = rib4_lookup_exact_best(rib, prefix);
    was_best = before != NULL && before->source_router_id == source_router_id;
    err = libbgp_rib4_withdraw(rib, source_router_id, prefix);
    if (err != LIBBGP_OK) {
        return err;
    }

    after = rib4_lookup_exact_best(rib, prefix);
    change->best = after;
    if (!was_best) {
        change->kind = BGP_RIB_CHANGE_NO_BEST_CHANGE;
    } else if (after == NULL) {
        change->kind = BGP_RIB_CHANGE_UNREACHABLE;
    } else {
        change->kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
    }
    return LIBBGP_OK;
}
```

Adjust function names if `libbgp_rib4_withdraw()` has a slightly different existing signature; do not duplicate deletion logic.

- [x] **Step 5: Mirror the implementation for IPv6**

Add equivalent `rib6_lookup_exact_best()`, `bgp_rib6_insert_track_best()`, and `bgp_rib6_withdraw_track_best()` to `worktrees/codex_v2/src/rib6.c`, using `libbgp_prefix6_eq()`, `libbgp_rib6_lookup()`, `libbgp_rib6_insert()`, `libbgp_rib6_withdraw()`, and `bgp_rib6_exact_update_id()`.

- [x] **Step 6: Run targeted and full tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_rib
make -C worktrees/codex_v2 test
```

Expected: both commands pass.

- [x] **Step 7: Commit**

```bash
git add worktrees/codex_v2/src/rib_internal.h worktrees/codex_v2/src/rib4.c worktrees/codex_v2/src/rib6.c worktrees/codex_v2/tests/test_rib.c
git commit -m "fix: track rib best-path changes"
```

---

### Task 2: Align RIB Comparator and Best-Only Iteration

**Files:**
- Modify: `worktrees/codex_v2/src/rib_internal.h`
- Modify: `worktrees/codex_v2/src/rib4.c`
- Modify: `worktrees/codex_v2/src/rib6.c`
- Test: `worktrees/codex_v2/tests/test_rib.c`

- [x] **Step 1: Write failing comparator and iterator tests**

Add this callback and tests to `test_rib.c`:

```c
typedef struct rib4_iter_count_ctx {
    size_t count;
    uint32_t sources[8];
} rib4_iter_count_ctx_t;

static bool record_rib4_source(const libbgp_rib4_route_t *route, void *ctx)
{
    rib4_iter_count_ctx_t *record = (rib4_iter_count_ctx_t *)ctx;

    LIBBGP_ASSERT(route != NULL);
    LIBBGP_ASSERT(record->count < LIBBGP_ARRAY_LEN(record->sources));
    record->sources[record->count++] = route->source_router_id;
    return true;
}

LIBBGP_TEST(rib4_best_route_prefers_lower_update_id_as_final_tie_break)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(192u, 0u, 2u, 0u, 24u);
    libbgp_rib4_route_t older = route4(prefix, 1u);
    libbgp_rib4_route_t newer = route4(prefix, 2u);

    older.update_id = 10u;
    newer.update_id = 20u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &newer));
    assert_rib4_best_source(&rib, ip4(192u, 0u, 2u, 99u), 1u);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_best_route_visits_one_route_per_prefix)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t first = p4(10u, 0u, 0u, 0u, 24u);
    libbgp_prefix4_t second = p4(10u, 0u, 1u, 0u, 24u);
    libbgp_rib4_route_t first_best = route4(first, 1u);
    libbgp_rib4_route_t first_backup = route4(first, 2u);
    libbgp_rib4_route_t second_best = route4(second, 3u);
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    first_best.local_pref = 200u;
    first_backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first_backup));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &second_best));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(2u, ctx.count);
    LIBBGP_ASSERT_EQ_U64(1u, ctx.sources[0]);
    LIBBGP_ASSERT_EQ_U64(3u, ctx.sources[1]);

    libbgp_rib4_destroy(&rib);
}
```

Register both tests.

- [x] **Step 2: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_rib
```

Expected: compile failure for `bgp_rib4_foreach_best_route()` and/or assertion failure for the current newer-update-id preference.

- [x] **Step 3: Add best-route iterator declarations**

Add to `src/rib_internal.h`:

```c
libbgp_err_t bgp_rib4_foreach_best_route(
    const libbgp_rib4_t *rib,
    bgp_rib4_route_iter_fn fn,
    void *ctx);
libbgp_err_t bgp_rib6_foreach_best_route(
    const libbgp_rib6_t *rib,
    bgp_rib6_route_iter_fn fn,
    void *ctx);
```

- [x] **Step 4: Fix the deterministic final tie-break**

In `src/rib4.c` and `src/rib6.c`, update the comparator so lower `update_id` wins when all earlier selection criteria are equal:

```c
if (a->update_id != b->update_id) {
    return a->update_id < b->update_id;
}
```

Keep local project policy knobs like `weight` only where already present, but do not allow eBGP/iBGP preference to override higher `LOCAL_PREF` or shorter AS_PATH. Use this order:

1. higher local weight, if project-local weight is configured
2. higher LOCAL_PREF
3. shorter AS_PATH
4. lower ORIGIN type
5. lower MED when neighboring AS is the same
6. eBGP over iBGP as a later tie-break
7. lower update ID
8. lower router ID

- [x] **Step 5: Implement best-only iterators**

In `rib4.c`, implement `bgp_rib4_foreach_best_route()` by iterating existing stored routes and invoking the callback only when the current route pointer is the exact best route for its prefix. Use existing container traversal rather than adding a second index.

Required shape:

```c
libbgp_err_t bgp_rib4_foreach_best_route(
    const libbgp_rib4_t *rib,
    bgp_rib4_route_iter_fn fn,
    void *ctx)
{
    /* Iterate all stored routes. For each candidate, call rib4_lookup_exact_best().
       Invoke fn(candidate, ctx) only when candidate == best. Stop early when fn returns false. */
}
```

Mirror the same behavior in `rib6.c`.

- [x] **Step 6: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_rib
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 7: Commit**

```bash
git add worktrees/codex_v2/src/rib_internal.h worktrees/codex_v2/src/rib4.c worktrees/codex_v2/src/rib6.c worktrees/codex_v2/tests/test_rib.c
git commit -m "fix: advertise only best rib routes"
```

---

### Task 3: Publish Route Events Only for Best-Path Changes

**Files:**
- Modify: `worktrees/codex_v2/src/fsm.c`
- Test: `worktrees/codex_v2/tests/test_fsm.c`

- [x] **Step 1: Write failing FSM route-event tests**

Add tests near existing route-event tests in `test_fsm.c`. Reuse existing `event_ctx_t` and UPDATE construction helpers where available; if helper names differ, adapt the test body to existing local helpers without changing the assertions.

```c
LIBBGP_TEST(fsm_does_not_publish_add_event_for_non_best_route)
{
    fsm_harness_t h;
    event_ctx_t events;
    libbgp_update_msg_t best;
    libbgp_update_msg_t worse;

    fsm_harness_init_established(&h, &events);
    make_ipv4_update(&best, p4(198u, 51u, 100u, 0u, 24u), ip4(192u, 0u, 2u, 1u), 200u);
    make_ipv4_update(&worse, p4(198u, 51u, 100u, 0u, 24u), ip4(192u, 0u, 2u, 2u), 100u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 1u, &best));
    LIBBGP_ASSERT_EQ_U64(1u, events.route_added_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 2u, &worse));
    LIBBGP_ASSERT_EQ_U64(1u, events.route_added_count);
    LIBBGP_ASSERT_EQ_U64(0u, events.route_withdrawn_count);

    libbgp_update_destroy(&worse);
    libbgp_update_destroy(&best);
    fsm_harness_destroy(&h);
}

LIBBGP_TEST(fsm_withdraw_best_publishes_replacement_not_withdraw)
{
    fsm_harness_t h;
    event_ctx_t events;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_update_msg_t primary;
    libbgp_update_msg_t backup;
    libbgp_update_msg_t withdraw;

    fsm_harness_init_established(&h, &events);
    make_ipv4_update(&primary, prefix, ip4(192u, 0u, 2u, 1u), 200u);
    make_ipv4_update(&backup, prefix, ip4(192u, 0u, 2u, 2u), 100u);
    make_ipv4_withdraw(&withdraw, prefix);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 1u, &primary));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 2u, &backup));
    LIBBGP_ASSERT_EQ_U64(1u, events.route_added_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 1u, &withdraw));
    LIBBGP_ASSERT_EQ_U64(2u, events.route_added_count);
    LIBBGP_ASSERT_EQ_U64(0u, events.route_withdrawn_count);

    libbgp_update_destroy(&withdraw);
    libbgp_update_destroy(&backup);
    libbgp_update_destroy(&primary);
    fsm_harness_destroy(&h);
}
```

If `fsm_harness_t`, `make_ipv4_update()`, or `fsm_apply_test_update()` do not already exist, add small static helpers in `test_fsm.c` using the existing `out_ctx_t`, `event_ctx_t`, and inbound packet helpers already in the file. Do not export test-only helpers.

- [x] **Step 2: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
```

Expected: current implementation publishes an add event for the non-best path and a withdraw event when a replacement route exists.

- [x] **Step 3: Replace raw-NLRI event publication with RIB change events**

In `src/fsm.c`, update `fsm_apply_update()` and `fsm_publish_update_events()` so RIB insertion captures `bgp_rib4_change_t` / `bgp_rib6_change_t` and stores only meaningful changes for event publication.

Use this event mapping:

```c
switch (change.kind) {
case BGP_RIB_CHANGE_NEW_BEST:
case BGP_RIB_CHANGE_REPLACEMENT_BEST:
    publish_route_added(change.best);
    break;
case BGP_RIB_CHANGE_UNREACHABLE:
    publish_route_withdrawn(prefix);
    break;
case BGP_RIB_CHANGE_NO_BEST_CHANGE:
    break;
}
```

Do not publish from raw `msg->nlri[]` or `msg->withdrawn[]` after this change.

- [x] **Step 4: Preserve rollback behavior**

Where `fsm_apply_update()` currently uses `bgp_rib4_insert_save_replaced()` / `bgp_rib4_withdraw_exact_save()` for rollback, keep rollback exactness. Either:

1. extend the new track helpers to also return saved replaced routes, or
2. keep the existing saved-route operations and compute `before` / `after` best around them.

Do not remove existing rollback paths for partial UPDATE failure.

- [x] **Step 5: Mirror IPv6 event behavior**

Apply identical logic for MP_REACH_NLRI and MP_UNREACH_NLRI IPv6 paths. A lower-preference IPv6 route must not publish add; withdrawing IPv6 best with a replacement must publish replacement add rather than withdraw.

- [x] **Step 6: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 7: Commit**

```bash
git add worktrees/codex_v2/src/fsm.c worktrees/codex_v2/tests/test_fsm.c
git commit -m "fix: publish route events from best-path changes"
```

---

### Task 4: Rebuild Outbound UPDATEs and Apply Filters Per Prefix

**Files:**
- Modify: `worktrees/codex_v2/src/fsm.c`
- Test: `worktrees/codex_v2/tests/test_fsm.c`

- [x] **Step 1: Write failing outbound mixed-UPDATE filter test**

Add a test to `test_fsm.c` using the existing output sink helpers:

```c
LIBBGP_TEST(fsm_outbound_filter_cannot_leak_denied_prefix_from_mixed_update)
{
    fsm_harness_t h;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_update_msg_t inbound;
    libbgp_prefix4_t allowed = p4(10u, 0u, 0u, 0u, 24u);
    libbgp_prefix4_t denied = p4(10u, 0u, 1u, 0u, 24u);
    libbgp_update_msg_t parsed;
    size_t used = 0u;

    fsm_harness_init_established_with_out_filter(&h, &out, &events, deny_10_0_1_0_24_filter);
    make_ipv4_update_two_nlri(&inbound, allowed, denied, ip4(192u, 0u, 2u, 1u), 100u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 1u, &inbound));
    LIBBGP_ASSERT_EQ_U64(1u, out.update_count);

    libbgp_update_init(&parsed);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, parse_first_sent_update(&out, &parsed, &used));
    LIBBGP_ASSERT_EQ_U64(1u, parsed.nlri_count);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&allowed, &parsed.nlri[0]));

    libbgp_update_destroy(&parsed);
    libbgp_update_destroy(&inbound);
    fsm_harness_destroy(&h);
}
```

Use the repo’s actual filter callback type and output packet parser names. The assertion must be that the sent UPDATE contains exactly one NLRI: the allowed prefix.

- [x] **Step 2: Write failing inbound mixed-UPDATE filter test**

```c
LIBBGP_TEST(fsm_inbound_filter_skips_only_denied_prefix_in_mixed_update)
{
    fsm_harness_t h;
    event_ctx_t events;
    libbgp_update_msg_t inbound;
    libbgp_prefix4_t allowed = p4(10u, 0u, 0u, 0u, 24u);
    libbgp_prefix4_t denied = p4(10u, 0u, 1u, 0u, 24u);
    const libbgp_rib4_route_t *found = NULL;

    fsm_harness_init_established_with_in_filter(&h, &events, deny_10_0_1_0_24_filter);
    make_ipv4_update_two_nlri(&inbound, allowed, denied, ip4(192u, 0u, 2u, 1u), 100u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_apply_test_update(&h, 1u, &inbound));
    LIBBGP_ASSERT_EQ_U64(1u, events.route_added_count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(h.fsm->rib4, ip4(10u, 0u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(h.fsm->rib4, ip4(10u, 0u, 1u, 1u), &found));

    libbgp_update_destroy(&inbound);
    fsm_harness_destroy(&h);
}
```

Register both tests.

- [x] **Step 3: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
```

Expected: outbound path sends the original mixed UPDATE or inbound accepted-prefix event is suppressed by packet-level `advertisements_ignored`.

- [x] **Step 4: Replace outbound reuse of `event->update`**

In `fsm_send_route_event_update()` and related send helpers, stop sending `event->update` directly for route-added events. Instead, build a fresh `libbgp_update_msg_t` from the selected RIB route that survived policy.

Required behavior:

```c
static libbgp_err_t fsm_send_route_added_from_rib4(
    fsm_output_t *out,
    const libbgp_rib4_route_t *route,
    uint32_t local_asn,
    bool use_4b_asn,
    bool is_ibgp,
    ...)
{
    libbgp_update_msg_t msg;
    libbgp_err_t err;

    libbgp_update_init(&msg);
    err = update_from_rib4_route(&msg, route);
    if (err == LIBBGP_OK) {
        err = fsm_send_prepared_update(out, &msg, local_asn, use_4b_asn, is_ibgp, ...);
    }
    libbgp_update_destroy(&msg);
    return err;
}
```

Use existing route-to-update construction code if present. The final sent UPDATE must contain only the event route’s prefix.

- [x] **Step 5: Track inbound filter state per prefix**

Replace packet-level `advertisements_ignored` with per-prefix decisions. Minimal internal shape:

```c
typedef struct fsm_prefix_decision4 {
    libbgp_prefix4_t prefix;
    bool accepted;
    bgp_rib4_change_t change;
} fsm_prefix_decision4_t;
```

When applying a mixed UPDATE, skip RIB insertion and event generation only for prefixes rejected by inbound policy. Accepted prefixes in the same UPDATE must still install and publish if they change best path.

- [x] **Step 6: Apply same logic to IPv6 MP_REACH/MP_UNREACH**

Use `libbgp_prefix6_t` and `bgp_rib6_change_t`. Outbound IPv6 UPDATEs must be rebuilt from the selected route and include only the filtered route’s MP_REACH/MP_UNREACH prefix.

- [x] **Step 7: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 8: Commit**

```bash
git add worktrees/codex_v2/src/fsm.c worktrees/codex_v2/tests/test_fsm.c
git commit -m "fix: enforce per-prefix route policy"
```

---

### Task 5: Use Best-Only RIB Advertisement on Session Establishment

**Files:**
- Modify: `worktrees/codex_v2/src/fsm.c`
- Test: `worktrees/codex_v2/tests/test_fsm.c`

- [x] **Step 1: Write failing initial-advertisement test**

Add this test to `test_fsm.c`:

```c
LIBBGP_TEST(fsm_initial_rib_advertisement_sends_only_best_route_per_prefix)
{
    fsm_harness_t h;
    out_ctx_t out;
    libbgp_prefix4_t prefix = p4(172u, 16u, 0u, 0u, 24u);
    libbgp_rib4_route_t best = route4(prefix, 1u);
    libbgp_rib4_route_t backup = route4(prefix, 2u);

    fsm_harness_init_before_established(&h, &out);
    best.local_pref = 200u;
    backup.local_pref = 100u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(h.fsm->rib4, &best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(h.fsm->rib4, &backup));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_drive_to_established(&h));
    LIBBGP_ASSERT_EQ_U64(1u, count_sent_updates_for_prefix(&out, prefix));

    fsm_harness_destroy(&h);
}
```

Adapt harness names to existing helpers. The assertion must count actual outbound UPDATE packets/NLRI, not internal callbacks.

- [x] **Step 2: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
```

Expected: existing initial RIB advertisement sends all stored routes for the prefix.

- [x] **Step 3: Use best-only iterators in advertisement callbacks**

In `fsm_advertise_rib4_cb()` / `fsm_advertise_rib6_cb()` call sites, replace:

```c
bgp_rib4_foreach_route(rib, fsm_advertise_rib4_cb, &ctx);
bgp_rib6_foreach_route(rib, fsm_advertise_rib6_cb, &ctx);
```

with:

```c
bgp_rib4_foreach_best_route(rib, fsm_advertise_rib4_cb, &ctx);
bgp_rib6_foreach_best_route(rib, fsm_advertise_rib6_cb, &ctx);
```

Do not change regular lookup semantics; only outbound initial advertisement should become best-only.

- [x] **Step 4: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 5: Commit**

```bash
git add worktrees/codex_v2/src/fsm.c worktrees/codex_v2/tests/test_fsm.c
git commit -m "fix: advertise selected rib routes on establishment"
```

---

### Task 6: Fix AS4_PATH Prepend and RFC 6793 Restore

**Files:**
- Modify: `worktrees/codex_v2/src/update.c`
- Test: `worktrees/codex_v2/tests/test_update.c`

- [x] **Step 1: Write failing AS4 prepend test**

Add to `test_update.c`:

```c
LIBBGP_TEST(update_prepend_2byte_peer_preserves_true_asn_in_as4_path)
{
    uint32_t asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65552u, false));

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[0]);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[0]);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}
```

- [x] **Step 2: Write failing suffix-restore test**

```c
LIBBGP_TEST(update_restore_as_path_uses_as4_path_as_suffix)
{
    uint32_t asns[] = { 65000u, LIBBGP_AS_TRANS, LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u, 65552u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 3u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(3u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65000u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[2]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}
```

Register both tests.

- [x] **Step 3: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_update
```

Expected: prepend test sees `AS_TRANS` in AS4_PATH; suffix test may pass accidentally for this simple sequence, so add one non-suffix matrix if needed:

```c
AS_PATH  = [64512, 64513, AS_TRANS, AS_TRANS]
AS4_PATH = [65551, 65552]
Expected = [64512, 64513, 65551, 65552]
```

- [x] **Step 4: Fix AS4 prepend**

In `libbgp_update_prepend_asn()` in `src/update.c`, keep `prep_asn` for AS_PATH but prepend the original `asn` to AS4_PATH:

```c
uint32_t prep_asn = use_4b_asn || asn <= 65535u ? asn : LIBBGP_AS_TRANS;
...
err = update_prepend_to_path(as_path, prep_asn);
...
if (!use_4b_asn) {
    libbgp_pattr_t *as4_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS4_PATH);
    if (as4_path != NULL) {
        err = update_prepend_to_path(as4_path, asn);
    }
}
```

- [x] **Step 5: Implement suffix reconstruction**

Replace positional/left-to-right AS_TRANS replacement in `libbgp_update_restore_as_path()` with RFC 6793 suffix behavior:

1. Flatten AS_PATH into `as_path_flat` while preserving segment boundaries if existing helpers support it.
2. Flatten AS4_PATH into `as4_flat`.
3. If `as4_count == 0`, only convert AS_PATH to 4-byte form.
4. If `as4_count <= as_path_count`, replace the last `as4_count` ASNs in AS_PATH with AS4_PATH values.
5. If `as4_count > as_path_count`, treat the attribute pair as malformed and return `LIBBGP_ERR_INVALID`.
6. Remove AS4_PATH after successful reconstruction.
7. Preserve AS_SET/confed segments conservatively: if exact suffix replacement cannot be mapped back safely, rebuild as one AS_SEQUENCE only when the original path contained only AS_SEQUENCE; otherwise return `LIBBGP_ERR_INVALID` rather than silently corrupting path semantics.

Core replacement loop:

```c
start = as_path_count - as4_count;
for (i = 0u; i < as4_count; i++) {
    as_path_flat[start + i] = as4_flat[i];
}
```

- [x] **Step 6: Avoid unnecessary AS4_PATH on downgrade**

In `libbgp_update_downgrade_as_path()`, create AS4_PATH only if at least one ASN in the 4-byte AS_PATH is greater than `65535` or an existing AS_TRANS would otherwise lose information.

Expected behavior:

```c
if (!path_needs_as4_shadow(as_path)) {
    convert_as_path_to_2byte_without_as4_path(as_path);
    return LIBBGP_OK;
}
```

- [x] **Step 7: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_update
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 8: Commit**

```bash
git add worktrees/codex_v2/src/update.c worktrees/codex_v2/tests/test_update.c
git commit -m "fix: preserve as4 path semantics"
```

---

### Task 7: Validate OPEN Peer BGP Identifier and Stop Cease Subcode

**Files:**
- Modify: `worktrees/codex_v2/src/fsm.c`
- Test: `worktrees/codex_v2/tests/test_fsm.c`

- [x] **Step 1: Write failing BGP Identifier tests**

Add table-driven tests to `test_fsm.c`:

```c
LIBBGP_TEST(fsm_rejects_invalid_open_bgp_identifiers)
{
    static const uint32_t invalid_ids[] = {
        0x01020304u,      /* equal local router ID after harness setup */
        0x00000001u,      /* 0/8 */
        0x7f000001u,      /* loopback */
        0xe0000001u,      /* multicast */
        0xf0000001u       /* reserved */
    };
    size_t i;

    for (i = 0u; i < LIBBGP_ARRAY_LEN(invalid_ids); i++) {
        fsm_harness_t h;
        out_ctx_t out;

        fsm_harness_init_open_sent(&h, &out, 0x01020304u);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_deliver_open(&h, 65000u, invalid_ids[i], 90u));
        LIBBGP_ASSERT_EQ_U64(1u, out.notification_count);
        LIBBGP_ASSERT_EQ_U64(2u, out.last_notification_code);    /* OPEN Message Error */
        LIBBGP_ASSERT_EQ_U64(3u, out.last_notification_subcode); /* Bad BGP Identifier */
        fsm_harness_destroy(&h);
    }
}
```

Use existing constants if names are available instead of numeric literals.

- [x] **Step 2: Write failing stop subcode test**

```c
LIBBGP_TEST(fsm_stop_sends_cease_administrative_shutdown)
{
    fsm_harness_t h;
    out_ctx_t out;

    fsm_harness_init_established_with_output(&h, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_stop(h.fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.notification_count);
    LIBBGP_ASSERT_EQ_U64(6u, out.last_notification_code);    /* Cease */
    LIBBGP_ASSERT_EQ_U64(2u, out.last_notification_subcode); /* Administrative Shutdown */
    fsm_harness_destroy(&h);
}
```

Register both tests.

- [x] **Step 3: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
```

Expected: current OPEN path accepts at least some invalid IDs, and stop sends Cease subcode 0.

- [x] **Step 4: Add full peer BGP ID validation**

In `src/fsm.c`, find the existing BGP ID helper or add one near the OPEN validation helpers:

```c
static bool fsm_valid_peer_bgp_id(uint32_t peer_id, uint32_t local_id)
{
    uint32_t host = ntohl(peer_id);
    uint8_t first = (uint8_t)(host >> 24);

    if (peer_id == 0u || peer_id == local_id) {
        return false;
    }
    if (first == 0u || first == 127u || first >= 224u) {
        return false;
    }
    return true;
}
```

If router IDs are stored in host order in this file, remove `ntohl()` and keep one consistent representation. Validate by using existing tests for accepted normal IDs.

- [x] **Step 5: Use validation in all OPEN receive paths**

Apply `fsm_valid_peer_bgp_id()` in both active `OpenSent` and passive/pre-OPEN handlers. On failure, send OPEN Message Error / Bad BGP Identifier and reset according to existing FSM error handling.

- [x] **Step 6: Fix administrative stop subcode**

In `src/fsm.c`, define or reuse a Cease subcode constant:

```c
#define FSM_CEASE_ADMINISTRATIVE_SHUTDOWN 2u
```

Change `libbgp_fsm_stop()` from:

```c
return fsm_reset_common(fsm, true, 0u);
```

to:

```c
return fsm_reset_common(fsm, true, FSM_CEASE_ADMINISTRATIVE_SHUTDOWN);
```

- [x] **Step 7: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 8: Commit**

```bash
git add worktrees/codex_v2/src/fsm.c worktrees/codex_v2/tests/test_fsm.c
git commit -m "fix: validate open identifiers and stop reason"
```

---

### Task 8: Set Partial on Forwarded Unknown Optional Transitive Attributes

**Files:**
- Modify: `worktrees/codex_v2/src/pattr.c`
- Modify: `worktrees/codex_v2/src/update.c` or `worktrees/codex_v2/src/fsm.c` if outbound preparation owns attribute mutation
- Test: `worktrees/codex_v2/tests/test_pattr.c`

- [x] **Step 1: Write failing Partial-bit forwarding test**

Add to `test_pattr.c`:

```c
LIBBGP_TEST(pattr_forwarded_unknown_optional_transitive_sets_partial)
{
    const uint8_t raw[] = {
        0xc0u, 99u, 2u, 0x12u, 0x34u
    };
    uint8_t out[16];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_pattr_t attr;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(&attr, raw, sizeof(raw), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(raw), used);
    LIBBGP_ASSERT_EQ_U64(0u, attr.flags & LIBBGP_PATTR_FLAG_PARTIAL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_prepare_for_ebgp_forward(&attr));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(&attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(0xe0u, out[0]);
    LIBBGP_ASSERT_EQ_U64(99u, out[1]);

    libbgp_pattr_destroy(&attr);
}
```

If no public/internal `libbgp_pattr_prepare_for_ebgp_forward()` exists, write the test against the actual outbound UPDATE preparation helper that serializes attributes for re-advertisement.

- [x] **Step 2: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_pattr
```

Expected: compile failure for missing prepare helper or serialized flags remain `0xc0`.

- [x] **Step 3: Add a narrowly scoped prepare helper**

Prefer an internal helper in `src/pattr.c` unless public API already exposes outbound preparation:

```c
libbgp_err_t libbgp_pattr_prepare_for_ebgp_forward(libbgp_pattr_t *attr)
{
    if (attr == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (attr->type == LIBBGP_PATTR_UNKNOWN &&
        (attr->flags & LIBBGP_PATTR_FLAG_OPTIONAL) != 0u &&
        (attr->flags & LIBBGP_PATTR_FLAG_TRANSITIVE) != 0u) {
        attr->flags |= LIBBGP_PATTR_FLAG_PARTIAL;
    }
    return LIBBGP_OK;
}
```

If this remains internal, declare it in a private header instead of `include/libbgp/pattr.h`.

- [x] **Step 4: Call the helper during outbound UPDATE preparation**

In the outbound update preparation path used before sending a learned route to eBGP peers, call the helper on copied attributes before serialization. Do not mutate inbound message attributes in place if those objects can still be used for local RIB state.

- [x] **Step 5: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_pattr
make -C worktrees/codex_v2 test TESTS=test_fsm
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 6: Commit**

```bash
git add worktrees/codex_v2/src/pattr.c worktrees/codex_v2/src/update.c worktrees/codex_v2/src/fsm.c worktrees/codex_v2/tests/test_pattr.c
git commit -m "fix: mark forwarded unknown transitive attrs partial"
```

---

### Task 9: Add Structured Parse Error Mapping for NOTIFICATION Accuracy

**Files:**
- Modify: `worktrees/codex_v2/src/packet.c`
- Modify: `worktrees/codex_v2/src/fsm.c`
- Modify: internal headers if packet parse error details need a private struct
- Test: `worktrees/codex_v2/tests/test_fsm.c`

- [x] **Step 1: Write failing malformed packet NOTIFICATION test**

Add to `test_fsm.c`:

```c
LIBBGP_TEST(fsm_sends_specific_notification_for_malformed_update)
{
    fsm_harness_t h;
    out_ctx_t out;
    const uint8_t malformed_update[] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0x00u, 0x1fu, 0x02u,
        0x00u, 0x00u,
        0x00u, 0x08u,
        0x40u, 0x01u, 0x01u, 0x00u,
        0x40u, 0x03u, 0x04u, 192u, 0u, 2u, 1u
    };

    fsm_harness_init_established_with_output(&h, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, fsm_deliver_raw_packet(&h, malformed_update, sizeof(malformed_update)));
    LIBBGP_ASSERT_EQ_U64(1u, out.notification_count);
    LIBBGP_ASSERT_EQ_U64(3u, out.last_notification_code); /* UPDATE Message Error */
    LIBBGP_ASSERT(out.last_notification_subcode != 0u);
    fsm_harness_destroy(&h);
}
```

This packet omits AS_PATH while carrying NLRI; adapt bytes if an existing fixture better captures a malformed UPDATE.

- [x] **Step 2: Run and verify failure**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
```

Expected: FSM either returns a generic error or sends an imprecise NOTIFICATION.

- [x] **Step 3: Add internal parse error details**

Add a private struct near packet parsing internals:

```c
typedef struct bgp_parse_error_detail {
    libbgp_err_t err;
    uint8_t notify_code;
    uint8_t notify_subcode;
} bgp_parse_error_detail_t;
```

Provide a helper that maps parser failures to RFC NOTIFICATION code/subcode. Keep `libbgp_packet_parse_as4()` behavior unchanged for public callers; add a detail variant for FSM/sink use.

- [x] **Step 4: Use detail mapping in FSM receive path**

When raw packet parse fails in `fsm.c`, send the mapped NOTIFICATION if `notify_code != 0`; otherwise use existing generic handling. Preserve session teardown.

- [x] **Step 5: Run tests**

Run:

```bash
make -C worktrees/codex_v2 test TESTS=test_fsm
make -C worktrees/codex_v2 test
```

Expected: all tests pass.

- [x] **Step 6: Commit**

```bash
git add worktrees/codex_v2/src/packet.c worktrees/codex_v2/src/fsm.c worktrees/codex_v2/tests/test_fsm.c
git commit -m "fix: map parse failures to bgp notifications"
```

---

### Task 10: Run Full Verification Matrix and Review

**Files:**
- No planned source changes unless failures are found.

- [x] **Step 1: Run normal tests**

```bash
make -C worktrees/codex_v2 test
```

Expected: all suites pass.

- [x] **Step 2: Run project verification**

```bash
make -C worktrees/codex_v2 verify
```

Expected: build, tests, header checks, symbol checks, and sanitizer verification pass.

- [x] **Step 3: Run threadsafe build/tests**

```bash
make -C worktrees/codex_v2 clean
make -C worktrees/codex_v2 THREADSAFE=1 test
```

Expected: all tests pass with `THREADSAFE=1`.

- [x] **Step 4: Run explicit sanitizer build if not already covered by `verify`**

```bash
make -C worktrees/codex_v2 clean
make -C worktrees/codex_v2 CFLAGS_EXTRA="-fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS_EXTRA="-fsanitize=address,undefined" test
```

Expected: all tests pass without sanitizer reports.

- [x] **Step 5: Inspect the final diff**

```bash
git diff -- worktrees/codex_v2/src worktrees/codex_v2/include worktrees/codex_v2/tests
```

Expected:

- RIB changes are internal and do not unnecessarily alter public ABI.
- FSM route publication is driven by selected-route changes.
- Outbound policy cannot leak denied prefixes from mixed UPDATEs.
- AS4_PATH behavior retains true 4-byte ASNs.
- OPEN/FSM NOTIFICATION behavior uses correct RFC code/subcode.
- Unknown optional transitive attributes get Partial when forwarded.

- [x] **Step 6: Run C/C++ code review agents**

Dispatch reviewers after implementation:

1. `cpp-reviewer` for C/C++ correctness, ownership, undefined behavior, and idioms.
2. `security-reviewer` because route filtering and packet parsing are security-sensitive external input paths.
3. `silent-failure-hunter` for swallowed parser/filter/FSM errors.

Address all CRITICAL and HIGH findings before completion.

- [x] **Step 7: Commit verification fixes if needed**

If review or verification found fixes:

```bash
git add worktrees/codex_v2/src worktrees/codex_v2/include worktrees/codex_v2/tests
git commit -m "fix: address bgp rfc verification findings"
```

Skip this commit if there are no further changes.

---

## Implementation Notes

- Keep changes inside `worktrees/codex_v2` except for documentation updates requested separately.
- Do not copy C++ API shapes into C. Match externally observable RFC behavior.
- Do not implement Add-Path; sending more than one path per prefix remains incorrect for this project unless Add-Path is explicitly added later.
- Prefer private/internal headers for new helper declarations unless tests need public API coverage.
- Preserve existing rollback-on-partial-failure behavior in FSM UPDATE application.
- Avoid mutating inbound UPDATE attributes during outbound preparation; clone or rebuild outbound UPDATEs.
- For AS4 reconstruction, fail closed on ambiguous segment reconstruction rather than silently corrupting AS_PATH.

## Final Acceptance Criteria

- `make -C worktrees/codex_v2 test` passes.
- `make -C worktrees/codex_v2 verify` passes.
- `make -C worktrees/codex_v2 THREADSAFE=1 test` passes.
- Sanitizer test command passes without ASan/UBSan reports.
- New tests prove:
  - non-best routes do not publish add events;
  - best withdraw with replacement publishes replacement add, not withdraw;
  - initial RIB advertisement sends one selected route per prefix;
  - outbound mixed UPDATE filtering cannot leak denied prefixes;
  - inbound mixed UPDATE filtering skips only denied prefixes;
  - AS4_PATH stores true 4-byte ASN when AS_PATH uses AS_TRANS;
  - AS_PATH restore uses AS4_PATH suffix semantics;
  - invalid OPEN BGP IDs produce Bad BGP Identifier;
  - administrative stop sends Cease/Admin Shutdown;
  - forwarded unknown optional transitive attributes set Partial.
