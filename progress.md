# Performance Optimization Progress

Plan: `docs/superpowers/plans/2026-05-14-performance-optimization.md`

Started: 2026-05-14
Branch: `codex_v2`

## Current Status

- Completed: Task 1, Task 2, Task 3, Task 4, Task 5, Task 6, Task 7, Task 8, Task 9, Task 10, Task 11, Task 12
- In progress: Task 13 implementation
- Next: Wait for Task 13 implementer result
- Notes: existing untracked `.codex/`, untracked `test-run.log`, deleted `Doxyfile`, and dirty `Makefile` are unrelated to the current Task 6 fix and will be left untouched unless needed by later tasks.

## Task Tracker

| # | Task | Status | Notes |
|---:|------|--------|-------|
| 1 | Harden build configuration and add targeted benchmarks | Completed | Commit `034b2ea`; spec and quality reviews passed |
| 2 | Fix discard_collect realloc growth | Completed | Commit `e44a70d`; spec and quality reviews passed; full ASAN blocked by pre-existing RIB UAF |
| 3 | Optimize foreach_best_route to use lpm_groups | Completed | Commit `0fa38ff`; spec and quality reviews passed |
| 4 | Optimize lookup_scoped to use source index | Completed | Commit `f9fc9fe`; spec and quality reviews passed |
| 5 | UPDATE attr view for O(1) lookup and duplicate detection | Completed | Commit `d5310a8`; spec and quality re-reviews passed |
| 6 | Packet write direct body | Completed | Commits `00645c4`, `2bdbc95`, `66e0a38`, `828c036`, `c62906d`; spec review passed; packet quality re-review passed |
| 7 | Small hot-path optimizations bundle | Completed | Commits `896ef5d`, `59719a5`, `28829c2`; spec and quality re-reviews passed |
| 8 | FSM insert_track_best clone reduction | Completed | Commits `46381ab`, `59304ea`; spec and quality re-reviews passed |
| 9 | AS_PATH contiguous allocation | Completed | Commits `e5078d1`, `2f61d6c`; spec and quality reviews passed |
| 10 | Event bus stack snapshot | Completed | Commits `47760d6`, `41dbf0e`; spec and quality re-reviews passed |
| 11 | Filter attr view and match-type bucketing | Completed | Commits `491f47f`, `83ad6d1`, `c185afb`; spec and quality re-reviews passed |
| 12 | Sink fragmented feed benchmark and delayed compact | Completed | Commit `8d03426`; spec and quality reviews passed |
| 13 | Hashmap reserve for batch insert | In progress | Implementer dispatched; reserve must account for 75% resize threshold |
| 14 | Neighbor AS internal cache for MED comparison | Pending |  |
| 15 | Profiling infrastructure and P2 decision gates | Pending |  |

## Activity Log

- 2026-05-14: Read RTK instructions and the performance plan.
- 2026-05-14: Confirmed branch `codex_v2`; saw unrelated untracked `.codex/`.
- 2026-05-14: Created this progress tracker.
- 2026-05-14: Dispatched Task 1 implementer subagent for `Makefile` and `bench/bench.c`.
- 2026-05-14: Task 1 implementer completed; commit `eb382a4`.
- 2026-05-14: Task 1 spec compliance review passed.
- 2026-05-14: Task 1 quality review found two benchmark sanity issues in `bench/bench.c`; sent back to implementer for fixes.
- 2026-05-14: Task 1 quality fixes completed; commit `034b2ea`.
- 2026-05-14: Task 1 spec re-review passed.
- 2026-05-14: Task 1 quality re-review passed; Task 1 completed.
- 2026-05-14: Dispatched Task 2 implementer subagent for `src/rib4.c`, `src/rib6.c`, and `tests/test_rib.c`.
- 2026-05-14: Task 2 implementer completed with concern: full ASAN test reports heap-use-after-free in an unrelated RIB test; starting triage.
- 2026-05-14: Reproduced the ASAN heap-use-after-free on Task 2 base commit `034b2ea`; current Task 2 large discard test passes before the baseline ASAN failure.
- 2026-05-14: Task 2 spec compliance review passed.
- 2026-05-14: Task 2 quality review passed; Task 2 completed.
- 2026-05-14: Root-cause work started for ASAN blocker: stale LPM group best pointer after same-prefix route mutation.
- 2026-05-14: Fixed ASAN baseline blockers in commit `700b00d`: RIB LPM removal now uses immutable route keys; sink compact test no longer reads past fixture.
- 2026-05-14: Full ASAN/UBSAN test and benchmark passed after baseline blocker fix.
- 2026-05-14: Dispatched Task 3 implementer subagent for `foreach_best_route` lpm_groups traversal.
- 2026-05-14: Task 3 implementer completed; commit `0fa38ff`.
- 2026-05-14: Task 3 spec compliance review passed.
- 2026-05-14: Task 3 quality review passed; Task 3 completed.
- 2026-05-14: Dispatched Task 4 implementer subagent for `lookup_scoped` source-index traversal.
- 2026-05-14: Task 4 implementer completed; commit `f9fc9fe`; reported ASAN/UBSAN test pass and `rib lookup_scoped` benchmark improvement from `33745.7 ns/op` to `10159.0 ns/op`.
- 2026-05-14: Task 4 spec compliance review passed; reviewer also ran ASAN/UBSAN test and benchmark successfully.
- 2026-05-14: Task 4 quality review passed with threaded and non-threaded RIB test coverage; Task 4 completed.
- 2026-05-14: Dispatched Task 5 implementer subagent for attr view header, UPDATE duplicate validation, FSM route attribute hot path, and update tests.
- 2026-05-14: Task 5 implementer completed; commit `094331b`; reported ASAN/UBSAN test pass and benchmark pass (`update parse/write: 223.8 ns/op`, `update parse large: 540.6 ns/op`).
- 2026-05-14: Task 5 spec compliance review passed; focused update test passed (`131 tests`).
- 2026-05-14: Task 5 quality review found blocking FSM attr-view/type-code shadowing issues plus update validation error-precedence risk; verified against current code and sent fixes back to implementer.
- 2026-05-14: Task 5 fixes completed and amended into commit `d5310a8`; added FSM UNKNOWN/type-code shadowing regression and update duplicate-before-malformed ordering regression; focused tests, full ASAN/UBSAN, and benchmark passed.
- 2026-05-14: Task 5 spec re-review passed for amended commit `d5310a8`.
- 2026-05-14: Task 5 quality re-review passed; local focused verification confirmed `update: 132 tests` and `fsm: 258 tests`; Task 5 completed.
- 2026-05-14: Dispatched Task 6 implementer subagent for direct packet body writing and byte-for-byte packet write test.
- 2026-05-14: Task 6 implementer completed; commit `00645c4`; reported packet focused test (`16 tests`), full ASAN/UBSAN test, and benchmark pass.
- 2026-05-14: Task 6 spec compliance review passed; reviewer ran ASAN/UBSAN full test successfully.
- 2026-05-15: Resumed execution. Found Task 6 follow-up commits `2bdbc95`, `66e0a38`, and `828c036` plus Task 7 implementation commit `896ef5d`; `progress.md` was behind git history.
- 2026-05-15: Re-dispatched Task 6 code quality review for committed range `d5310a8..828c036`.
- 2026-05-15: Confirmed unrelated dirty worktree entries: deleted `Doxyfile`, untracked `.codex/`, untracked `test-run.log`; leaving them untouched.
- 2026-05-15: Task 6 quality review found an Important issue: packet write small-buffer failure could zero caller body bytes instead of preserving output.
- 2026-05-15: Verified the Task 6 quality finding against `src/packet.c`; dispatched a focused fix for `src/packet.c` and `tests/test_packet.c`.
- 2026-05-15: Task 6 quality fix completed in commit `c62906d`; focused packet test passed and the Makefile-driven ASAN/UBSAN test target exited 0.
- 2026-05-15: Task 6 quality re-review confirmed the packet fix; reviewer also noted the cumulative `d5310a8..c62906d` range includes known Task 7 prefix/hashmap work, so Task 6 is closed on the packet-file findings and Task 7 review will cover those changes.
- 2026-05-15: Reviewed Task 7 dirty prefix follow-up edits; marker memcmp was already present in current `src/packet.c`.
- 2026-05-15: Ran `rtk make CFLAGS_EXTRA="-O2 -g -fsanitize=address,undefined" test TESTS=prefix`; target exited 0 and appeared to run the full suite.
- 2026-05-15: Committed Task 7 prefix follow-up as `59719a5` (`test(prefix): strengthen cidr_to_mask coverage`).
- 2026-05-15: Task 7 spec compliance review passed; reviewer also reported ASAN/UBSAN test and bench exited 0.
- 2026-05-15: Task 7 quality review found Important issues: hashmap bitmask invariant only documented, and hand-written cidr lookup table lacked all-0..32 oracle coverage.
- 2026-05-15: Applied Task 7 quality fixes: added hashmap power-of-two helper/assert/resize guard and changed cidr_to_mask test to loop over every CIDR 0..32.
- 2026-05-15: First ASAN/UBSAN verification attempt failed while opening a generated dependency file during `test_fsm` compilation, likely due to current dirty Makefile rebuild behavior; immediate rerun passed.
- 2026-05-15: Full ASAN/UBSAN test passed on rerun; benchmark passed.
- 2026-05-15: Committed Task 7 quality fixes as `28829c2` (`fix(perf): enforce hashmap bucket invariant`).
- 2026-05-15: Task 7 quality re-review passed with no Critical/Important/Minor issues; reviewer also ran strict C11/pedantic/Werror test successfully.
- 2026-05-15: Read Task 8 plan text and confirmed current worktree has unrelated dirty `Doxyfile`, `Makefile`, `README.md`, `examples/README.md`, untracked example files, `.codex/`, `test-run.log`, and `progress.md`.
- 2026-05-15: Dispatched Task 8 implementer for RIB/FSM insert/withdraw track-best optimization and benchmark.
- 2026-05-15: Task 8 implementer completed commit `46381ab`; changed `src/fsm.c`, RIB internals, `tests/test_rib.c`, and `bench/bench.c`; reported RIB/FSM focused tests, full ASAN/UBSAN test, and benchmark passed.
- 2026-05-15: Task 8 spec compliance review passed; reviewer also ran ASAN/UBSAN test and benchmark successfully.
- 2026-05-15: Task 8 quality review found Important issues: `change.best` borrowed pointers are cloned after RIB lock release, weakening THREADSAFE behavior; save-aware RIB helper/rollback paths lack targeted tests.
- 2026-05-15: Verified the borrowed-pointer concern against `src/rib4.c` and `src/fsm.c`; sending fixes back to Task 8 implementer.
- 2026-05-15: Task 8 quality fixes completed in commit `59304ea`; implementer reports owned best-route snapshots cloned under RIB lock, IPv4/IPv6 save-aware tests, benchmark clamp, full ASAN/UBSAN test pass, and benchmark pass.
- 2026-05-15: Task 8 quality re-review passed with no Critical/Important/Minor issues; reviewer confirmed under-lock owned snapshots, no clones on `NO_BEST_CHANGE`, targeted IPv4/IPv6 tests, and benchmark clamp.
- 2026-05-15: Read Task 9 plan text and noted AS_PATH ownership also appears in `src/update.c`; dispatched Task 9 implementer scoped to `src/pattr.c` and `tests/test_pattr.c`.
- 2026-05-15: Task 9 implementer stopped with NEEDS_CONTEXT after focused pattr tests passed but full ASAN/UBSAN failed: parsed contiguous AS_PATH flowed into `src/update.c`, whose free helper still freed per-segment `asns`.
- 2026-05-15: Verified Task 9 root cause: AS_PATH public struct has no ownership flag, and `update_free_as_path_segments()` needed the same contiguous-block ownership convention.
- 2026-05-15: Authorized minimal Task 9 scope expansion to `src/update.c` and `src/internal.h` for shared internal AS_PATH free/layout helpers.
- 2026-05-15: Task 9 completed in commit `e5078d1`; implementer reports ASAN/UBSAN full test and benchmark passed.
- 2026-05-15: Task 9 spec review found two issues: test fixture encoded 65012 instead of requested 65020, and contiguous ownership was inferred from pointer layout rather than explicit internal ownership tracking.
- 2026-05-15: Verified the Task 9 spec findings; sending fixes back to implementer with direction to use private internal contiguous-block tracking without public ABI changes.
- 2026-05-15: Task 9 spec fixes completed in commit `2f61d6c`; implementer reports corrected fixture/assertions, explicit internal contiguous-block registry, manual-layout regression test, full ASAN/UBSAN test pass, benchmark pass, and THREADSAFE=1 pattr test pass.
- 2026-05-15: Task 9 spec re-review passed; reviewer also ran default test, ASAN/UBSAN test, bench, and THREADSAFE=1 pattr test successfully.
- 2026-05-15: Task 9 quality review passed with no Critical/Important issues; minor note left for future documentation of `bgp_as_path_segments_free` ownership contract.
- 2026-05-15: Read Task 10 plan text and current event publish implementation; dispatched Task 10 implementer for stack snapshot optimization.
- 2026-05-15: Task 10 implementer completed commit `47760d6`; changed `src/event.c` and `tests/test_event.c`; reported default test and ASAN/UBSAN test passed.
- 2026-05-15: Noted committed `1f0ccbf` build/example update appears between Task 9 and Task 10 in history; Task 10 reviews will use `1f0ccbf..47760d6` to keep scope clean.
- 2026-05-15: Task 10 spec compliance review passed; reviewer independently ran default test and ASAN/UBSAN test successfully.
- 2026-05-15: Task 10 quality review found no code defects but requested a heap snapshot allocation-failure regression for `match_count > 64`.
- 2026-05-15: Task 10 quality fix completed in commit `41dbf0e`; added heap allocation-failure test plus 64/65 boundary tests; focused event test and ASAN/UBSAN full test passed.
- 2026-05-15: Resumed execution using `superpowers:subagent-driven-development`; dispatched Task 10 quality re-review for range `1f0ccbf..41dbf0e`.
- 2026-05-15: Task 10 quality re-review passed; reviewer ran default test, ASAN/UBSAN test, THREADSAFE=1 test, and diff check successfully. Task 10 completed.
- 2026-05-15: Preparing Task 11; noted plan's example says first-match-wins, but current code/tests preserve last-match-wins semantics, so Task 11 must optimize without semantic change.
- 2026-05-15: Task 11 implementer completed commit `491f47f`; reported ASAN/UBSAN full test pass, bench build pass, and reduced-count filter benchmark run.
- 2026-05-15: Dispatched Task 11 spec compliance review for range `41dbf0e..491f47f`.
- 2026-05-15: Task 11 spec review found attr-view semantic drift for duplicate attrs, AS_PATH/AS4_PATH origin ordering, and malformed first duplicate masking later valid attrs; verified findings. Match-type bucketing remains out of scope because the plan gives no concrete storage/bucketing requirements and preserving last-match-wins would require a larger redesign.
- 2026-05-15: Sent Task 11 spec fixes back to implementer: preserve old linear-scan semantics on duplicate attrs and AS_PATH/AS4 origin-order cases while retaining attr-view fast path where semantically safe; add regression tests.
- 2026-05-15: Task 11 spec fixes completed in commit `83ad6d1`; implementer reports focused filter test, full ASAN/UBSAN test, and benchmark passed.
- 2026-05-15: Dispatched Task 11 spec re-review for cumulative range `41dbf0e..83ad6d1`.
- 2026-05-15: Task 11 spec re-review passed; reviewer also ran focused filter and benchmark builds with Werror plus diff check.
- 2026-05-15: Task 11 quality review found Important issues: filter benchmark default route matches generated `/8` rules and exits early, and attr-view fast path keys by public `type_code` where old filter semantics used public `type`; also noted minor null-filter short-circuit ordering and IPv6 duplicate coverage.
- 2026-05-15: Verified Task 11 quality findings and dispatched fixes back to implementer.
- 2026-05-15: Task 11 quality fixes completed in commit `c185afb`; implementer reports stale `type_code` fallback, benchmark no-match fix, null-filter short-circuit restoration, IPv6 duplicate coverage, focused filter test, full ASAN/UBSAN test, and benchmark passed.
- 2026-05-15: Dispatched Task 11 quality re-review for cumulative range `41dbf0e..c185afb`.
- 2026-05-15: Task 11 quality re-review passed with no Critical/Important/Minor issues; reviewer ran focused filter test and benchmark build/smoke with Werror. Task 11 completed.
- 2026-05-15: Dispatched Task 12 implementer for sink delayed compact and fragmented/chunk feed benchmark.
- 2026-05-15: Task 12 implementer completed commit `8d03426` with concern: new chunk feed benchmark shows relative chunking cost but does not strongly exercise delayed compact; full ASAN/UBSAN test and benchmark passed.
- 2026-05-15: Reviewed Task 12 diff; concern appears benchmark-specific because exact packet chunk feed usually drains buffered bytes and resets offset. Dispatched Task 12 spec review to decide whether additional delayed-compact benchmark coverage is required.
- 2026-05-15: Task 12 spec review passed; reviewer confirmed chunk benchmarks, existing fragmented memmove benchmark coverage, delayed compact logic, overflow guards, and touched file scope.
- 2026-05-15: Dispatched Task 12 code quality review for range `c185afb..8d03426`.
- 2026-05-15: Task 12 quality review passed with no Critical/Important issues; minor note about documenting white-box test layout coupling accepted as non-blocking. Task 12 completed.
- 2026-05-15: Preparing Task 13; noted current hashmap resizes at 75% load, so `bgp_hashmap_reserve(count)` should allocate enough buckets to insert `count` entries without immediately resizing.
