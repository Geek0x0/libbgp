CC ?= gcc
AR ?= ar
PREFIX ?= /usr/local
THREADSAFE ?= 0

BUILD_ROOT := build
BUILD_DIR := $(BUILD_ROOT)/threadsafe-$(THREADSAFE)
FLAG_STAMP := $(BUILD_DIR)/.flags
FLAG_STAMP_TMP := $(BUILD_ROOT)/.flags.threadsafe-$(THREADSAFE).tmp
LIB_NAME := bgp
STATIC_LIB := $(BUILD_DIR)/lib$(LIB_NAME).a
SHARED_LIB := $(BUILD_DIR)/lib$(LIB_NAME).so
STATIC_LIB_ALIAS := $(BUILD_ROOT)/lib$(LIB_NAME).a
SHARED_LIB_ALIAS := $(BUILD_ROOT)/lib$(LIB_NAME).so

PUBLIC_HEADERS := $(wildcard include/libbgp/*.h)

CPPFLAGS_BASE := -Iinclude -DLIBBGP_SHARED
CFLAGS_BASE := -std=c11 -Wall -Wextra -pedantic -fPIC -fvisibility=hidden -MMD -MP
CFLAGS_EXTRA ?=
LDFLAGS_EXTRA ?=

ifeq ($(THREADSAFE),1)
CPPFLAGS_BASE += -DBGP_THREADSAFE
LDFLAGS_EXTRA += -pthread
endif

CFLAGS = $(CFLAGS_BASE) $(CFLAGS_EXTRA)
CPPFLAGS := $(CPPFLAGS_BASE)
export FLAG_STAMP_CONTENT

define FLAG_STAMP_CONTENT
CC=$(CC)
CPPFLAGS=$(CPPFLAGS)
CFLAGS=$(CFLAGS)
LDFLAGS_EXTRA=$(LDFLAGS_EXTRA)
endef

LIB_SRCS := src/alloc.c src/errcode.c src/log.c src/prefix4.c src/prefix6.c src/capability.c src/pattr.c \
	src/open.c src/keepalive.c src/notification.c src/update.c src/packet.c \
	src/hashmap.c src/radix4.c src/radix6.c src/rib4.c src/rib6.c src/filter.c src/event.c src/sink.c src/out_handler.c \
	src/fsm.c
LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD_DIR)/%.o)

TEST_SUPPORT := tests/test_main.c tests/fixtures/alloc_tracker.c
TEST_COMMON_OBJS := $(TEST_SUPPORT:%.c=$(BUILD_DIR)/%.o)

TEST_SRCS := $(filter-out tests/test_main.c,$(wildcard tests/test_*.c))
TEST_OBJS := $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
TEST_BINS := $(TEST_SRCS:tests/%.c=$(BUILD_DIR)/tests/%)

EXAMPLE_SRCS := examples/peer_and_print.c examples/route_server.c
EXAMPLE_OBJS := $(EXAMPLE_SRCS:%.c=$(BUILD_DIR)/%.o)
EXAMPLE_BINS := $(EXAMPLE_SRCS:examples/%.c=$(BUILD_DIR)/examples/%)

BENCH_SRCS := bench/bench.c
BENCH_OBJS := $(BENCH_SRCS:%.c=$(BUILD_DIR)/%.o)
BENCH_BINS := $(BENCH_SRCS:bench/%.c=$(BUILD_DIR)/bench/%)

DEPS := $(LIB_OBJS:.o=.d) $(TEST_COMMON_OBJS:.o=.d) $(TEST_OBJS:.o=.d) $(EXAMPLE_OBJS:.o=.d) $(BENCH_OBJS:.o=.d)

.PHONY: all clean test bench install headers examples symbol-check verify release-check FORCE
.SECONDARY: $(TEST_OBJS) $(TEST_COMMON_OBJS) $(EXAMPLE_OBJS) $(BENCH_OBJS)

all: $(STATIC_LIB) $(SHARED_LIB) $(STATIC_LIB_ALIAS) $(SHARED_LIB_ALIAS)

$(BUILD_ROOT):
	mkdir -p $(BUILD_ROOT)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(FLAG_STAMP): FORCE | $(BUILD_DIR)
	@printf '%s\n' "$$FLAG_STAMP_CONTENT" > $(FLAG_STAMP_TMP); \
	if ! test -f $@ || ! cmp -s $(FLAG_STAMP_TMP) $@; then mv $(FLAG_STAMP_TMP) $@; else rm $(FLAG_STAMP_TMP); fi

$(BUILD_DIR)/%.o: %.c $(FLAG_STAMP)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(LIB_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $(LIB_OBJS)

$(SHARED_LIB): $(LIB_OBJS) | $(BUILD_DIR)
	$(CC) -shared $(LIB_OBJS) $(LDFLAGS_EXTRA) -o $@

$(STATIC_LIB_ALIAS): $(STATIC_LIB) | $(BUILD_ROOT)
	cp $< $@

$(SHARED_LIB_ALIAS): $(SHARED_LIB) | $(BUILD_ROOT)
	cp $< $@

$(BUILD_DIR)/tests/%: $(BUILD_DIR)/tests/%.o $(TEST_COMMON_OBJS) $(STATIC_LIB)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(TEST_COMMON_OBJS) $(STATIC_LIB) $(LDFLAGS_EXTRA) -o $@

$(BUILD_DIR)/examples/%: $(BUILD_DIR)/examples/%.o $(STATIC_LIB)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(STATIC_LIB) $(LDFLAGS_EXTRA) -o $@

$(BUILD_DIR)/bench/%: $(BUILD_DIR)/bench/%.o $(STATIC_LIB)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(STATIC_LIB) $(LDFLAGS_EXTRA) -o $@

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do $$t; done

bench: CFLAGS_EXTRA += -O2 -g -fno-omit-frame-pointer
bench: $(BENCH_BINS)
	@echo "Running benchmarks with -O2 -g -fno-omit-frame-pointer"
	$(BUILD_DIR)/bench/bench

examples: $(EXAMPLE_BINS)

symbol-check: all
	@bad_static="$$(nm -g $(STATIC_LIB) | awk '$$2 ~ /^[TDB]$$/ && $$3 !~ /^(libbgp_|bgp_)/ {print}')"; \
	bad_private_static="$$(nm -g $(STATIC_LIB) | awk '$$2 ~ /^[TDB]$$/ && $$3 ~ /^libbgp_rib[46]_(saved_route|insert_save|withdraw_exact|restore_saved|exact_update)/ {print}')"; \
	bad_shared="$$(nm -D --defined-only $(SHARED_LIB) | awk '$$2 ~ /^[TDB]$$/ && $$3 !~ /^libbgp_/ {print}')"; \
	if test -n "$$bad_static" || test -n "$$bad_private_static" || test -n "$$bad_shared"; then \
		if test -n "$$bad_static"; then printf '%s\n%s\n' "Unexpected static symbols:" "$$bad_static"; fi; \
		if test -n "$$bad_private_static"; then printf '%s\n%s\n' "Private RIB helpers use public prefix:" "$$bad_private_static"; fi; \
		if test -n "$$bad_shared"; then printf '%s\n%s\n' "Unexpected shared symbols:" "$$bad_shared"; fi; \
		exit 1; \
	fi

verify:
	$(MAKE) clean
	$(MAKE) all
	$(MAKE) headers
	$(MAKE) test
	$(MAKE) THREADSAFE=1 test
	$(MAKE) CFLAGS_EXTRA="-fsanitize=address,undefined -g" LDFLAGS_EXTRA="-fsanitize=address,undefined" test
	$(MAKE) examples
	$(MAKE) symbol-check

release-check: verify

headers: all
	@set -e; for h in $(PUBLIC_HEADERS); do \
		printf '#include <%s>\nint main(void){return 0;}\n' "$${h#include/}" > $(BUILD_DIR)/header_test.c; \
		$(CC) -Iinclude $(CPPFLAGS) $(CFLAGS) $(BUILD_DIR)/header_test.c -c -o $(BUILD_DIR)/header_test.o; \
	done

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/include/libbgp $(DESTDIR)$(PREFIX)/lib
	cp -R include/libbgp/*.h $(DESTDIR)$(PREFIX)/include/libbgp/
	cp $(STATIC_LIB) $(SHARED_LIB) $(DESTDIR)$(PREFIX)/lib/

clean:
	rm -rf $(BUILD_ROOT)

FORCE:

-include $(DEPS)
