CC ?= gcc
AR ?= ar
PREFIX ?= /usr/local
THREADSAFE ?= 0

BUILD_DIR := build
LIB_NAME := bgp
STATIC_LIB := $(BUILD_DIR)/lib$(LIB_NAME).a
SHARED_LIB := $(BUILD_DIR)/lib$(LIB_NAME).so

PUBLIC_HEADERS := $(wildcard include/libbgp/*.h)

CPPFLAGS_BASE := -Iinclude
CFLAGS_BASE := -std=c11 -Wall -Wextra -pedantic -fPIC
CFLAGS_EXTRA ?=
LDFLAGS_EXTRA ?=

ifeq ($(THREADSAFE),1)
CPPFLAGS_BASE += -DBGP_THREADSAFE
LDFLAGS_EXTRA += -pthread
endif

CFLAGS := $(CFLAGS_BASE) $(CFLAGS_EXTRA)
CPPFLAGS := $(CPPFLAGS_BASE)

LIB_SRCS := src/alloc.c src/errcode.c
LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD_DIR)/%.o)

TEST_SUPPORT := tests/test_main.c tests/fixtures/alloc_tracker.c
TEST_COMMON_OBJS := $(TEST_SUPPORT:%.c=$(BUILD_DIR)/%.o)

TEST_SRCS := tests/test_alloc_log.c
TEST_BINS := $(TEST_SRCS:tests/%.c=$(BUILD_DIR)/tests/%)

.PHONY: all clean test install headers

all: $(STATIC_LIB) $(SHARED_LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(BUILD_DIR) $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(SHARED_LIB): $(BUILD_DIR) $(LIB_OBJS)
	$(CC) -shared $(LIB_OBJS) $(LDFLAGS_EXTRA) -o $@

$(BUILD_DIR)/tests/%: tests/%.c $(TEST_COMMON_OBJS) $(STATIC_LIB)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(TEST_COMMON_OBJS) $(STATIC_LIB) $(LDFLAGS_EXTRA) -o $@

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do $$t; done

headers: all
	@set -e; for h in $(PUBLIC_HEADERS); do \
		printf '#include "%s"\nint main(void){return 0;}\n' "$$h" > $(BUILD_DIR)/header_test.c; \
		$(CC) -I. $(CPPFLAGS) $(CFLAGS) $(BUILD_DIR)/header_test.c -c -o $(BUILD_DIR)/header_test.o; \
	done

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/include/libbgp $(DESTDIR)$(PREFIX)/lib
	cp -R include/libbgp/*.h $(DESTDIR)$(PREFIX)/include/libbgp/
	cp $(STATIC_LIB) $(SHARED_LIB) $(DESTDIR)$(PREFIX)/lib/

clean:
	rm -rf $(BUILD_DIR)
