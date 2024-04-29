BUILD_DIR := build
OS := $(shell uname)
COMPILER_VERSION := $(shell $(CXX) --version)

# ----- Unclog lib (for testing)

LIBUNCLOG_LIB := $(BUILD_DIR)/libunclog.a
LIBUNCLOG_SRCS := \
	unclog/emit.cc \
	unclog/elf.cc \
	unclog/thumb2.cc \
	unclog/thumb2_inst.cc \
	nanolog.c

# ----- Unclog tool

UNCLOG_BIN := $(BUILD_DIR)/bin/unclog
UNCLOG_SRCS := unclog/args.cc unclog/unclog.cc

# ----- Runtime unit tests

TESTS_STAMP := $(BUILD_DIR)/nanolog_tests.timestamp
TESTS_BIN := $(BUILD_DIR)/nanolog_tests
TESTS_SRCS := tests/unittest_main.cc tests/test_nanolog.cc nanolog.c

# ----- Compiler flags

ifeq 'Darwin' '$(OS)'
AR := libtool -static -o
else
AR := ar rcs
endif

CFLAGS = --std=c17 -fexceptions
CXXFLAGS = --std=c++20
CPPFLAGS += -MMD -MP
#CPPFLAGS += -O0 -g3
CPPFLAGS += -Os -g
CPPFLAGS += -Werror -Wall -Wextra

ifneq '' '$(findstring clang,$(COMPILER_VERSION))'
CFLAGS += -Wno-declaration-after-statement

CPPFLAGS += -Weverything \
			-Wno-unknown-warning-option \
			-Wno-poison-system-directories \
			-Wno-format-pedantic \
			-Wno-unsafe-buffer-usage \
			-Wno-switch-default

CXXFLAGS += -Wno-c++98-compat-pedantic \
			-Wno-gnu-zero-variadic-macro-arguments \
			-Wno-missing-prototypes \
			-Wno-old-style-cast \
			-Wno-covered-switch-default \
			-Wno-switch-enum \
			-Wno-cast-align \
			-Wno-unused-function \
			-Wno-c++98-compat
else
CPPFLAGS += -Wconversion
endif
CPPFLAGS += -Wno-padded

# ----- Targets and rules

$(BUILD_DIR)/%.c.o: %.c Makefile
	mkdir -p $(dir $@) && $(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.cc.o: %.cc Makefile
	mkdir -p $(dir $@) && $(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

LIBUNCLOG_OBJS := $(LIBUNCLOG_SRCS:%=$(BUILD_DIR)/%.o)
$(LIBUNCLOG_LIB): $(LIBUNCLOG_OBJS)
	mkdir -p $(dir $@) && $(AR) $@ $(LIBUNCLOG_OBJS)

UNCLOG_OBJS := $(UNCLOG_SRCS:%=$(BUILD_DIR)/%.o)
$(UNCLOG_BIN): $(UNCLOG_OBJS) $(LIBUNCLOG_LIB) Makefile
	mkdir -p $(dir $@) && $(CXX) $(LDFLAGS) $(UNCLOG_OBJS) $(LIBUNCLOG_LIB) -o $@ && strip $@

TESTS_OBJS := $(TESTS_SRCS:%=$(BUILD_DIR)/%.o)
$(TESTS_BIN): $(TESTS_OBJS) $(LIBUNCLOG_LIB) Makefile
	mkdir -p $(dir $@) && $(CXX) $(LDFLAGS) $(TESTS_OBJS) $(LIBUNCLOG_LIB) -o $@

$(TESTS_STAMP): $(TESTS_BIN)
	$(TESTS_BIN) -m && touch $(TESTS_STAMP)

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

all: $(TESTS_STAMP) $(UNCLOG_BIN)
.DEFAULT_GOAL := all

-include $(UNCLOG_OBJS:.o=.d)
-include $(LIBUNCLOG_OBJS:.o=.d)
-include $(TESTS_OBJS:.o=.d)
