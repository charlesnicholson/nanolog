BUILD_DIR := build
OS := $(shell uname)
COMPILER_VERSION := $(shell $(CXX) --version)

UNCLOG_BIN := $(BUILD_DIR)/bin/unclog
UNCLOG_SRCS := unclog/unclog.cc \
			   unclog/args.cc \
			   unclog/elf.cc \
			   unclog/emit.cc \
			   unclog/thumb2.cc \
			   unclog/thumb2_inst.cc \
			   nanolog.c
UNCLOG_OBJS := $(UNCLOG_SRCS:%=$(BUILD_DIR)/%.o)
UNCLOG_DEPS := $(UNCLOG_OBJS:.o=.d)

TESTS_STAMP := $(BUILD_DIR)/nanolog_tests.timestamp
TESTS_BIN := $(BUILD_DIR)/nanolog_tests
TESTS_SRCS := tests/unittest_main.cc nanolog.c
TESTS_OBJS := $(TESTS_SRCS:%=$(BUILD_DIR)/%.o)
TESTS_DEPS := $(TESTS_DEPS:.o=.d)

LDFLAGS = -flto

CPPFLAGS += -DNANOLOG_HOST_TOOL

CFLAGS = --std=c17
CXXFLAGS = --std=c++20

CPPFLAGS += -MMD -MP -g
CPPFLAGS += -Os -flto
CPPFLAGS += -Werror -Wall -Wextra

ifneq '' '$(findstring clang,$(COMPILER_VERSION))'
CPPFLAGS += -Weverything -Wno-poison-system-directories -Wno-format-pedantic
CXXFLAGS += -Wno-c++98-compat-pedantic \
			-Wno-gnu-zero-variadic-macro-arguments \
			-Wno-missing-prototypes \
			-Wno-old-style-cast \
			-Wno-covered-switch-default \
			-Wno-switch-enum \
			-Wno-cast-align \
			-Wno-unused-function \
			-Wno-c++98-compat
CFLAGS += -Wno-declaration-after-statement
else
CPPFLAGS += -Wconversion
endif
CPPFLAGS += -Wno-padded

$(BUILD_DIR)/%.c.o: %.c Makefile
	mkdir -p $(dir $@) && $(CC) $(CPPFLAGS) $(CFLAGS) -x c -c $< -o $@

$(BUILD_DIR)/%.cc.o: %.cc Makefile
	mkdir -p $(dir $@) && $(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(UNCLOG_BIN): $(UNCLOG_OBJS) Makefile
	mkdir -p $(dir $@) && $(CXX) $(LDFLAGS) $(UNCLOG_OBJS) -o $@

$(TESTS_BIN): $(TESTS_OBJS) Makefile
	mkdir -p $(dir $@) && $(CXX) $(LDFLAGS) $(TESTS_OBJS) -o $@

$(TESTS_STAMP): $(TESTS_BIN)
	$(TESTS_BIN) -m && touch $(TESTS_STAMP)

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

all: $(TESTS_STAMP) $(UNCLOG_BIN)
.DEFAULT_GOAL := all

-include $(UNCLOG_DEPS)
-include $(TESTS_DEPS)
