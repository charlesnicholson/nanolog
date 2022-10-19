BUILD_DIR := build
OS := $(shell uname)

UNCLOG_SRCS := unclog/unclog.cc \
			   unclog/nl_elf.cc \
			   unclog/nl_thumb2.cc \
			   unclog/nl_thumb2_inst.cc \
			   nanolog.c

UNCLOG_OBJS := $(UNCLOG_SRCS:%=$(BUILD_DIR)/%.o)
UNCLOG_DEPS := $(UNCLOG_OBJS:.o=.d)

ifdef NANOLOG_VERBOSE
CPPFLAGS += -DNANOLOG_VERBOSE
endif
CPPFLAGS += -DNANOLOG_NO_SECTIONS

CFLAGS = --std=c17
CXXFLAGS = --std=c++20

CPPFLAGS += -MMD -MP -Os -flto -g
#CPPFLAGS += -Werror -Wall -Wextra

ifeq ($(OS),Darwin)
CPPFLAGS += -Weverything
endif

CPPFLAGS += -Wno-c++98-compat -Wno-padded

ifeq ($(OS),Darwin)
CPPFLAGS += -Wno-poison-system-directories -Wno-format-pedantic
CXXFLAGS += -Wno-c++98-compat-pedantic \
			-Wno-gnu-zero-variadic-macro-arguments \
			-Wno-missing-prototypes \
			-Wno-old-style-cast \
			-Wno-covered-switch-default \
			-Wno-switch-enum \
			-Wno-cast-align \
			-Wno-unused-function
endif

LDFLAGS = -flto

$(BUILD_DIR)/bin/unclog: $(UNCLOG_OBJS) Makefile
	mkdir -p $(dir $@) && $(CXX) $(LDFLAGS) $(UNCLOG_OBJS) -o $@

$(BUILD_DIR)/%.c.o: %.c Makefile
	mkdir -p $(dir $@) && $(CC) $(CPPFLAGS) $(CFLAGS) -x c -c $< -o $@

$(BUILD_DIR)/%.cc.o: %.cc Makefile
	mkdir -p $(dir $@) && $(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

.DEFAULT_GOAL := $(BUILD_DIR)/bin/unclog

-include $(UNCLOG_DEPS)

