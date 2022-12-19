#include "../nanolog.h"
#include "doctest.h"

#include <cstring>
#include <string>
#include <vector>

TEST_CASE("nanolog_set_threshold") {
  REQUIRE(nanolog_set_threshold(99999) == NANOLOG_RET_ERR_BAD_ARG);
  REQUIRE(nanolog_set_threshold(NL_SEV_DEBUG) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_set_threshold(NL_SEV_INFO) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_set_threshold(NL_SEV_WARNING) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_set_threshold(NL_SEV_ERROR) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_set_threshold(NL_SEV_CRITICAL) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_set_threshold(NL_SEV_ASSERT) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_set_threshold(NL_SEV_ASSERT + 1) == NANOLOG_RET_ERR_BAD_ARG);
}

TEST_CASE("nanolog_get_threshold") {
  REQUIRE(nanolog_set_threshold(NL_SEV_ASSERT) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_get_threshold() == NL_SEV_ASSERT);
  REQUIRE(nanolog_set_threshold(NL_SEV_CRITICAL) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_get_threshold() == NL_SEV_CRITICAL);
  REQUIRE(nanolog_set_threshold(NL_SEV_ERROR) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_get_threshold() == NL_SEV_ERROR);
  REQUIRE(nanolog_set_threshold(NL_SEV_WARNING) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_get_threshold() == NL_SEV_WARNING);
  REQUIRE(nanolog_set_threshold(NL_SEV_INFO) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_get_threshold() == NL_SEV_INFO);
  REQUIRE(nanolog_set_threshold(NL_SEV_DEBUG) == NANOLOG_RET_SUCCESS);
  REQUIRE(nanolog_get_threshold() == NL_SEV_DEBUG);
}

TEST_CASE("nanolog_set_handler") {
  static int s_calls{0};
  REQUIRE(nanolog_set_handler([](void *, unsigned, char const *, va_list) { ++s_calls; })
          == NANOLOG_RET_SUCCESS);
  nanolog_log_sev("", NL_SEV_ASSERT);
  REQUIRE(s_calls == 1);
}

TEST_CASE("nanolog_fmt_is_binary") {
  int binary{9999};
  REQUIRE(nanolog_fmt_is_binary(nullptr, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
  REQUIRE(nanolog_fmt_is_binary(nullptr, &binary) == NANOLOG_RET_ERR_BAD_ARG);
  REQUIRE(nanolog_fmt_is_binary("hello", nullptr) == NANOLOG_RET_ERR_BAD_ARG);

  static_assert(NL_BINARY_LOG_MARKER == 0x1F);

  SUBCASE("empty string is not binary") {
    REQUIRE(nanolog_fmt_is_binary("", &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 0);
  }

  SUBCASE("1f is binary") {
    REQUIRE(nanolog_fmt_is_binary("\x1f", &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 1);
  }

  SUBCASE("ascii is not binary") {
    REQUIRE(nanolog_fmt_is_binary("hello", &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 0);
  }

  SUBCASE("leading 1f is binary") {
    REQUIRE(nanolog_fmt_is_binary("\x1f" "more stuff", &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 1);
  }

  SUBCASE("1f after ascii is not binary") {
    REQUIRE(nanolog_fmt_is_binary("stuff\x1f", &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 0);
  }
}

TEST_CASE("nanolog_log_sev") {
  static std::string *s_fmt{new std::string()};
  static unsigned s_sev{12345};
  REQUIRE(nanolog_set_handler([](void *, unsigned sev, char const *fmt, va_list) {
    *s_fmt=std::string{fmt}; s_sev=sev; }) == NANOLOG_RET_SUCCESS);
  nanolog_log_sev("logging is fun", NL_SEV_WARNING);
  REQUIRE(*s_fmt == "logging is fun");
  REQUIRE_EQ(s_sev, NL_SEV_WARNING | NL_DYNAMIC_SEV_BIT);
  delete s_fmt;
  s_fmt = nullptr;
}

TEST_CASE("nanolog_log_sev_ctx") {
  struct Log { std::string fmt; unsigned sev; };
  std::vector<Log> captures;
  REQUIRE(nanolog_set_handler(
    [](void *ctx, unsigned sev, char const *fmt, va_list) {
      static_cast<std::vector<Log>*>(ctx)->emplace_back(Log{ .fmt=fmt, .sev=sev });
    }) == NANOLOG_RET_SUCCESS);

  SUBCASE("marks severity as dynamic") {
    nanolog_log_sev_ctx("hello", NL_SEV_ERROR, &captures);
    REQUIRE(captures.size() == 1);
    REQUIRE(captures[0].fmt == "hello");
    REQUIRE_EQ(captures[0].sev, NL_SEV_ERROR | NL_DYNAMIC_SEV_BIT);
  }
}

TEST_CASE("nanolog_varint_decode") {
  unsigned val = 99999999;

  SUBCASE("bad args") {
    unsigned char c;
    REQUIRE(nanolog_varint_decode(nullptr, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_decode(nullptr, &val) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_decode(&c, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
  }

  SUBCASE("zero") {
    unsigned char const buf[] = { 0 };
    REQUIRE(nanolog_varint_decode(buf, &val) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 0);
  }

  SUBCASE("stops at first byte that doesn't have high bit set") {
    unsigned char const buf[] = { 0x01, 0xFF };
    REQUIRE(nanolog_varint_decode(buf, &val) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 1);
  }

  SUBCASE("one byte less than 127") {
    unsigned char const buf[] = { 79 };
    REQUIRE(nanolog_varint_decode(buf, &val) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 79);
  }

  SUBCASE("127 is the largest single-byte value") {
    unsigned char const buf[] = { 0x7F };
    REQUIRE(nanolog_varint_decode(buf, &val) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 127);
  }

  SUBCASE("128 is the smallest two-byte value") {
    unsigned char const buf[] = { 0x81, 0x00 };
    REQUIRE(nanolog_varint_decode(buf, &val) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 128);
  }

  SUBCASE("two bytes greater than 128") {
    unsigned char const buf[] = { 0xAA, 0x45 };
    REQUIRE(nanolog_varint_decode(buf, &val) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 5445);
  }
}

TEST_CASE("nanolog_varint_encode") {
  char buf[16];
  memset(buf, 0, sizeof(buf));
  unsigned len;

  SUBCASE("bad args") {
    REQUIRE(nanolog_varint_encode(0, nullptr, 0, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_encode(0, buf, 0, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_encode(0, buf, sizeof(buf), nullptr) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_encode(0, buf, 0, &len) == NANOLOG_RET_ERR_BAD_ARG);
  }

  SUBCASE("exhaustion") {
    REQUIRE(nanolog_varint_encode(1u << 7, buf, 1, &len) == NANOLOG_RET_ERR_EXHAUSTED);
    REQUIRE(nanolog_varint_encode(1u << 14, buf, 2, &len) == NANOLOG_RET_ERR_EXHAUSTED);
    REQUIRE(nanolog_varint_encode(1u << 21, buf, 3, &len) == NANOLOG_RET_ERR_EXHAUSTED);
    REQUIRE(nanolog_varint_encode(1u << 28, buf, 4, &len) == NANOLOG_RET_ERR_EXHAUSTED);
  }
}

TEST_CASE("nanolog_parse_binary_log") {
  struct BinaryLog { nl_arg_type_t type; std::vector<unsigned char> payload; };
  nanolog_handler_cb_t const old_handler{nanolog_get_handler()};

  nanolog_set_handler([](void *ctx, unsigned sev, char const *fmt, va_list args) {
    int binary;
    REQUIRE(nanolog_fmt_is_binary(fmt, &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 1);
    REQUIRE(nanolog_parse_binary_log(
      [](void *ctx_, nl_arg_type_t type, void const *p, unsigned len) {
        auto const *pc{static_cast<unsigned char const *>(p)};
        static_cast<std::vector<BinaryLog>*>(ctx_)->emplace_back(
          BinaryLog{.type=type, .payload=std::vector<unsigned char>(pc, pc+len)});
      }, ctx, sev, fmt, args) == NANOLOG_RET_SUCCESS);
  });

  std::vector<BinaryLog> logs;

  SUBCASE("empty binlog emits start, guid, end") {
    char const payload[] = { NL_BINARY_LOG_MARKER, 75, NL_ARG_TYPE_LOG_END };
    nanolog_log_debug_ctx(payload, &logs);
    REQUIRE(logs.size() == 3);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[1].payload.size() == 1);
    REQUIRE(logs[1].payload[0] == 75);
    REQUIRE(logs[2].type == NL_ARG_TYPE_LOG_END);
  }

  nanolog_set_handler(old_handler);
}

