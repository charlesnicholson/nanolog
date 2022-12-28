#include "../nanolog.h"
#include "../unclog/boilerplate.h"

#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS
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
  static std::string *s_fmt; std::string fmt; s_fmt = &fmt;
  static unsigned s_sev{12345};
  REQUIRE(nanolog_set_handler([](void *, unsigned sev, char const *fmt_, va_list) {
    *s_fmt=fmt_; s_sev=sev; }) == NANOLOG_RET_SUCCESS);
  nanolog_log_sev("logging is fun", NL_SEV_WARNING);
  REQUIRE(fmt == "logging is fun");
  REQUIRE_EQ(s_sev, NL_SEV_WARNING | NL_DYNAMIC_SEV_BIT);
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
  unsigned val = 99999999, len = 99999999;

  SUBCASE("bad args") {
    unsigned char c;
    REQUIRE(nanolog_varint_decode(nullptr, nullptr, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_decode(nullptr, nullptr, &len) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_decode(nullptr, &val, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
    REQUIRE(nanolog_varint_decode(&c, nullptr, nullptr) == NANOLOG_RET_ERR_BAD_ARG);
  }

  SUBCASE("zero") {
    unsigned char const buf[] = { 0 };
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 0);
    REQUIRE(len == 1);
  }

  SUBCASE("stops at first byte that doesn't have high bit set") {
    unsigned char const buf[] = { 0x01, 0xFF };
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 1);
    REQUIRE(len == 1);
  }

  SUBCASE("one byte less than 127") {
    unsigned char const buf[] = { 79 };
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 79);
    REQUIRE(len == 1);
  }

  SUBCASE("127 is the largest single-byte value") {
    unsigned char const buf[] = { 0x7F };
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 127);
    REQUIRE(len == 1);
  }

  SUBCASE("128 is the smallest two-byte value") {
    unsigned char const buf[] = { 0x81, 0x00 };
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 128);
    REQUIRE(len == 2);
  }

  SUBCASE("two bytes greater than 128") {
    unsigned char const buf[] = { 0xAA, 0x45 };
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == 5445);
    REQUIRE(len == 2);
  }
}

TEST_CASE("nanolog_varint_encode") {
  byte buf[16];
  size_t const bufsz{sizeof(buf)};
  memset(buf, 0, sizeof(buf));
  auto len{0u};

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

  buf[0] = buf[1] = 0xFF;

  SUBCASE("zero") {
    REQUIRE(nanolog_varint_encode(0, buf, bufsz, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(len == 1);
    REQUIRE(buf[0] == 0);
  }

  SUBCASE("one") {
    REQUIRE(nanolog_varint_encode(1, buf, bufsz, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(len == 1);
    REQUIRE(buf[0] == 1);
  }

  SUBCASE("single-byte values") {
    for (auto i{0u}; i < 127; ++i) {
      buf[0] = 0xFF; len = 0;
      REQUIRE(nanolog_varint_encode(i, buf, bufsz, &len) == NANOLOG_RET_SUCCESS);
      REQUIRE(len == 1);
      REQUIRE(buf[0] == i);
    }
  }

  SUBCASE("128 is the smallest two-byte encoding") {
    REQUIRE(nanolog_varint_encode(128, buf, bufsz, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(len == 2);
    REQUIRE(buf[0] == 0x81);
    REQUIRE(buf[1] == 0);
  }

  SUBCASE("two bytes greater than 128") {
    REQUIRE(nanolog_varint_encode(5445, buf, bufsz, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(len == 2);
    REQUIRE(buf[0] == 0xAA);
    REQUIRE(buf[1] == 0x45);
  }
}

TEST_CASE("varint round-trip") {
  byte buf[16];
  unsigned len, val;
  for (auto i{0u}; i < 65536u; ++i) {
    REQUIRE(nanolog_varint_encode(i, buf, sizeof(buf), &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(nanolog_varint_decode(buf, &val, &len) == NANOLOG_RET_SUCCESS);
    REQUIRE(val == i);
  }
}

TEST_CASE("zigzag") {
  SUBCASE("nanolog_zigzag_encode") {
    REQUIRE(nanolog_zigzag_encode(0) == 0);
    REQUIRE(nanolog_zigzag_encode(-1) == 1);
    REQUIRE(nanolog_zigzag_encode(1) == 2);
    REQUIRE(nanolog_zigzag_encode(-2) == 3);
    REQUIRE(nanolog_zigzag_encode(2) == 4);
  }

  SUBCASE("nanolog_zigzag_decode") {
    REQUIRE(nanolog_zigzag_decode(0) == 0);
    REQUIRE(nanolog_zigzag_decode(1) == -1);
    REQUIRE(nanolog_zigzag_decode(2) == 1);
    REQUIRE(nanolog_zigzag_decode(3) == -2);
    REQUIRE(nanolog_zigzag_decode(4) == 2);
  }

  SUBCASE("round-trip") {
    for (auto i{-65535}; i < 65536; ++i) {
      REQUIRE(nanolog_zigzag_decode(nanolog_zigzag_encode(i)) == i);
    }
  }
}

void require_varint(void const *payload, unsigned guid) {
  unsigned payload_guid, len;
  REQUIRE(nanolog_varint_decode(payload, &payload_guid, &len) == NANOLOG_RET_SUCCESS);
  REQUIRE(payload_guid == guid);
}

void require_2byte(void const *payload, uint16_t expected) {
  uint16_t actual; memcpy(&actual, payload, sizeof(actual)); REQUIRE(actual == expected);
}

void require_4byte(void const *payload, uint32_t expected) {
  uint32_t actual; memcpy(&actual, payload, sizeof(actual)); REQUIRE(actual == expected);
}

void require_8byte(void const *payload, uint64_t expected) {
  uint64_t actual; memcpy(&actual, payload, sizeof(actual)); REQUIRE(actual == expected);
}

void require_pointer(void const *payload, void *expected) {
  void *actual; memcpy(&actual, payload, sizeof(actual)); REQUIRE(actual == expected);
}

void require_double(void const *payload, double expected) {
  double actual; memcpy(&actual, payload, sizeof(actual));
  REQUIRE(actual == doctest::Approx(expected).epsilon(0.000000001));
}

struct BinaryLog { nl_arg_type_t type; byte_vec payload; };

byte_vec varint_vec(unsigned val) {
  byte buf[32];
  unsigned n{0};
  REQUIRE(nanolog_varint_encode(val, buf, sizeof(buf), &n) == NANOLOG_RET_SUCCESS);
  return byte_vec{buf, buf+n};
}

std::vector<char> make_bin_payload(unsigned guid,
                                   std::vector<BinaryLog> const& contents = {}) {
  char guid_encoded[16];
  unsigned guid_len{0};
  REQUIRE(nanolog_varint_encode(guid, guid_encoded, sizeof(guid_encoded), &guid_len)
    == NANOLOG_RET_SUCCESS);

  std::vector<char> bp;
  bp.emplace_back(char(NL_BINARY_LOG_MARKER));
  bp.insert(std::end(bp), guid_encoded, guid_encoded + guid_len);

  char c{0};
  bool lo{true};
  for (auto const& [type, payload] : contents) {
    c |= char(type) << (lo ? 0 : 4);
    if (!lo || !payload.empty()) { bp.emplace_back(c); c = 0; }
    if (!payload.empty()) {
      bp.insert(bp.end(), payload.begin(), payload.end());
      lo = true;
    } else {
      lo = !lo;
    }
  }
  c |= char(NL_ARG_TYPE_LOG_END << (lo ? 0 : 4));
  bp.emplace_back(c);
  return bp;
}

TEST_CASE("nanolog_parse_binary_log") {
  nanolog_handler_cb_t const old_handler{nanolog_get_handler()};

  nanolog_set_handler([](void *ctx, unsigned sev, char const *fmt, va_list args) {
    int binary;
    REQUIRE(nanolog_fmt_is_binary(fmt, &binary) == NANOLOG_RET_SUCCESS);
    REQUIRE(binary == 1);
    REQUIRE(nanolog_parse_binary_log(
      [](void *ctx_, nl_arg_type_t type, void const *p, unsigned len) {
        auto const *pc{static_cast<unsigned char const *>(p)};
        static_cast<std::vector<BinaryLog>*>(ctx_)->emplace_back(
          BinaryLog{.type=type, .payload=byte_vec(pc, pc+len)});
      }, ctx, sev, fmt, args) == NANOLOG_RET_SUCCESS);
  });

  std::vector<BinaryLog> logs;

  SUBCASE("empty binlog emits start, guid, end") {
    nanolog_log_debug_ctx(make_bin_payload(12345).data(), &logs);
    REQUIRE(logs.size() == 3);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[0].payload.empty());
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    require_varint(logs[1].payload.data(), 12345);
    REQUIRE(logs[2].type == NL_ARG_TYPE_LOG_END);
    REQUIRE(logs[2].payload.empty());
  }

  SUBCASE("1-byte scalar") {
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_SCALAR_1_BYTE, .payload={}}}).data(), &logs, 'f');
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_SCALAR_1_BYTE);
    REQUIRE(logs[2].payload.size() == 1);
    REQUIRE(logs[2].payload[0] == 'f');
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("2-byte scalar") {
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_SCALAR_2_BYTE, .payload={}}}).data(), &logs, 4321);
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_SCALAR_2_BYTE);
    REQUIRE(logs[2].payload.size() == 2);
    require_2byte(logs[2].payload.data(), 4321);
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("4-byte scalar") {
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_SCALAR_4_BYTE, .payload={}}}).data(), &logs, 0x12345678);
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_SCALAR_4_BYTE);
    REQUIRE(logs[2].payload.size() == 4);
    require_4byte(logs[2].payload.data(), 0x12345678);
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("8-byte scalar") {
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_SCALAR_8_BYTE, .payload={}}}).data(), &logs, 0x12345678abcdef12);
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_SCALAR_8_BYTE);
    REQUIRE(logs[2].payload.size() == 8);
    require_8byte(logs[2].payload.data(), 0x12345678abcdef12);
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("pointer") {
    int x; void *p{&x};
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_POINTER, .payload={}}}).data(), &logs, p);
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_POINTER);
    REQUIRE(logs[2].payload.size() == sizeof(void*));
    require_pointer(logs[2].payload.data(), p);
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("double") {
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_DOUBLE, .payload={}}}).data(), &logs, 3.14159265359);
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_DOUBLE);
    REQUIRE(logs[2].payload.size() == sizeof(double));
    require_double(logs[2].payload.data(), 3.14159265359);
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("wint_t") {
    nanolog_log_debug_ctx(make_bin_payload(0, {
      {.type=NL_ARG_TYPE_WINT_T, .payload={}}}).data(), &logs, (wint_t)1234);
    REQUIRE(logs.size() == 4);
    REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
    REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
    REQUIRE(logs[2].type == NL_ARG_TYPE_WINT_T);
    REQUIRE(logs[2].payload.size() == sizeof(wint_t));
    switch (sizeof(wint_t)) {
      case 2: require_2byte(logs[2].payload.data(), 1234); break;
      case 4: require_4byte(logs[2].payload.data(), 1234); break;
      default: REQUIRE_MESSAGE(0, "unsupported size of wint_t: ", sizeof(wint_t));
    }
    REQUIRE(logs[3].type == NL_ARG_TYPE_LOG_END);
  }

  SUBCASE("stars") {
    SUBCASE("field width") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_FIELD_WIDTH_STAR, .payload={}},
        {.type=NL_ARG_TYPE_SCALAR_4_BYTE, .payload={}}}).data(), &logs, 3000, 12345);
      REQUIRE(logs.size() == 5);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_FIELD_WIDTH_STAR);
      require_varint(logs[2].payload.data(), nanolog_zigzag_encode(3000));
      REQUIRE(logs[3].type == NL_ARG_TYPE_SCALAR_4_BYTE);
      require_4byte(logs[3].payload.data(), 12345);
      REQUIRE(logs[4].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("precision") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_PRECISION_STAR, .payload={}},
        {.type=NL_ARG_TYPE_SCALAR_4_BYTE, .payload={}}}).data(), &logs, 4321, 12345);
      REQUIRE(logs.size() == 5);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_PRECISION_STAR);
      require_varint(logs[2].payload.data(), nanolog_zigzag_encode(4321));
      REQUIRE(logs[3].type == NL_ARG_TYPE_SCALAR_4_BYTE);
      require_4byte(logs[3].payload.data(), 12345);
      REQUIRE(logs[4].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("field and precision") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_FIELD_WIDTH_STAR, .payload={}},
        {.type=NL_ARG_TYPE_PRECISION_STAR, .payload={}},
        {.type=NL_ARG_TYPE_SCALAR_4_BYTE, .payload={}}}).data(),
        &logs, 1234, 4321, 12345);
      REQUIRE(logs.size() == 6);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_FIELD_WIDTH_STAR);
      require_varint(logs[2].payload.data(), nanolog_zigzag_encode(1234));
      REQUIRE(logs[3].type == NL_ARG_TYPE_PRECISION_STAR);
      require_varint(logs[3].payload.data(), nanolog_zigzag_encode(4321));
      REQUIRE(logs[4].type == NL_ARG_TYPE_SCALAR_4_BYTE);
      require_4byte(logs[4].payload.data(), 12345);
      REQUIRE(logs[5].type == NL_ARG_TYPE_LOG_END);
    }
  }

  SUBCASE("string") {
    SUBCASE("unspecified length") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_STRING, .payload={}}}).data(), &logs, "hello world");
      REQUIRE(logs.size() == 5);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_STRING_LEN);
      require_varint(logs[2].payload.data(), unsigned(strlen("hello world")));
      REQUIRE(logs[3].type == NL_ARG_TYPE_STRING);
      REQUIRE(std::string{reinterpret_cast<char const *>(logs[3].payload.data()),
                          unsigned(logs[3].payload.size())} == "hello world");
      REQUIRE(logs[4].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("star precision greater than string length") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_PRECISION_STAR, .payload={}},
        {.type=NL_ARG_TYPE_STRING, .payload={}}}).data(), &logs, 50, "hello world");
      REQUIRE(logs.size() == 6);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_PRECISION_STAR);
      require_varint(logs[2].payload.data(), nanolog_zigzag_encode(50));
      REQUIRE(logs[3].type == NL_ARG_TYPE_STRING_LEN);
      require_varint(logs[3].payload.data(), unsigned(strlen("hello world")));
      REQUIRE(logs[4].type == NL_ARG_TYPE_STRING);
      REQUIRE(std::string{reinterpret_cast<char const *>(logs[4].payload.data()),
                          unsigned(logs[4].payload.size())} == "hello world");
      REQUIRE(logs[5].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("star precision smaller than string length") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_PRECISION_STAR, .payload={}},
        {.type=NL_ARG_TYPE_STRING, .payload={}}}).data(), &logs, 5, "hello world");
      REQUIRE(logs.size() == 6);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_PRECISION_STAR);
      require_varint(logs[2].payload.data(), nanolog_zigzag_encode(5));
      REQUIRE(logs[3].type == NL_ARG_TYPE_STRING_LEN);
      require_varint(logs[3].payload.data(), 5);
      REQUIRE(logs[4].type == NL_ARG_TYPE_STRING);
      REQUIRE(std::string{reinterpret_cast<char const *>(logs[4].payload.data()),
                          unsigned(logs[4].payload.size())} == "hello");
      REQUIRE(logs[5].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("negative star precision is ignored when computing local strlen") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_PRECISION_STAR, .payload={}},
        {.type=NL_ARG_TYPE_STRING, .payload={}}}).data(), &logs, -1, "hello world");
      REQUIRE(logs.size() == 6);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_PRECISION_STAR);
      require_varint(logs[2].payload.data(), nanolog_zigzag_encode(-1));
      REQUIRE(logs[3].type == NL_ARG_TYPE_STRING_LEN);
      require_varint(logs[3].payload.data(), unsigned(strlen("hello world")));
      REQUIRE(logs[4].type == NL_ARG_TYPE_STRING);
      REQUIRE(std::string{reinterpret_cast<char const *>(logs[4].payload.data()),
                          unsigned(logs[4].payload.size())} == "hello world");
      REQUIRE(logs[5].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("literal precision greater than string length") {
      auto const bin_payload = make_bin_payload(0, {
        {.type=NL_ARG_TYPE_STRING_PRECISION_LITERAL, .payload=varint_vec(100)},
        {.type=NL_ARG_TYPE_STRING, .payload={}}});
      nanolog_log_debug_ctx(bin_payload.data(), &logs, "hello world");
      REQUIRE(logs.size() == 5);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_STRING_LEN);
      require_varint(logs[2].payload.data(), unsigned(strlen("hello world")));
      REQUIRE(logs[3].type == NL_ARG_TYPE_STRING);
      REQUIRE(std::string{reinterpret_cast<char const *>(logs[3].payload.data()),
                          unsigned(logs[3].payload.size())} == "hello world");
      REQUIRE(logs[4].type == NL_ARG_TYPE_LOG_END);
    }

    SUBCASE("literal precision less than string length") {
      nanolog_log_debug_ctx(make_bin_payload(0, {
        {.type=NL_ARG_TYPE_STRING_PRECISION_LITERAL, .payload=varint_vec(4)},
        {.type=NL_ARG_TYPE_STRING, .payload={}}}).data(), &logs, "hello world");
      REQUIRE(logs.size() == 5);
      REQUIRE(logs[0].type == NL_ARG_TYPE_LOG_START);
      REQUIRE(logs[1].type == NL_ARG_TYPE_GUID);
      REQUIRE(logs[2].type == NL_ARG_TYPE_STRING_LEN);
      require_varint(logs[2].payload.data(), 4);
      REQUIRE(logs[3].type == NL_ARG_TYPE_STRING);
      REQUIRE(std::string{reinterpret_cast<char const *>(logs[3].payload.data()),
                          unsigned(logs[3].payload.size())} == "hell");
      REQUIRE(logs[4].type == NL_ARG_TYPE_LOG_END);
    }
  }

  nanolog_set_handler(old_handler);
}

