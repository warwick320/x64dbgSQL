#include <iostream>

#include "core.h"

using xsql::Budget;
using xsql::ExecuteQuery;
using xsql::IDebuggerProvider;
using xsql::Json;
using xsql::State;
namespace {

class Fixture : public IDebuggerProvider {
 public:
  State current{"paused", 5, 1, 42, 9, 0x1010};
  unsigned register_reads = 0;
  bool transition = false;
  State GetState() override { return current; }

  Json ReadRows(std::string_view name, const State& state, Budget&) override {
    if (name == "session")
      return Json::array(
          {Json::array({state.name, state.epoch, state.generation, state.pid,
                        state.tid, state.ip, "x64", 1, 3, 0})});
    if (name == "registers") {
      ++register_reads;
      if (transition)
        ++current.epoch;
      return Json::array({Json::array({9, "rip", 0x1010}),
                          Json::array({9, "rax", 0x20000000000001LL})});
    }
    if (name == "events")
      return Json::array(
          {Json::array({1, 20, 1, "resume", 9, nullptr, nullptr, 10}),
           Json::array({2, 10, 1, "pause", 9, 0x1010, nullptr, 20}),
           Json::array({3, 30, 2, "init", nullptr, nullptr, nullptr, 30})});
    if (name == "modules")
      return Json::array({Json::array(
          {0x1000, 0x1000, 0x1010, "fixture.exe", "C:/fixture.exe"})});
    if (name == "sections")
      return Json::array(
          {Json::array({0x1000, "fixture.exe", ".text", 0x1010, 0x10, 0x50})});
    if (name == "memory_map")
      return Json::array(
          {Json::array({0x1000, 0x1000, 32, 4096, 1, "fixture.exe"})});
    if (name == "labels")
      return Json::array({Json::array({0x1010, "entry", true})});
    if (name == "comments")
      return Json::array({Json::array({0x1010, "fixture stop", true})});
    return Json::array();
  }

  std::vector<std::uint8_t> ReadMemory(std::uint64_t, unsigned size,
                                       Budget&) override {
    return std::vector<std::uint8_t>(size, 0xab);
  }
};

void Check(bool condition, std::string_view message,
           const Json& detail = nullptr) {
  if (!condition)
    throw std::runtime_error(std::string(message) + " " + detail.dump());
}

}  // namespace

int main() {
  try {
    Fixture fixture;
    std::atomic_bool cancelled{false};
    const auto run = [&](const char* sql, int max_rows = 1000,
                         int timeout = 5000) {
      return ExecuteQuery(
          fixture,
          {{"sql", sql}, {"max_rows", max_rows}, {"timeout_ms", timeout}},
          cancelled);
    };
    const auto expect = [&](const char* sql, const char* code) {
      const auto result = run(sql);
      Check(
          !result.at("ok").get<bool>() && result.at("error").at("code") == code,
          std::string("wrong rejection for ") + sql, result);
    };
    const auto empty = run("SELECT 1;");
    Check(empty.at("ok") == true, "select fixture", empty);
    expect("SELECT 1; SELECT 2", "E_PARSE");
    expect("PRAGMA writable_schema", "E_PERM");
    expect("ATTACH ':memory:' AS more", "E_PERM");
    expect("UPDATE labels SET text='none'", "E_PERM");
    expect("SELECT * FROM memory", "E_PREDICATE");
    expect("SELECT * FROM memory(0,4097)", "E_LIMIT");
    auto result = run("SELECT bytes FROM memory(4096,2)");
    Check(result.at("rows").at(0).at(0).at("blob_hex") == "abab",
          "blob encoding", result);
    result = run(
        "SELECT -9223372036854775808, 1.25, NULL, "
        "CAST(X'225C00090AF09F9880' AS TEXT), X'01ABFF00', X''");
    const auto mixed_row = Json::array(
        {{{"int64", "-9223372036854775808"}},
         1.25,
         nullptr,
         std::string("\"\\\0\t\n\xf0\x9f\x98\x80", 9),
         {{"blob_hex", "01abff00"}},
         {{"blob_hex", ""}}});
    Check(result.at("row_count") == 1 && result.at("rows").at(0) == mixed_row,
          "mixed result values preserve position and wire types", result);
    expect("SELECT CAST(X'F09080' AS TEXT)", "E_RESULT_TYPE");
    result = run("SELECT printf('%.*c',32500,'\"') AS payload");
    Check(result.at("row_count") == 1 && result.at("truncated") == false,
          "escaped text within the result budget");
    result = run("SELECT printf('%.*c',32700,'\"') AS payload");
    Check(result.at("row_count") == 0 && result.at("truncated") == true,
          "escaped text beyond the result budget");
    result = run(
        "SELECT a.bytes,b.bytes FROM memory(4096,8) a JOIN memory(4096,8) b");
    Check(result.at("work").at("memory_bytes") == 8 &&
              result.at("work").at("memory_cache_hits") == 1,
          "reused bounded memory read", result);
    result = run(
        "WITH sizes(n) AS (VALUES(1),(3),(2)) "
        "SELECT a.bytes,b.bytes FROM sizes JOIN main.memory(4096,n) a "
        "JOIN memory(8192,1) b ORDER BY n DESC");
    Check(result.at("row_count") == 3 &&
              result.at("rows").at(0).at(0).at("blob_hex") == "ababab" &&
              result.at("rows").at(1).at(0).at("blob_hex") == "abab" &&
              result.at("rows").at(2).at(0).at("blob_hex") == "ab" &&
              result.at("rows").at(0).at(1).at("blob_hex") == "ab",
          "sorted memory results retain bytes from each cursor scan", result);
    expect(
        "WITH RECURSIVE seq(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM seq "
        "WHERE i<17) "
        "SELECT sum(m.size) FROM seq JOIN memory(i*4096,4096) m",
        "E_LIMIT");
    result =
        run("SELECT * FROM registers a JOIN registers b USING(name) ORDER BY "
            "a.name");
    Check(result.at("row_count") == 2 && fixture.register_reads == 1,
          "snapshot reuse", result);
    result = run("SELECT value FROM registers WHERE name='rax'");
    Check(result.at("rows").at(0).at(0).at("int64") == "9007199254740993",
          "lossless integer", result);
    result = run("SELECT module,label,comment FROM stop_context");
    Check(result.at("rows").at(0) ==
              Json::array({"fixture.exe", "entry", "fixture stop"}),
          "stop relation", result);
    result = run("SELECT section,protect FROM image_layout");
    Check(result.at("rows").at(0).at(0) == ".text" &&
              result.at("rows").at(0).at(1).at("int64") == "32",
          "static and runtime join", result);
    result = run("SELECT type,elapsed_ms FROM event_spans ORDER BY seq");
    Check(result.at("rows").at(0).at(1).at("int64") == "10" &&
              result.at("rows").at(1).at(1).is_null(),
          "event gaps use monotonic time and stay within a generation", result);
    result = run("SELECT * FROM registers", 2);
    Check(result.at("truncated") == false, "exact row cap", result);
    result = run("SELECT * FROM registers", 1);
    Check(result.at("truncated") == true && result.at("row_count") == 1,
          "row overflow", result);
    fixture.transition = true;
    expect("SELECT * FROM registers", "E_STATE_CHANGED");
    fixture.transition = false;
    fixture.current.name = "running";
    expect("SELECT * FROM memory(4096,2)", "E_STATE");
    result = run("SELECT count(*) FROM events");
    Check(result.at("ok") == true, "events must be readable while running",
          result);
    constexpr auto expensive =
        "WITH RECURSIVE seq(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM seq "
        "WHERE i<100000000) SELECT sum(i) FROM seq";
    result = run(expensive, 1, 5);
    Check(result.at("error").at("code") == "E_TIMEOUT", "query deadline",
          result);
    cancelled.store(true);
    expect("SELECT 1", "E_CANCELLED");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
