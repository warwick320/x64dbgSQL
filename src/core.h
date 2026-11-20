#ifndef X64DBGSQL_CORE_H_
#define X64DBGSQL_CORE_H_

#include <atomic>
#include <chrono>
#include <cstdint>
#include <json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace xsql {

using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;

inline constexpr int kProtocolVersion = 1;
inline constexpr std::size_t kMaxFrame = 1024 * 1024;
inline constexpr std::size_t kMaxResult = 64 * 1024;
inline constexpr std::uint32_t kMaxSql = 32 * 1024;
inline constexpr int kMaxDisassemblyRows = 256;
inline constexpr int kMaxStatementInstructions = 2048;

struct Error : std::runtime_error {
  std::string code;
  std::string hint;
  Error(std::string code, std::string message, std::string hint = {});
};

struct State {
  std::string name = "idle";
  std::int64_t epoch = 0;
  std::int64_t generation = 0;
  std::int64_t pid = 0;
  std::int64_t tid = 0;
  std::int64_t ip = 0;
  bool operator==(const State&) const = default;
};

struct Budget {
  Clock::time_point deadline;
  const std::atomic_bool& cancelled;
  std::size_t memory_bytes = 0;
  void Check() const;
};

class IDebuggerProvider {
 public:
  virtual ~IDebuggerProvider() = default;
  virtual State GetState() = 0;
  virtual Json ReadRows(std::string_view table, const State& state,
                        Budget& budget) = 0;
  virtual std::vector<std::uint8_t> ReadMemory(std::uint64_t address,
                                               unsigned size,
                                               Budget& budget) = 0;
  virtual Json ReadInstructions(std::uint64_t, unsigned, Budget&) {
    throw Error("E_PROVIDER", "Native instruction decoding is unavailable.");
  }
};

Json ExecuteQuery(IDebuggerProvider& provider, const Json& request,
                  const std::atomic_bool& cancelled);
Json DescribeSchema(std::string_view name = {});
std::string SchemaHash();
Json Failure(const Error& error, const State& state = {});
std::string RequireString(const Json& data, const char* key,
                          std::size_t max_size);
int OptionalInteger(const Json& data, const char* key, int fallback,
                    int minimum, int maximum);
std::string SerializeUtf8(const Json& value);

}  // namespace xsql

#endif  // X64DBGSQL_CORE_H_
