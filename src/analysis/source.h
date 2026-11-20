#ifndef X64DBGSQL_ANALYSIS_SOURCE_HPP_
#define X64DBGSQL_ANALYSIS_SOURCE_HPP_

#include <functional>
#include <optional>
#include <utility>

#include "core.h"

namespace xsql::analysis {

enum class Backend { kIda, kGhidra };

struct Predicate {
  std::string column;
  std::string value;
};

struct AddressRange {
  std::string column;
  std::int64_t start;
  std::int64_t end;
};

struct ReadOptions {
  std::vector<Predicate> filters;
  std::vector<std::string> columns;
  std::optional<AddressRange> range;
};

struct Program {
  Backend backend;
  std::string filename;
  std::string sha256;
  std::string version;
  std::string revision;
  std::int64_t image_base;
  int bits;
  std::string identity;
};

struct TableResult {
  std::vector<std::string> columns;
  Json rows;
  bool truncated;
};

class Source {
 public:
  using Transport = std::function<Json(std::string_view, const Budget&)>;
  Source(Backend backend, Transport transport);

  class PreparedRead {
   private:
    friend class Source;
    PreparedRead(std::string sql, std::size_t limit)
        : sql_(std::move(sql)), limit_(limit) {}
    std::string sql_;
    std::size_t limit_;
  };

  static PreparedRead PrepareRead(std::string_view table,
                                  const ReadOptions& options, int limit);

  Program Identify(const Budget& budget) const;
  TableResult Catalog(const Budget& budget) const;
  TableResult Read(std::string_view table, const ReadOptions& options,
                   int limit, const Budget& budget) const;
  TableResult Read(const PreparedRead& read, const Budget& budget) const;
  Json Functions(const Program& program, std::int64_t size,
                 std::optional<std::int64_t> rva, const Budget& budget) const;

 private:
  TableResult Select(std::string_view sql, std::size_t limit,
                     const Budget& budget) const;
  Backend backend_;
  Transport transport_;
};

inline constexpr std::size_t kMaxFunctions = 2048;
inline constexpr std::size_t kMaxNativeRows = 200;
inline constexpr std::size_t kMaxProjectionColumns = 32;
inline constexpr std::size_t kMaxNativeRowBytes = 16 * 1024;
inline constexpr std::size_t kMaxRemoteBytes = 512 * 1024;

std::string_view BackendName(Backend backend);
std::int64_t ParseAddress(const Json& value);
bool IsSha256(std::string_view value);
std::string QuoteText(std::string_view value);

}  // namespace xsql::analysis

#endif  // X64DBGSQL_ANALYSIS_SOURCE_HPP_
