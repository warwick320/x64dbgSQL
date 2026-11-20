#ifndef X64DBGSQL_QUERY_VIRTUAL_TABLE_HPP
#define X64DBGSQL_QUERY_VIRTUAL_TABLE_HPP

#include <sqlite3.h>

#include <map>
#include <optional>
#include <unordered_map>

#include "core.h"
#include "query/schema.h"

namespace xsql::sql {

struct Query {
  IDebuggerProvider& provider;
  bool static_bound;
  State initial;
  Budget budget;
  std::unordered_map<std::string, Json> snapshots;
  std::map<std::pair<std::int64_t, std::int64_t>, std::vector<std::uint8_t>>
      memory_cache;
  std::size_t provider_reads = 0;
  std::size_t snapshot_hits = 0;
  std::size_t memory_hits = 0;
  std::optional<Error> error;
  std::map<std::pair<std::int64_t, std::int64_t>, Json> instruction_cache{};
  std::size_t instructions_read = 0;
};

extern const sqlite3_module module;
int authorize(void*, int action, const char* first, const char* second,
              const char*, const char*);

}  // namespace xsql::sql

#endif  // X64DBGSQL_QUERY_VIRTUAL_TABLE_HPP
