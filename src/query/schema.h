#ifndef X64DBGSQL_QUERY_SCHEMA_HPP
#define X64DBGSQL_QUERY_SCHEMA_HPP

#include <span>
#include <string_view>

namespace xsql::sql {

struct Table {
  const char* name;
  const char* columns;
  const char* description;
  bool paused = true;
};

struct View {
  Table table;
  const char* sql;
};

std::span<const Table> Tables();
std::span<const View> Views();
bool IsMemory(const Table& table);
bool IsDisassembly(const Table& table);
const Table* FindTable(std::string_view name);

}  // namespace xsql::sql

#endif  // X64DBGSQL_QUERY_SCHEMA_HPP
