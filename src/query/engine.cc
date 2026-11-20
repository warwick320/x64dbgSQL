#include <cmath>
#include <memory>

#include "analysis/bound_provider.h"
#include "query/virtual_table.h"

namespace xsql {

using sql::authorize;
using sql::module;
using sql::Query;
using sql::Tables;
using sql::Views;

Json Envelope(const State& state);

namespace {
using Database = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;

Database OpenMemoryDatabase() {
  sqlite3* raw = nullptr;
  const int rc = sqlite3_open_v2(
      ":memory:", &raw,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX |
          SQLITE_OPEN_PRIVATECACHE,
      nullptr);
  Database db(raw, sqlite3_close);
  if (rc != SQLITE_OK)
    throw Error("E_INTERNAL", "Could not initialize SQLite.");
  return db;
}

struct ViewSchema {
  std::unique_ptr<unsigned char, decltype(&sqlite3_free)> image{nullptr,
                                                               sqlite3_free};
  sqlite3_int64 size = 0;
};

const ViewSchema& SharedViewSchema() {
  static const auto schema = [] {
    const auto db = OpenMemoryDatabase();
    for (const auto& view : Views()) {
      const auto ddl =
          std::string("CREATE VIEW ") + view.table.name + " AS " + view.sql;
      if (sqlite3_exec(db.get(), ddl.c_str(), nullptr, nullptr, nullptr) !=
          SQLITE_OK)
        throw Error("E_INTERNAL", "Could not initialize the SQLite views.");
    }
    ViewSchema view_schema;
    view_schema.image.reset(
        sqlite3_serialize(db.get(), "main", &view_schema.size, 0));
    if (!view_schema.image)
      throw Error("E_INTERNAL", "Could not serialize the SQLite views.");
    return view_schema;
  }();
  return schema;
}

void CheckSqlite(sqlite3* db, int code, Query& query,
                 std::string_view fallback) {
  if (code == SQLITE_OK || code == SQLITE_ROW || code == SQLITE_DONE)
    return;
  if (query.error)
    throw *query.error;
  query.budget.Check();
  const std::string error = sqlite3_errmsg(db);
  if (code == SQLITE_AUTH || error.find("prohibited") != std::string::npos ||
      error.find("may not be modified") != std::string::npos)
    throw Error("E_PERM", "SQL operation is outside the read-only allowlist.",
                "Inspect the public schema.");
  if (error.find("no query solution") != std::string::npos)
    throw Error("E_PREDICATE",
                "Provide both arguments to memory(addr,size) or "
                "disassembly(addr,count).");
  if (error.find("no such table:") != std::string::npos)
    throw Error("E_NO_TABLE", error,
                "Run schema to discover available tables.");
  if (error.find("no such column:") != std::string::npos)
    throw Error("E_NO_COLUMN", error,
                "Run schema to inspect the table columns.");
  if (code == SQLITE_TOOBIG || code == SQLITE_NOMEM)
    throw Error("E_LIMIT", "SQLite's query limits were exceeded.");
  throw Error(std::string(fallback), error);
}

Json ReadCell(sqlite3_stmt* statement, int index) {
  switch (sqlite3_column_type(statement, index)) {
    case SQLITE_INTEGER: {
      Json value = Json::object();
      value.emplace("int64",
                    std::to_string(sqlite3_column_int64(statement, index)));
      return value;
    }
    case SQLITE_FLOAT: {
      const auto value = sqlite3_column_double(statement, index);
      if (!std::isfinite(value))
        throw Error("E_RESULT_TYPE",
                    "A REAL result is outside the JSON number range.");
      return value;
    }
    case SQLITE_TEXT: {
      const auto* value =
          reinterpret_cast<const char*>(sqlite3_column_text(statement, index));
      return std::string(value, static_cast<std::size_t>(
                                    sqlite3_column_bytes(statement, index)));
    }
    case SQLITE_BLOB: {
      constexpr char alphabet[] = "0123456789abcdef";
      const auto* blob = static_cast<const unsigned char*>(
          sqlite3_column_blob(statement, index));
      const auto count =
          static_cast<std::size_t>(sqlite3_column_bytes(statement, index));
      std::string hex(count * 2, '\0');
      for (std::size_t offset = 0; offset < count; ++offset) {
        hex[offset * 2] = alphabet[blob[offset] >> 4];
        hex[offset * 2 + 1] = alphabet[blob[offset] & 15];
      }
      Json value = Json::object();
      value.emplace("blob_hex", std::move(hex));
      return value;
    }
    default:
      return nullptr;
  }
}

bool IsReadKeyword(std::string_view input) {
  for (;;) {
    const auto offset = input.find_first_not_of(" \t\r\n\f;");
    if (offset == std::string_view::npos)
      return false;
    input.remove_prefix(offset);
    if (input.starts_with("--")) {
      const auto end = input.find('\n');
      if (end == std::string_view::npos)
        return false;
      input.remove_prefix(end + 1);
    } else if (input.starts_with("/*")) {
      const auto end = input.find("*/", 2);
      if (end == std::string_view::npos)
        return false;
      input.remove_prefix(end + 2);
    } else
      break;
  }
  const auto end = input.find_first_not_of(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
  auto word = std::string(input.substr(0, end));
  for (auto& c : word)
    if (c >= 'a' && c <= 'z')
      c = static_cast<char>(c - 'a' + 'A');
  return word == "SELECT" || word == "WITH";
}

}  // namespace

Json ExecuteQuery(IDebuggerProvider& provider, const Json& request,
                  const std::atomic_bool& cancelled) {
  const auto start = Clock::now();
  State initial;
  try {
    const auto sql = RequireString(request, "sql", kMaxSql);
    if (!IsReadKeyword(sql))
      throw Error("E_PERM",
                  "A single read-only SELECT or WITH query is required.");
    const int max_rows = OptionalInteger(request, "max_rows", 1000, 1, 1000);
    const int timeout = OptionalInteger(request, "timeout_ms", 5000, 1, 15000);
    initial = provider.GetState();
    Budget budget{start + std::chrono::milliseconds(timeout), cancelled};
    std::optional<analysis::BoundProvider> bound;
    if (const auto snapshot = request.find("static_analysis");
        snapshot != request.end()) {
      bound.emplace(provider, *snapshot, initial, budget);
    }
    Query context{bound ? static_cast<IDebuggerProvider&>(*bound) : provider,
                  bound.has_value(),
                  initial,
                  budget,
                  {},
                  {},
                  0,
                  0,
                  0,
                  {}};
    static const auto heap_limit = sqlite3_hard_heap_limit64(64 * 1024 * 1024);
    (void)heap_limit;
    const auto db = OpenMemoryDatabase();
    auto* const database = db.get();
    const auto& schema = SharedViewSchema();
    // Every statement gets an isolated connection over the immutable view DDL.
    CheckSqlite(
        database,
        sqlite3_deserialize(database, "main", schema.image.get(), schema.size,
                            schema.size, SQLITE_DESERIALIZE_READONLY),
        context, "E_INTERNAL");
    sqlite3_db_config(database, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
    sqlite3_db_config(database, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
    sqlite3_limit(database, SQLITE_LIMIT_LENGTH, 128 * 1024);
    sqlite3_limit(database, SQLITE_LIMIT_SQL_LENGTH, kMaxSql);
    sqlite3_limit(database, SQLITE_LIMIT_COLUMN, 64);
    sqlite3_limit(database, SQLITE_LIMIT_EXPR_DEPTH, 64);
    sqlite3_limit(database, SQLITE_LIMIT_COMPOUND_SELECT, 16);
    sqlite3_limit(database, SQLITE_LIMIT_VDBE_OP, 50000);
    sqlite3_limit(database, SQLITE_LIMIT_ATTACHED, 0);
    sqlite3_progress_handler(
        database, 1000,
        [](void* pointer) {
          const auto& budget = *static_cast<Budget*>(pointer);
          return budget.cancelled.load(std::memory_order_relaxed) ||
                         Clock::now() >= budget.deadline
                     ? 1
                     : 0;
        },
        &context.budget);
    // Register tables by name so SQLite connects only the ones a query uses.
    for (const auto& table : Tables()) {
      CheckSqlite(
          database,
          sqlite3_create_module_v2(database, table.name, &module, &context,
                                   nullptr),
          context, "E_INTERNAL");
    }
    sqlite3_set_authorizer(database, authorize, nullptr);
    sqlite3_stmt* statement = nullptr;
    const char* tail = nullptr;
    int rc =
        sqlite3_prepare_v3(database, sql.data(), static_cast<int>(sql.size()),
                           0, &statement, &tail);
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> prepared(
        statement, sqlite3_finalize);
    CheckSqlite(database, rc, context, "E_PARSE");
    if (!statement || !sqlite3_stmt_readonly(statement) ||
        sqlite3_column_count(statement) == 0 ||
        sqlite3_stmt_isexplain(statement))
      throw Error("E_PERM",
                  "A single read-only SELECT or WITH query is required.");
    if (tail < sql.data() + sql.size()) {
      sqlite3_stmt* extra = nullptr;
      rc = sqlite3_prepare_v3(database, tail,
                              static_cast<int>(sql.data() + sql.size() - tail),
                              0, &extra, nullptr);
      const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>
          extra_prepared(extra, sqlite3_finalize);
      context.budget.Check();
      if (rc != SQLITE_OK || extra)
        throw Error("E_PARSE", "Only one SQL statement is allowed.");
    }

    Json result = Envelope(initial);
    auto& columns = result["columns"];
    auto& rows = result["rows"];
    const int count = sqlite3_column_count(statement);
    for (int i = 0; i < count; ++i) {
      const char* declared = sqlite3_column_decltype(statement, i);
      columns.push_back({{"name", sqlite3_column_name(statement, i)},
                         {"type", declared ? Json(declared) : Json(nullptr)}});
    }
    std::size_t bytes = SerializeUtf8(result).size() + 256;
    if (bytes >= kMaxResult)
      throw Error("E_LIMIT", "Result column metadata exceeds the byte limit.");
    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
      context.budget.Check();
      if (rows.size() >= static_cast<std::size_t>(max_rows)) {
        result["truncated"] = true;
        break;
      }
      Json::array_t cells;
      cells.reserve(static_cast<std::size_t>(count));
      for (int i = 0; i < count; ++i)
        cells.push_back(ReadCell(statement, i));
      Json row(std::move(cells));
      bytes += SerializeUtf8(row).size() + 1;
      if (bytes > kMaxResult) {
        result["truncated"] = true;
        break;
      }
      rows.push_back(std::move(row));
    }
    CheckSqlite(database, rc, context, "E_QUERY");
    context.budget.Check();
    const auto current = provider.GetState();
    if (!(current == initial))
      throw Error("E_STATE_CHANGED",
                  "The target state changed during the query.",
                  "Refresh the session and retry.");
    result["row_count"] = rows.size();
    result["elapsed_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                              start)
            .count();
    result["work"] = {{"provider_reads", context.provider_reads},
                      {"snapshot_cache_hits", context.snapshot_hits},
                      {"memory_bytes", context.budget.memory_bytes},
                      {"memory_cache_hits", context.memory_hits}};
    return result;
  } catch (const Error& error) {
    auto result = Failure(error, initial);
    result["elapsed_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                              start)
            .count();
    return result;
  }
}

}  // namespace xsql
