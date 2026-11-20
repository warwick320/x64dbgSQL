#include "query/virtual_table.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <span>

#include "analysis/bound_provider.h"

namespace xsql::sql {

struct VirtualTable {
  sqlite3_vtab base{};
  Query* query = nullptr;
  const Table* table = nullptr;
};

struct Cursor {
  sqlite3_vtab_cursor base{};
  const Json* rows = nullptr;
  std::span<const std::uint8_t> bytes;
  std::int64_t address = 0;
  std::int64_t requested = 0;
  std::size_t index = 0;
  std::size_t count = 0;
};

VirtualTable& AsTable(sqlite3_vtab* table) {
  return *reinterpret_cast<VirtualTable*>(table);
}
Cursor& AsCursor(sqlite3_vtab_cursor* cursor) {
  return *reinterpret_cast<Cursor*>(cursor);
}

int CursorError(sqlite3_vtab_cursor* cursor, const Error& error) {
  try {
    AsTable(cursor->pVtab).query->error = error;
  } catch (...) {
    return SQLITE_NOMEM;
  }
  return SQLITE_ERROR;
}

int ConnectTable(sqlite3* db, void* context, int argc, const char* const* argv,
                 sqlite3_vtab** output, char**) {
  try {
    const auto* table = argc == 3 ? FindTable(argv[0]) : nullptr;
    if (!table)
      return SQLITE_ERROR;
    const auto declaration =
        std::string("CREATE TABLE x(") + table->columns + ")";
    if (const int rc = sqlite3_declare_vtab(db, declaration.c_str());
        rc != SQLITE_OK)
      return rc;
    if (const int rc = sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
        rc != SQLITE_OK)
      return rc;
    auto value = std::make_unique<VirtualTable>();
    value->query = static_cast<Query*>(context);
    value->table = table;
    *output = &value.release()->base;
    return SQLITE_OK;
  } catch (...) {
    return SQLITE_NOMEM;
  }
}

int BestIndex(sqlite3_vtab* raw, sqlite3_index_info* info) {
  const auto& table = *AsTable(raw).table;
  if (!IsMemory(table) && !IsDisassembly(table)) {
    info->estimatedCost = 1000;
    info->estimatedRows = 256;
    return SQLITE_OK;
  }
  int address = -1;
  int size = -1;
  for (int i = 0; i < info->nConstraint; ++i) {
    const auto& constraint = info->aConstraint[i];
    if (!constraint.usable || constraint.op != SQLITE_INDEX_CONSTRAINT_EQ)
      continue;
    if (constraint.iColumn == 3)
      address = i;
    if (constraint.iColumn == 4)
      size = i;
  }
  if (address == -1 || size == -1)
    return SQLITE_CONSTRAINT;
  info->aConstraintUsage[address].argvIndex = 1;
  info->aConstraintUsage[address].omit = 1;
  info->aConstraintUsage[size].argvIndex = 2;
  info->aConstraintUsage[size].omit = 1;
  info->estimatedCost = 20;
  info->estimatedRows = 1;
  return SQLITE_OK;
}

int OpenCursor(sqlite3_vtab*, sqlite3_vtab_cursor** output) {
  try {
    *output = &(new Cursor)->base;
    return SQLITE_OK;
  } catch (...) {
    return SQLITE_NOMEM;
  }
}

int Filter(sqlite3_vtab_cursor* raw, int, const char*, int argc,
           sqlite3_value** argv) {
  auto& cursor = AsCursor(raw);
  auto& table = AsTable(raw->pVtab);
  auto& query = *table.query;
  try {
    cursor.index = 0;
    cursor.count = 0;
    cursor.rows = nullptr;
    cursor.bytes = {};
    query.budget.Check();
    if (analysis::IsStaticTable(table.table->name) && !query.static_bound)
      throw Error("E_STATIC_UNBOUND",
                  "This table requires a linked static analysis source.",
                  "Configure --static-provider and --static-url.");
    if (table.table->paused && query.initial.name != "paused")
      throw Error("E_STATE", "This table requires a paused target.",
                  "Pause the target in x64dbg and retry.");
    const bool disassemble = IsDisassembly(*table.table);
    if (IsMemory(*table.table) || disassemble) {
      if (argc != 2 || sqlite3_value_type(argv[0]) != SQLITE_INTEGER ||
          sqlite3_value_type(argv[1]) != SQLITE_INTEGER)
        throw Error("E_PREDICATE",
                    "Memory and disassembly ranges require integer arguments.");
      const auto address = sqlite3_value_int64(argv[0]);
      const auto size = sqlite3_value_int64(argv[1]);
      const auto key = std::pair<std::int64_t, std::int64_t>(address, size);
      if (disassemble) {
        if (address < 0 || size < 1 || size > kMaxDisassemblyRows)
          throw Error("E_LIMIT", "Provide an address and 1–256 instructions.");
        auto found = query.instruction_cache.find(key);
        if (found == query.instruction_cache.end()) {
          if (query.instructions_read + static_cast<std::size_t>(size) >
              kMaxStatementInstructions)
            throw Error("E_LIMIT", "The statement instruction budget was exceeded.");
          query.instructions_read += static_cast<std::size_t>(size);
          ++query.provider_reads;
          auto rows = query.provider.ReadInstructions(
              static_cast<std::uint64_t>(address), static_cast<unsigned>(size),
              query.budget);
          if (!rows.is_array() || rows.size() != static_cast<std::size_t>(size))
            throw Error("E_PROVIDER", "The decoder did not return the full range.");
          found = query.instruction_cache.emplace(key, std::move(rows)).first;
        } else {
          ++query.snapshot_hits;
        }
        cursor.rows = &found->second;
        cursor.address = address;
        cursor.requested = size;
        cursor.count = cursor.rows->size();
        return SQLITE_OK;
      }
      if (address < 0 || size < 1 || size > 4096 ||
          address > std::numeric_limits<std::int64_t>::max() - (size - 1))
        throw Error("E_LIMIT",
                    "Invalid address or memory size. The maximum is 4096 bytes "
                    "per read.");
      auto found = query.memory_cache.find(key);
      if (found == query.memory_cache.end()) {
        const auto bytes = static_cast<std::size_t>(size);
        if (query.budget.memory_bytes + bytes > 65536 ||
            query.memory_cache.size() == 256)
          throw Error("E_LIMIT",
                      "The per-query memory read budget was exceeded.");
        query.budget.memory_bytes += bytes;
        ++query.provider_reads;
        auto data = query.provider.ReadMemory(
            static_cast<std::uint64_t>(address), static_cast<unsigned>(size),
            query.budget);
        if (data.size() != bytes)
          throw Error("E_UNREADABLE",
                      "The full address range could not be read.");
        found = query.memory_cache.emplace(key, std::move(data)).first;
      } else {
        ++query.memory_hits;
      }
      cursor.bytes = found->second;
      cursor.address = address;
      cursor.count = 1;
      return SQLITE_OK;
    }
    auto iterator = query.snapshots.find(table.table->name);
    if (iterator == query.snapshots.end()) {
      ++query.provider_reads;
      auto rows = query.provider.ReadRows(table.table->name, query.initial,
                                          query.budget);
      if (!rows.is_array() || rows.size() > 8192 ||
          SerializeUtf8(rows).size() > 4 * 1024 * 1024)
        throw Error("E_LIMIT",
                    "Provider snapshot exceeded the per-table budget.");
      iterator =
          query.snapshots.emplace(table.table->name, std::move(rows)).first;
    } else {
      ++query.snapshot_hits;
    }
    cursor.rows = &iterator->second;
    cursor.count = cursor.rows->size();
    return SQLITE_OK;
  } catch (const Error& error) {
    return CursorError(raw, error);
  } catch (...) {
    return CursorError(
        raw, Error("E_INTERNAL", "The provider could not build a snapshot."));
  }
}

int Next(sqlite3_vtab_cursor* raw) {
  try {
    AsTable(raw->pVtab).query->budget.Check();
    ++AsCursor(raw).index;
    return SQLITE_OK;
  } catch (const Error& error) {
    return CursorError(raw, error);
  } catch (...) {
    return SQLITE_ERROR;
  }
}

int Column(sqlite3_vtab_cursor* raw, sqlite3_context* result, int index) {
  const auto& cursor = AsCursor(raw);
  try {
    if (!cursor.rows) {
      if (index == 2)
        // The query cache owns the bytes until after the statement is finalized.
        sqlite3_result_blob(result, cursor.bytes.data(),
                            static_cast<int>(cursor.bytes.size()),
                            SQLITE_STATIC);
      else if (index == 0 || index == 3)
        sqlite3_result_int64(result, cursor.address);
      else
        sqlite3_result_int64(result,
                             static_cast<sqlite3_int64>(cursor.bytes.size()));
      return SQLITE_OK;
    }
    if (index >= 3 && cursor.requested != 0) {
      sqlite3_result_int64(result, index == 3 ? cursor.address : cursor.requested);
      return SQLITE_OK;
    }
    const auto& value =
        cursor.rows->at(cursor.index).at(static_cast<std::size_t>(index));
    if (value.is_null())
      sqlite3_result_null(result);
    else if (value.is_number_integer())
      sqlite3_result_int64(result, value.get<std::int64_t>());
    else if (value.is_number_float())
      sqlite3_result_double(result, value.get<double>());
    else if (value.is_boolean())
      sqlite3_result_int(result, value.get<bool>() ? 1 : 0);
    else if (value.is_string()) {
      const auto& string = value.get_ref<const std::string&>();
      sqlite3_result_text(result, string.data(),
                          static_cast<int>(string.size()), SQLITE_TRANSIENT);
    } else
      return SQLITE_ERROR;
    return SQLITE_OK;
  } catch (...) {
    return SQLITE_ERROR;
  }
}

const sqlite3_module module = [] {
  sqlite3_module value{};
  value.iVersion = 3;
  value.xConnect = ConnectTable;
  value.xBestIndex = BestIndex;
  value.xDisconnect = [](sqlite3_vtab* ptr) {
    delete &AsTable(ptr);
    return SQLITE_OK;
  };
  value.xOpen = OpenCursor;
  value.xClose = [](sqlite3_vtab_cursor* ptr) {
    delete &AsCursor(ptr);
    return SQLITE_OK;
  };
  value.xFilter = Filter;
  value.xNext = Next;
  value.xEof = [](sqlite3_vtab_cursor* ptr) {
    return AsCursor(ptr).index >= AsCursor(ptr).count ? 1 : 0;
  };
  value.xColumn = Column;
  value.xRowid = [](sqlite3_vtab_cursor* ptr, sqlite3_int64* rowid) {
    *rowid = static_cast<sqlite3_int64>(AsCursor(ptr).index) + 1;
    return SQLITE_OK;
  };
  return value;
}();

int authorize(void*, int action, const char* first, const char* second,
              const char*, const char*) {
  switch (action) {
    case SQLITE_SELECT:
    case SQLITE_RECURSIVE:
      return SQLITE_OK;
    case SQLITE_READ:
      return first && FindTable(first) ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_FUNCTION: {
      constexpr std::string_view allowed[] = {
          "abs",          "avg",          "coalesce", "count",  "dense_rank",
          "glob",         "group_concat", "hex",      "ifnull", "json_array",
          "json_extract", "json_object",  "lag",      "lead",   "length",
          "like",         "lower",        "max",      "min",    "nullif",
          "printf",       "rank",         "replace",  "round",  "row_number",
          "substr",       "sum",          "total",    "trim",   "typeof",
          "upper"};
      return second && std::ranges::find(allowed, second) != std::end(allowed)
                 ? SQLITE_OK
                 : SQLITE_DENY;
    }
    default:
      return SQLITE_DENY;
  }
}

}  // namespace xsql::sql
