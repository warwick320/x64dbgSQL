#include "analysis/source.h"

#include <algorithm>
#include <charconv>
#include <limits>
#include <set>

namespace xsql::analysis {
namespace {

constexpr auto kMetadataSql =
    "SELECT key,value FROM binary WHERE key IN "
    "('tool_name','tool_version','idasql_version','filename','sha256',"
    "'image_base','bits','revision','program_path','idb_path','analysis_id') "
    "ORDER BY key";

bool IsLetter(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

std::string Identifier(std::string_view value) {
  if (value.empty() || value.size() > 128 || !IsLetter(value.front()) ||
      !std::ranges::all_of(value, [](char c) {
        return IsLetter(c) || (c >= '0' && c <= '9');
      })) {
    throw Error("E_INPUT",
                "Analyzer object and column names must be identifiers.");
  }
  return "\"" + std::string(value) + "\"";
}

std::string Literal(std::string_view value) {
  if (value.size() > 512 || value.find('\0') != std::string_view::npos) {
    throw Error("E_INPUT", "Invalid analyzer predicate value.");
  }
  if (value.starts_with("0x") || value.starts_with("0X") ||
      (!value.empty() && std::ranges::all_of(value, [](char c) {
        return c >= '0' && c <= '9';
      }))) {
    return std::to_string(ParseAddress(std::string(value)));
  }
  return QuoteText(value);
}

std::string Lower(std::string value) {
  for (char& c : value) {
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
  }
  return value;
}

bool InvalidResult(const Json& result) {
  return !result.value("success", false) || result.value("timed_out", false) ||
         result.value("partial", false) || result.value("truncated", false) ||
         (result.contains("error") && !result.at("error").is_null() &&
          result.at("error") != "");
}

}  // namespace

Source::Source(Backend backend, Transport transport)
    : backend_(backend), transport_(std::move(transport)) {}

std::string QuoteText(std::string_view value) {
  std::string result(1, '\'');
  for (char c : value) {
    if (c == '\'')
      result.push_back(c);
    result.push_back(c);
  }
  result.push_back('\'');
  return result;
}

std::string_view BackendName(Backend backend) {
  return backend == Backend::kIda ? "idasql" : "ghidrasql";
}

bool IsSha256(std::string_view value) {
  return value.size() == 64 && std::ranges::all_of(value, [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

std::int64_t ParseAddress(const Json& value) {
  constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
  if (value.is_number_unsigned() && value.get<std::uint64_t>() <= maximum) {
    return static_cast<std::int64_t>(value.get<std::uint64_t>());
  }
  if (value.type() == Json::value_t::number_integer &&
      value.get<std::int64_t>() >= 0) {
    return value.get<std::int64_t>();
  }
  if (value.is_string()) {
    std::string_view digits = value.get_ref<const std::string&>();
    const bool hex = digits.starts_with("0x") || digits.starts_with("0X");
    if (hex)
      digits.remove_prefix(2);
    std::int64_t parsed = 0;
    const auto last = digits.data() + digits.size();
    const auto [end, err] =
        std::from_chars(digits.data(), last, parsed, hex ? 16 : 10);
    if (!digits.empty() && err == std::errc{} && end == last && parsed >= 0)
      return parsed;
  }
  throw Error("E_STATIC_ADDRESS",
              "Expected a nonnegative exact 64-bit address.");
}

TableResult Source::Select(std::string_view sql, std::size_t limit,
                           const Budget& budget) const {
  budget.Check();
  try {
    auto envelope = transport_(sql, budget);
    budget.Check();
    Json* statement = &envelope;
    if (envelope.contains("results")) {
      auto& results = envelope.at("results");
      if (InvalidResult(envelope) || !results.is_array() ||
          results.size() != 1 || envelope.value("statement_count", 1) != 1) {
        throw Error("E_STATIC_PROTOCOL",
                    "Analyzer did not return one complete statement result.");
      }
      statement = &results.front();
    }
    if (InvalidResult(*statement)) {
      throw Error(
          "E_STATIC_QUERY", "Analyzer could not complete this read.",
          "Check the native schema, required predicates, and endpoint logs.");
    }
    auto columns = statement->at("columns").get<std::vector<std::string>>();
    auto rows = std::move(statement->at("rows"));
    if (columns.empty() || columns.size() > 256 || !rows.is_array() ||
        rows.size() > limit + 1 ||
        statement->value("row_count", rows.size()) != rows.size()) {
      throw Error("E_STATIC_PROTOCOL", "Invalid analyzer result shape.");
    }
    for (const auto& row : rows) {
      if (!row.is_array() || row.size() != columns.size()) {
        throw Error("E_STATIC_PROTOCOL",
                    "Analyzer row does not match the column list.");
      }
    }
    const bool truncated = rows.size() > limit;
    if (truncated)
      rows.erase(rows.end() - 1);
    return {std::move(columns), std::move(rows), truncated};
  } catch (const Json::exception&) {
    throw Error("E_STATIC_PROTOCOL",
                "Analyzer response does not match the SQL HTTP contract.");
  }
}

Program Source::Identify(const Budget& budget) const {
  const auto result = Select(kMetadataSql, 16, budget);
  Json values = Json::object();
  for (const auto& row : result.rows) {
    const auto key = RequireString(Json{{"key", row.at(0)}}, "key", 64);
    if (values.contains(key)) {
      throw Error("E_STATIC_PROTOCOL",
                  "The analyzer returned duplicate program metadata.");
    }
    values[key] = row.at(1);
  }
  const auto version =
      values.value("tool_version", values.value("idasql_version", ""));
  const auto name = Lower(values.value(
      "tool_name", values.contains("idasql_version") ? "idasql" : ""));
  if (result.truncated || name != BackendName(backend_)) {
    throw Error(
        "E_STATIC_BACKEND",
        "The endpoint does not identify itself as the selected analyzer.");
  }
  const auto hash = Lower(values.value("sha256", ""));
  const auto base = ParseAddress(values.value("image_base", Json(0)));
  const auto bits = ParseAddress(values.value("bits", Json(0)));
  const auto filename = RequireString(values, "filename", 512);
  const auto revision_field = values.value("revision", Json(""));
  const auto revision = revision_field.is_string()
                            ? revision_field.get<std::string>()
                            : revision_field.dump();
  return {backend_,
          filename,
          hash,
          version,
          revision,
          base,
          bits <= 64 ? static_cast<int>(bits) : 0,
          values.dump()};
}

TableResult Source::Catalog(const Budget& budget) const {
  return Select(
      "SELECT name,type FROM sqlite_master WHERE type IN ('table','view') "
      "AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1001",
      1000, budget);
}

Source::PreparedRead Source::PrepareRead(std::string_view table,
                                         const ReadOptions& options,
                                         int limit) {
  if (limit < 1 || limit > static_cast<int>(kMaxNativeRows) ||
      options.filters.size() > 8) {
    throw Error(
        "E_INPUT",
        "Analyzer reads accept 1–200 rows and at most eight predicates.");
  }
  if (Lower(std::string(table)).starts_with("sqlite_")) {
    throw Error("E_INPUT", "Use static catalog to inspect database metadata.");
  }
  if (options.columns.size() > kMaxProjectionColumns)
    throw Error("E_INPUT", "Project at most 32 analyzer columns.");
  std::string sql = "SELECT ";
  if (options.columns.empty()) {
    sql += '*';
  } else {
    std::set<std::string> names;
    for (const auto& column : options.columns) {
      if (!names.insert(Lower(column)).second)
        throw Error("E_INPUT", "Analyzer projection columns must be unique.");
      if (names.size() > 1)
        sql += ',';
      sql += Identifier(column);
    }
  }
  sql += " FROM " + Identifier(table);
  bool first = true;
  const auto add_filter = [&](std::string predicate) {
    sql += std::exchange(first, false) ? " WHERE " : " AND ";
    sql += predicate;
  };
  for (const auto& filter : options.filters)
    add_filter(Identifier(filter.column) + "=" + Literal(filter.value));
  if (options.range) {
    const auto& [column, start, end] = *options.range;
    if (start < 0 || end <= start)
      throw Error("E_INPUT", "Analyzer range start must precede its end.");
    const auto name = Identifier(column);
    add_filter(name + ">=" + std::to_string(start));
    add_filter(name + "<" + std::to_string(end));
    sql += " ORDER BY " + name;
  }
  sql += " LIMIT " + std::to_string(limit + 1);
  return PreparedRead(std::move(sql), static_cast<std::size_t>(limit));
}

TableResult Source::Read(std::string_view table, const ReadOptions& options,
                         int limit, const Budget& budget) const {
  return Read(PrepareRead(table, options, limit), budget);
}

TableResult Source::Read(const PreparedRead& read, const Budget& budget) const {
  return Select(read.sql_, read.limit_, budget);
}

Json Source::Functions(const Program& program, std::int64_t size,
                       std::optional<std::int64_t> rva,
                       const Budget& budget) const {
  if (size <= 0 ||
      program.image_base > std::numeric_limits<std::int64_t>::max() - size ||
      (rva && (*rva < 0 || *rva >= size))) {
    throw Error("E_STATIC_ADDRESS",
                "The image range or requested RVA is out of range.");
  }
  const auto lower = std::to_string(program.image_base);
  const auto upper = std::to_string(program.image_base + size);
  const auto start =
      backend_ == Backend::kIda ? "c.chunk_start" : "c.start_addr";
  const auto end = backend_ == Backend::kIda ? "c.chunk_end" : "c.end_addr";
  const std::string point =
      rva ? std::to_string(program.image_base + *rva) : "";
  std::string sql;
  if (rva && backend_ == Backend::kIda) {
    sql =
        "SELECT CAST(func_addr AS TEXT),CAST(chunk_start AS TEXT),"
        "CAST(chunk_end AS TEXT),name FROM func_at(" +
        point +
        ") "
        "ORDER BY chunk_start,func_addr";
  } else {
    sql = "SELECT CAST(f.addr AS TEXT),CAST(" + std::string(start) +
          " AS TEXT),CAST(" + end +
          " AS TEXT),f.name FROM function_chunks c "
          "JOIN funcs f ON f.addr=c.func_addr WHERE " +
          start + ">=" + lower + " AND " + end + "<=" + upper +
          " AND f.addr>=" + lower + " AND f.addr<" + upper;
    if (rva)
      sql += " AND " + std::string(start) + "<=" + point + " AND " + end + ">" +
             point;
    sql += " ORDER BY " + std::string(start) + ",f.addr";
  }
  sql += " LIMIT " + std::to_string(kMaxFunctions + 1);
  const auto result = Select(sql, kMaxFunctions, budget);
  if (result.truncated) {
    throw Error(
        "E_STATIC_LIMIT", "The function chunk snapshot exceeds 2048 rows.",
        "Pass --static-rva with an address inside the function to query.");
  }
  Json output = Json::array();
  for (const auto& row : result.rows) {
    if (row.size() != 4 || !row.at(3).is_string()) {
      throw Error("E_STATIC_PROTOCOL",
                  "Invalid analyzer function chunk record.");
    }
    const auto entry = ParseAddress(row.at(0)) - program.image_base;
    const auto first = ParseAddress(row.at(1)) - program.image_base;
    const auto last = ParseAddress(row.at(2)) - program.image_base;
    if (entry < 0 || entry >= size || first < 0 || last <= first ||
        last > size || (rva && (*rva < first || *rva >= last))) {
      throw Error("E_STATIC_ADDRESS",
                  "Analyzer returned a chunk outside the verified image or "
                  "requested range.");
    }
    const auto& name = row.at(3).get_ref<const std::string&>();
    if (name.size() > 1024)
      throw Error("E_STATIC_LIMIT",
                  "Analyzer function name exceeds the text limit.");
    output.push_back(Json::array({entry, first, last, name}));
  }
  return output;
}

}  // namespace xsql::analysis
