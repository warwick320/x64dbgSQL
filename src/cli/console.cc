#include <algorithm>
#include <fstream>
#include <iostream>

#include "cli/commands.h"

namespace xsql::cli {

std::string ReadBounded(std::istream& stream, std::size_t limit) {
  std::string output;
  char value;
  while (stream.get(value)) {
    if (output.size() >= limit)
      throw Error("E_LIMIT", "Input exceeds the size limit.");
    output.push_back(value);
  }
  if (!stream.eof())
    throw Error("E_INPUT", "Failed to read input.");
  return output;
}

std::string ReadFile(const std::filesystem::path& path, std::size_t limit) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw Error("E_INPUT", "Could not open the input file.");
  return ReadBounded(input, limit);
}

std::string DisplayValue(const Json& value) {
  if (value.is_null())
    return "NULL";
  if (value.is_object() && value.contains("int64"))
    return value.at("int64").get<std::string>();
  if (value.is_object() && value.contains("blob_hex"))
    return value.at("blob_hex").get<std::string>();
  if (value.is_string()) {
    std::string escaped;
    for (const auto character : value.get_ref<const std::string&>()) {
      if (static_cast<unsigned char>(character) < 32 || character == 127) {
        escaped += "\\x";
        escaped +=
            "0123456789abcdef"[static_cast<unsigned char>(character) >> 4];
        escaped +=
            "0123456789abcdef"[static_cast<unsigned char>(character) & 15];
      } else
        escaped += character;
    }
    return escaped;
  }
  return value.dump();
}

void PrintResult(const Json& value, bool table) {
  if (!table || !value.value("ok", false) || !value.contains("columns")) {
    std::cout << SerializeUtf8(value) << '\n';
    return;
  }
  for (const auto& column : value.at("columns"))
    std::cout << DisplayValue(column.at("name")) << '\t';
  std::cout << '\n';
  for (const auto& row : value.at("rows")) {
    for (const auto& cell : row)
      std::cout << DisplayValue(cell) << '\t';
    std::cout << '\n';
  }
  if (value.value("truncated", false))
    std::cerr << "Result reached its output limit. Narrow the query.\n";
}

Json RequestSchema(const Json& session, const std::string& table,
                   bool static_configured, ReadChannel* channel) {
  if (session.is_null())
    return DescribeSchema(table);
  auto result = xsql::Exchange(session, {{"op", "schema"}, {"table", table}},
                               18000, channel);
  if (static_configured && result.value("ok", false)) {
    for (auto& item : result.at("tables")) {
      if (item.value("requires_static_analysis", false))
        item["available"] = result.value("state", "") == "paused";
    }
  }
  return result;
}

Json SendQuery(const Json& session, const Json& arguments,
               const std::string& id, int default_rows,
               const StaticOptions* options,
               const std::atomic_bool* cancelled, ReadChannel* channel) {
  const auto sql = RequireString(arguments, "sql", kMaxSql);
  const auto rows =
      OptionalInteger(arguments, "max_rows", default_rows, 1, 1000);
  const auto timeout = OptionalInteger(arguments, "timeout_ms", 5000, 1, 15000);
  Json request{{"op", "query"},
               {"request_id", id},
               {"sql", sql},
               {"max_rows", rows},
               {"timeout_ms", timeout}};
  if (!options)
    return xsql::Exchange(session, request, timeout + 3000, channel);

  const std::atomic_bool never_cancelled{false};
  Budget budget{Clock::now() + std::chrono::milliseconds(timeout),
                cancelled ? *cancelled : never_cancelled};
  request["static_analysis"] = BindStaticAnalysis(*options, session, budget, channel);
  budget.Check();
  const auto remaining = static_cast<int>(std::clamp<std::int64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(budget.deadline -
                                                            Clock::now())
          .count(),
      1, timeout));
  request["timeout_ms"] = remaining;
  return xsql::Exchange(session, request, remaining + 1000, channel);
}

}  // namespace xsql::cli
