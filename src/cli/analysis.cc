#include "cli/analysis.h"

#include <algorithm>
#include <limits>
#include <set>

#include "ipc.h"
#include "platform/analyzer_http.h"

namespace xsql::cli {
namespace {

using analysis::ParseAddress;

constexpr std::size_t kMaxStaticBatchBytes = 256 * 1024;

bool UsesCurrentFunction(const std::vector<analysis::Predicate>& filters) {
  return std::ranges::any_of(filters, [](const auto& predicate) {
    return predicate.value == "@function";
  });
}

std::string FunctionAddress(const Json& chunks,
                            const analysis::Program& program) {
  std::set<std::int64_t> entries;
  for (const auto& chunk : chunks)
    entries.insert(ParseAddress(chunk.at(0)));
  if (entries.size() != 1) {
    throw Error("E_STATIC_FUNCTION",
                "The selected address needs one static function owner.",
                "Choose an explicit RVA or use a native function address.");
  }
  return std::to_string(program.image_base + *entries.begin());
}

analysis::Source Connect(const StaticOptions& options) {
  return analysis::Source(options.backend, platform::AnalyzerHttp(options.url));
}

void ValidateStaticRead(std::string_view table,
                        const analysis::ReadOptions& read) {
  if (UsesCurrentFunction(read.filters))
    throw Error("E_INPUT", "@function requires a live combined query.");
  if (table.empty())
    throw Error("E_INPUT", "Select a native analyzer table.");
}

void CheckStaticIdentity(const analysis::Source& source,
                         const analysis::Program& before,
                         const Budget& budget) {
  if (before.identity != source.Identify(budget).identity) {
    throw Error("E_STATIC_CHANGED",
                "The active analyzer program changed during the read.");
  }
  budget.Check();
}

Json Result(analysis::TableResult table) {
  const auto count = table.rows.size();
  return {{"ok", true},
          {"columns", std::move(table.columns)},
          {"rows", std::move(table.rows)},
          {"row_count", count},
          {"truncated", table.truncated}};
}

Json ProgramJson(const analysis::Program& program) {
  return {{"backend", analysis::BackendName(program.backend)},
          {"filename", program.filename},
          {"sha256", program.sha256},
          {"image_base", program.image_base},
          {"bits", program.bits},
          {"version", program.version},
          {"revision", program.revision}};
}

std::int64_t IntegerCell(const Json& value) {
  return ParseAddress(value.at("int64"));
}

int Remaining(const Budget& budget) {
  budget.Check();
  return static_cast<int>(std::clamp<std::int64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(budget.deadline -
                                                            Clock::now())
          .count(),
      1, 15000));
}

Json NativeRows(const analysis::TableResult& result) {
  if (result.truncated) {
    throw Error("E_STATIC_LIMIT",
                "The selected native table snapshot exceeds 200 rows.",
                "Pass --static-where with a narrower predicate.");
  }
  const std::set<std::string> columns(result.columns.begin(),
                                      result.columns.end());
  if (columns.size() != result.columns.size()) {
    throw Error("E_STATIC_PROTOCOL",
                "Analyzer rows contain duplicate column names.");
  }
  Json rows = Json::array();
  for (const auto& row : result.rows) {
    Json object = Json::object();
    for (std::size_t i = 0; i != result.columns.size(); ++i)
      object[result.columns[i]] = row[i];
    if (SerializeUtf8(object).size() > analysis::kMaxNativeRowBytes) {
      throw Error("E_STATIC_LIMIT",
                  "A native row is too large for the combined query.",
                  "Use static read to view the native result separately.");
    }
    rows.push_back(std::move(object));
  }
  return rows;
}

}  // namespace

Json StaticInfo(const StaticOptions& options, const Budget& budget) {
  return {{"ok", true},
          {"program", ProgramJson(Connect(options).Identify(budget))}};
}

Json StaticCatalog(const StaticOptions& options, const Budget& budget) {
  const auto source = Connect(options);
  source.Identify(budget);
  return Result(source.Catalog(budget));
}

Json StaticRead(const StaticOptions& options, int limit, const Budget& budget) {
  ValidateStaticRead(options.table, options.read);
  const auto source = Connect(options);
  const auto before = source.Identify(budget);
  auto result = source.Read(options.table, options.read, limit, budget);
  CheckStaticIdentity(source, before, budget);
  return Result(std::move(result));
}

Json StaticReadBatch(const StaticOptions& options,
                     const std::vector<StaticReadRequest>& reads,
                     const Budget& budget) {
  if (reads.empty() || reads.size() > kMaxStaticBatchReads)
    throw Error("E_INPUT", "Specify between 1 and 32 native reads.");
  std::vector<analysis::Source::PreparedRead> prepared;
  prepared.reserve(reads.size());
  for (const auto& read : reads) {
    budget.Check();
    ValidateStaticRead(read.table, read.read);
    prepared.push_back(
        analysis::Source::PrepareRead(read.table, read.read, read.limit));
  }

  const auto source = Connect(options);
  const auto before = source.Identify(budget);
  Json output{{"ok", true}, {"results", Json::array()}};
  auto& results = output.at("results");
  // Include the wrapper and the separators between results in the size limit.
  auto bytes = SerializeUtf8(output).size();
  for (const auto& read : prepared) {
    auto result = Result(source.Read(read, budget));
    bytes += SerializeUtf8(result).size() + (results.empty() ? 0 : 1);
    if (bytes > kMaxStaticBatchBytes) {
      throw Error("E_STATIC_LIMIT", "Native read batch exceeds 256 KiB.",
                  "Narrow the projections or split the batch.");
    }
    results.push_back(std::move(result));
  }
  CheckStaticIdentity(source, before, budget);
  return output;
}

Json BindStaticAnalysis(const StaticOptions& options, const Json& session,
                        const Budget& budget, ReadChannel* channel) {
  const auto source = Connect(options);
  const auto program = source.Identify(budget);
  if (!analysis::IsSha256(program.sha256)) {
    throw Error("E_STATIC_IDENTITY",
                "The analyzer did not report the original input SHA-256.");
  }
  const bool resolve_function = UsesCurrentFunction(options.read.filters);
  if (options.table.empty() && (!options.read.filters.empty() ||
                                !options.read.columns.empty() ||
                                options.read.range)) {
    throw Error("E_INPUT",
                "Combined analyzer read options require --static-table.");
  }
  const auto name = options.module.empty() ? program.filename : options.module;
  std::string predicate;
  if (name.starts_with("0x") || name.starts_with("0X")) {
    predicate = "m.base=" + std::to_string(ParseAddress(name));
  } else {
    const bool path = name.find_first_of("/\\") != std::string::npos;
    predicate = std::string(path ? "lower(m.path)" : "lower(m.name)") +
                "=lower(" + analysis::QuoteText(name) + ")";
  }
  const auto sql =
      "SELECT s.pid,s.ip,m.base,m.size,m.name,m.path FROM session s CROSS JOIN "
      "modules m WHERE " +
      predicate + " LIMIT 2";
  const auto remaining = Remaining(budget);
  const auto reply = xsql::Exchange(session,
                                    {{"op", "query"},
                                     {"request_id", NewId()},
                                     {"sql", sql},
                                     {"max_rows", 2},
                                     {"timeout_ms", remaining}},
                                    remaining, channel);
  if (!reply.value("ok", false)) {
    const auto& error = reply.at("error");
    throw Error(error.value("code", "E_STATE"),
                error.value("message", "Could not select the live module."),
                error.value("hint", ""));
  }
  const auto& rows = reply.at("rows");
  if (rows.size() != 1 || reply.value("truncated", false)) {
    throw Error("E_STATIC_MODULE",
                "The analyzer image did not resolve to one loaded module.",
                "Pause the process and use --static-module with a unique name, "
                "absolute path, or hexadecimal load base.");
  }
  const auto& module = rows.front();
  const auto base = IntegerCell(module.at(2));
  const auto size = IntegerCell(module.at(3));
  const auto path =
      std::filesystem::path(ToWide(module.at(5).get<std::string>()));
  const auto arch = session.at("arch").get<std::string>();
  if (program.bits != (arch == "x64" ? 64 : 32) || !path.is_absolute() ||
      path.root_name().wstring().size() != 2 ||
      !std::filesystem::is_regular_file(path) ||
      std::filesystem::file_size(path) > 512ULL * 1024 * 1024) {
    throw Error(
        "E_STATIC_IDENTITY",
        "The loaded image architecture or accessible file did not match.",
        "Use a local PE image of matching architecture, up to 512 MiB.");
  }
  if (FileSha256(path, &budget) != program.sha256) {
    throw Error("E_STATIC_IDENTITY",
                "The analyzer SHA-256 differs from the loaded module's file.",
                "Open the same build of the executable in both tools.");
  }
  budget.Check();
  std::optional<std::int64_t> focus;
  if (options.rva == "current" || (resolve_function && options.rva.empty())) {
    const auto ip = IntegerCell(module.at(1));
    if (ip < base || ip - base >= size) {
      throw Error("E_STATIC_ADDRESS",
                  "The instruction pointer is outside the selected module.");
    }
    focus = ip - base;
  } else if (!options.rva.empty()) {
    focus = ParseAddress(options.rva);
  }
  auto snapshot = ProgramJson(program);
  snapshot["module"] = Json::array({base, size, module.at(4), module.at(5)});
  snapshot["pid"] = IntegerCell(module.at(0));
  snapshot["epoch"] = reply.at("epoch");
  snapshot["generation"] = reply.at("generation");
  snapshot["focus_rva"] = focus ? Json(*focus) : Json(nullptr);
  snapshot["functions"] = source.Functions(program, size, focus, budget);
  if (!options.table.empty()) {
    auto read = options.read;
    if (resolve_function) {
      const auto address = FunctionAddress(snapshot.at("functions"), program);
      for (auto& filter : read.filters)
        if (filter.value == "@function")
          filter.value = address;
    }
    snapshot["native"] = {
        {"table", options.table},
        {"rows", NativeRows(source.Read(options.table, read,
                                        analysis::kMaxNativeRows, budget))}};
  }
  if (source.Identify(budget).identity != program.identity) {
    throw Error("E_STATIC_CHANGED",
                "The active analyzer program or its reported revision changed "
                "during the query.");
  }
  return snapshot;
}

}  // namespace xsql::cli
