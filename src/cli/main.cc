#include <windows.h>

#include <charconv>
#include <iostream>
#include <map>
#include <optional>

#include "cli/commands.h"

namespace {
namespace analysis = xsql::analysis;
using xsql::Budget;
using xsql::Clock;
using xsql::Error;
using xsql::Failure;
using xsql::Json;
using xsql::kMaxSql;
using xsql::kProtocolVersion;
using xsql::ListSessions;
using xsql::NewId;
using xsql::OptionalInteger;
using xsql::SchemaHash;
using xsql::SelectSession;
using xsql::SessionDirectory;
using xsql::ToUtf8;
using xsql::ToWide;
using xsql::cli::CaptureCheckpoint;
using xsql::cli::DiffCheckpoints;
using xsql::cli::PrintResult;
using xsql::cli::ReadBounded;
using xsql::cli::ReadFile;
using xsql::cli::RequestSchema;
using xsql::cli::RunMcp;
using xsql::cli::SendQuery;
using xsql::cli::StaticCatalog;
using xsql::cli::StaticInfo;
using xsql::cli::StaticOptions;
using xsql::cli::StaticRead;

constexpr auto usage = R"(x64dbgSQL
  doctor | sessions | status
  query -q SQL | -f FILE | - [--max-rows N] [--timeout-ms N] [--json]
  schema [TABLE] [--offline]
  static info|catalog|read [TABLE] --static-provider ida|ghidra [--static-url URL]
  checkpoint capture FILE | checkpoint diff BEFORE AFTER
  mcp [--session ID] [--compact]
  annotation set|remove KIND ADDRESS [TEXT] --session ID --reason TEXT
  breakpoint add|remove --session ID --reason TEXT
  control run|pause|step --session ID --reason TEXT
  action status ID --session ID

Session commands accept --session ID. Changes also accept --id, --epoch, and --generation.
Query and MCP can use --static-provider, --static-url, --static-module, --static-rva,
--static-table, and repeated --static-where COLUMN=VALUE.
Native static reads also accept --static-columns COLUMN[,COLUMN] and
--static-range COLUMN=START:END (inclusive start, exclusive end).
)";

struct Arguments {
  std::vector<std::string> words;
  std::map<std::string, std::string> options;
  std::vector<analysis::Predicate> filters;
  bool json = false;
  bool offline = false;
  bool compact = false;

  std::string option(const std::string& name, std::string fallback = {}) const {
    const auto match = options.find(name);
    return match == options.end() ? fallback : match->second;
  }
};

Arguments ParseArguments(int argc, wchar_t** argv) {
  Arguments result;
  for (int i = 1; i < argc; ++i) {
    const auto value = ToUtf8(argv[i]);
    if (value == "--json")
      result.json = true;
    else if (value == "--offline")
      result.offline = true;
    else if (value == "--compact")
      result.compact = true;
    else if (value == "--help" || value == "-h")
      result.words.push_back("help");
    else if (value == "--static-where") {
      if (++i == argc)
        throw Error("E_INPUT", "Missing value for --static-where.");
      auto filter = ToUtf8(argv[i]);
      const auto equals = filter.find('=');
      if (equals == std::string::npos || equals == 0)
        throw Error("E_INPUT", "Use --static-where COLUMN=VALUE.");
      result.filters.push_back(
          {filter.substr(0, equals), filter.substr(equals + 1)});
    } else if (value == "-q" || value == "-f" || value == "--session" ||
               value == "--max-rows" || value == "--static-provider" ||
               value == "--static-url" || value == "--static-module" ||
               value == "--static-rva" || value == "--static-table" ||
               value == "--static-columns" || value == "--static-range" ||
               value == "--timeout-ms" || value == "--reason" ||
               value == "--id" || value == "--epoch" ||
               value == "--generation") {
      if (++i == argc || !result.options.emplace(value, ToUtf8(argv[i])).second)
        throw Error("E_INPUT", "Missing or duplicate value for " + value);
    } else if (value.starts_with("--")) {
      throw Error("E_INPUT", "Unknown option " + value);
    } else
      result.words.push_back(value);
  }
  return result;
}

std::int64_t ParseDecimal(const std::string& text) {
  std::int64_t value = 0;
  const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size() || value < 0)
    throw Error("E_INPUT", "Expected a nonnegative decimal integer.");
  return value;
}

std::optional<StaticOptions> StaticConfig(const Arguments& args) {
  const auto provider = args.option("--static-provider");
  if (provider.empty()) {
    if (!args.filters.empty() || args.options.contains("--static-url") ||
        args.options.contains("--static-module") ||
        args.options.contains("--static-rva") ||
        args.options.contains("--static-table") ||
        args.options.contains("--static-columns") ||
        args.options.contains("--static-range"))
      throw Error("E_INPUT",
                  "Static analysis options require --static-provider.");
    return std::nullopt;
  }
  const bool ida = provider == "ida" || provider == "idasql";
  if (!ida && provider != "ghidra" && provider != "ghidrasql")
    throw Error("E_INPUT", "Use --static-provider ida or ghidra.");
  analysis::ReadOptions read{args.filters, {}, std::nullopt};
  if (args.options.contains("--static-columns")) {
    const auto option = args.option("--static-columns");
    std::string_view remaining = option;
    for (;;) {
      const auto comma = remaining.find(',');
      read.columns.emplace_back(remaining.substr(0, comma));
      if (comma == std::string_view::npos)
        break;
      remaining.remove_prefix(comma + 1);
    }
  }
  if (args.options.contains("--static-range")) {
    const auto range = args.option("--static-range");
    const auto equals = range.find('=');
    const auto colon = range.find(':');
    if (equals == std::string::npos || colon == std::string::npos ||
        equals == 0 || colon <= equals + 1 || colon + 1 == range.size())
      throw Error("E_INPUT", "Use --static-range COLUMN=START:END.");
    read.range = analysis::AddressRange{
        range.substr(0, equals),
        analysis::ParseAddress(range.substr(equals + 1, colon - equals - 1)),
        analysis::ParseAddress(range.substr(colon + 1))};
  }
  return StaticOptions{
      ida ? analysis::Backend::kIda : analysis::Backend::kGhidra,
      args.option("--static-url",
                  ida ? "http://127.0.0.1:8080" : "http://127.0.0.1:8081"),
      args.option("--static-module"),
      args.option("--static-rva"),
      args.option("--static-table"),
      std::move(read)};
}

Json RunStatic(const Arguments& args, StaticOptions options) {
  if (args.words.size() < 2)
    throw Error("E_INPUT", "Use static info, catalog, or read TABLE.");
  const auto timeout = OptionalInteger(
      {{"t", ParseDecimal(args.option("--timeout-ms", "5000"))}}, "t", 5000, 1,
      15000);
  const std::atomic_bool cancelled{false};
  const Budget budget{Clock::now() + std::chrono::milliseconds(timeout),
                      cancelled};
  if (args.words == std::vector<std::string>{"static", "info"})
    return StaticInfo(options, budget);
  if (args.words == std::vector<std::string>{"static", "catalog"})
    return StaticCatalog(options, budget);
  if (args.words.size() == 3 && args.words[1] == "read") {
    options.table = args.words[2];
    const auto limit =
        OptionalInteger({{"n", ParseDecimal(args.option("--max-rows", "100"))}},
                        "n", 100, 1, 200);
    return StaticRead(options, limit, budget);
  }
  throw Error("E_INPUT", "Use static info, catalog, or read TABLE.");
}

Json RunCommand(const Arguments& args,
                const std::optional<StaticOptions>& options) {
  if (args.words.empty())
    throw Error("E_INPUT", "Specify a command. See --help.");
  const auto& command = args.words.front();
  const auto session_id = args.option("--session");
  if (command == "static") {
    if (!options)
      throw Error("E_INPUT", "Select a static analysis backend.");
    return RunStatic(args, *options);
  }
  if (command == "sessions") {
    return {{"ok", true}, {"sessions", ListSessions()}};
  }
  if (command == "doctor") {
    return {{"ok", true},
            {"protocol_version", kProtocolVersion},
            {"schema_hash", SchemaHash()},
            {"registry", ToUtf8(SessionDirectory().c_str())},
            {"sessions", ListSessions()}};
  }
  if (command == "schema") {
    if (args.words.size() > 2)
      throw Error("E_INPUT", "Expected at most one table name.");
    return RequestSchema(
        args.offline ? Json(nullptr) : SelectSession(session_id),
        args.words.size() == 2 ? args.words[1] : "", options.has_value());
  }
  if (command == "checkpoint" && args.words.size() == 4 &&
      args.words[1] == "diff")
    return DiffCheckpoints(ToWide(args.words[2]), ToWide(args.words[3]));
  if (command == "checkpoint" && args.words.size() == 3 &&
      args.words[1] == "capture")
    return CaptureCheckpoint(SelectSession(session_id), ToWide(args.words[2]));
  if (command == "query") {
    const bool stdin_sql = args.words.size() == 2 && args.words[1] == "-";
    const bool literal = args.options.contains("-q");
    const bool file = args.options.contains("-f");
    if (static_cast<int>(stdin_sql) + static_cast<int>(literal) +
                static_cast<int>(file) !=
            1 ||
        args.words.size() != (stdin_sql ? 2U : 1U))
      throw Error("E_INPUT",
                  "Specify exactly one SQL input using -q, -f, or -.");
    auto sql = stdin_sql ? ReadBounded(std::cin, kMaxSql)
               : file    ? ReadFile(ToWide(args.option("-f")), kMaxSql)
                         : args.option("-q");
    return SendQuery(
        SelectSession(session_id),
        {{"sql", std::move(sql)},
         {"max_rows", ParseDecimal(args.option("--max-rows", "1000"))},
         {"timeout_ms", ParseDecimal(args.option("--timeout-ms", "5000"))}},
        NewId(), 1000, options ? &*options : nullptr);
  }
  if (command == "status")
    return xsql::Exchange(SelectSession(session_id), {{"op", "status"}});
  if (command == "action" && args.words.size() == 3 &&
      args.words[1] == "status")
    return xsql::Exchange(SelectSession(session_id),
                          {{"op", "action_status"}, {"id", args.words[2]}});
  if (command == "annotation" || command == "breakpoint" ||
      command == "control") {
    if (session_id.empty() || args.option("--reason").empty() ||
        args.words.size() < 2)
      throw Error("E_INPUT",
                  "Changes require a verb, explicit --session, and --reason.");
    const auto session = SelectSession(session_id);
    auto status = xsql::Exchange(session, {{"op", "status"}});
    if (!status.value("ok", false))
      return status;
    auto id = args.option("--id");
    if (id.empty())
      id = NewId();
    const auto epoch = args.option("--epoch");
    const auto generation = args.option("--generation");
    Json request{
        {"op", command},
        {"verb", args.words[1]},
        {"id", id},
        {"reason", args.option("--reason")},
        {"expected_epoch",
         epoch.empty() ? status.at("epoch") : Json(ParseDecimal(epoch))},
        {"generation", generation.empty() ? status.at("generation")
                                          : Json(ParseDecimal(generation))}};
    if (command == "annotation") {
      const auto count = args.words.size();
      if (count != 4 && count != 5)
        throw Error("E_INPUT",
                    "Expected annotation kind and address, optionally followed "
                    "by text.");
      request["kind"] = args.words[2];
      request["addr"] = args.words[3];
      if (count == 5)
        request["text"] = args.words[4];
    } else if (args.words.size() != 2)
      throw Error("E_INPUT", "Unexpected action arguments.");
    try {
      return xsql::Exchange(session, request);
    } catch (const Error& problem) {
      auto result = Failure(problem);
      result["action_id"] = id;
      result["session"] = session_id;
      return result;
    }
  }
  throw Error("E_INPUT", "Unknown command or arguments. See --help.");
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  try {
    const auto args = ParseArguments(argc, argv);
    if (!args.words.empty() && args.words.front() == "help") {
      std::cout << usage;
      return 0;
    }
    const auto options = StaticConfig(args);
    if (args.words == std::vector<std::string>{"mcp"})
      return RunMcp(args.option("--session"), options, args.compact);
    if (args.compact)
      throw Error("E_INPUT", "--compact applies to MCP only.");
    const auto result = RunCommand(args, options);
    PrintResult(result, !args.json && !args.words.empty() &&
                            args.words.front() == "query");
    if (result.value("ok", false))
      return 0;
    const auto code = result.at("error").value("code", "");
    if (code == "E_INPUT")
      return 2;
    if (code == "E_NOT_FOUND" || code == "E_AMBIGUOUS")
      return 3;
    if (code == "E_VERSION")
      return 4;
    if (code == "E_PERM")
      return 5;
    if (code == "E_TIMEOUT" || code == "E_CANCELLED")
      return 6;
    return 1;
  } catch (const Error& problem) {
    PrintResult(Failure(problem), false);
    if (problem.code == "E_INPUT")
      return 2;
    if (problem.code == "E_NOT_FOUND" || problem.code == "E_AMBIGUOUS")
      return 3;
    if (problem.code == "E_VERSION")
      return 4;
    return 1;
  } catch (...) {
    PrintResult(Failure(Error("E_INTERNAL", "Could not process the command.")),
                false);
    return 1;
  }
}
