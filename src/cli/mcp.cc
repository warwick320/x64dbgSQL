#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <mutex>
#include <thread>

#include "cli/commands.h"

namespace xsql::cli {

static Json ListTools(bool with_source) {
  Json query_inputs{{"sql", {{"type", "string"}, {"maxLength", kMaxSql}}},
                    {"max_rows",
                     {{"type", "integer"},
                      {"minimum", 1},
                      {"maximum", 1000},
                      {"default", 200}}},
                    {"timeout_ms",
                     {{"type", "integer"},
                      {"minimum", 1},
                      {"maximum", 15000},
                      {"default", 5000}}}};
  if (with_source)
    query_inputs["with_static"] = {{"type", "boolean"}, {"default", true}};
  const auto input = [](const Json& properties, Json required) {
    return Json{{"type", "object"},
                {"properties", properties},
                {"required", std::move(required)},
                {"additionalProperties", false}};
  };
  const auto tool = [](std::string_view name, std::string_view description,
                       Json schema) {
    return Json{
        {"name", name},
        {"description", description},
        {"inputSchema", std::move(schema)},
        {"annotations", {{"readOnlyHint", true}, {"openWorldHint", false}}}};
  };
  Json result = Json::array(
      {tool("x64dbgsql_query",
            "Run one read-only relational query. A configured analyzer adds "
            "static_stop_context and static_functions.",
            input(query_inputs, Json::array({"sql"}))),
       tool("x64dbgsql_schema",
            "Discover debugger tables, columns, views, and their state "
            "requirements.",
            input({{"table", {{"type", "string"}, {"maxLength", 128}}}},
                  Json::array()))});
  if (with_source) {
    result.push_back(
        tool("x64dbgsql_static_catalog",
             "Discover the configured analyzer's native tables and views.",
             input(Json::object(), Json::array())));
    const Json identifier{{"type", "string"},
                          {"minLength", 1},
                          {"maxLength", 128},
                          {"pattern", "^[A-Za-z_][A-Za-z0-9_]*$"}};
    const Json address{{"type", "string"}, {"minLength", 1}, {"maxLength", 20}};
    Json read_inputs{
        {"table", identifier},
        {"where",
         {{"type", "object"},
          {"maxProperties", 8},
          {"propertyNames", identifier},
          {"additionalProperties", {{"type", "string"}, {"maxLength", 512}}}}},
        {"columns",
         {{"type", "array"},
          {"minItems", 1},
          {"maxItems", analysis::kMaxProjectionColumns},
          {"uniqueItems", true},
          {"items", identifier}}},
        {"range",
         input({{"column", identifier}, {"start", address}, {"end", address}},
               Json::array({"column", "start", "end"}))},
        {"max_rows",
         {{"type", "integer"},
          {"minimum", 1},
          {"maximum", analysis::kMaxNativeRows},
          {"default", 100}}}};
    const Json timeout{{"type", "integer"},
                       {"minimum", 1},
                       {"maximum", 15000},
                       {"default", 5000}};
    const auto required = Json::array({"table"});
    auto batch_item = input(read_inputs, required);
    read_inputs["timeout_ms"] = timeout;
    result.push_back(tool("x64dbgsql_static_read",
                          "Read a bounded result from a native table or view.",
                          input(read_inputs, required)));
    result.push_back(tool(
        "x64dbgsql_static_read_batch",
        "Read up to 32 native table results in order with one timeout and "
        "shared analyzer identity checks. The combined result is limited to "
        "256 KiB.",
        input({{"reads",
                {{"type", "array"},
                 {"minItems", 1},
                 {"maxItems", kMaxStaticBatchReads},
                 {"items", std::move(batch_item)}}},
               {"timeout_ms", timeout}},
              Json::array({"reads"}))));
  }
  return result;
}

static void RequireFields(const Json& object,
                          std::initializer_list<std::string_view> allowed) {
  if (!object.is_object())
    throw Error("E_INPUT", "Expected an object for the native read arguments.");
  for (auto field = object.begin(); field != object.end(); ++field) {
    if (std::ranges::find(allowed, field.key()) == allowed.end())
      throw Error("E_INPUT", "Unexpected field in native read arguments.");
  }
}

static StaticReadRequest ReadArguments(const Json& args,
                                       analysis::ReadOptions read, bool batch) {
  if (batch)
    RequireFields(args, {"table", "where", "columns", "range", "max_rows"});
  auto table = RequireString(args, "table", 128);
  const auto filters = args.value("where", Json::object());
  if (!filters.is_object() || filters.size() > 8)
    throw Error("E_INPUT", "Expected at most eight analyzer predicates.");
  read.filters.clear();
  for (const auto& [column, value] : filters.items()) {
    if (!value.is_string())
      throw Error("E_INPUT", "Analyzer predicates require string values.");
    read.filters.push_back({column, value.get<std::string>()});
  }
  if (const auto columns = args.find("columns"); columns != args.end()) {
    if (!columns->is_array() || columns->empty() ||
        columns->size() > analysis::kMaxProjectionColumns)
      throw Error("E_INPUT", "Project between 1 and 32 analyzer columns.");
    read.columns = columns->get<std::vector<std::string>>();
  }
  if (args.contains("range")) {
    const auto& range = args.at("range");
    if (batch)
      RequireFields(range, {"column", "start", "end"});
    const auto address = [&](const char* field) {
      if (batch)
        return analysis::ParseAddress(RequireString(range, field, 20));
      return analysis::ParseAddress(range.at(field));
    };
    read.range = analysis::AddressRange{RequireString(range, "column", 128),
                                        address("start"), address("end")};
  }
  const auto limit =
      OptionalInteger(args, "max_rows", 100, 1, analysis::kMaxNativeRows);
  return {std::move(table), std::move(read), limit};
}

static std::vector<StaticReadRequest> BatchArguments(const Json& args,
                                                     const Budget& budget) {
  RequireFields(args, {"reads", "timeout_ms"});
  const auto reads = args.find("reads");
  if (reads == args.end() || !reads->is_array() || reads->empty() ||
      reads->size() > kMaxStaticBatchReads)
    throw Error("E_INPUT", "Specify between 1 and 32 native reads.");
  std::vector<StaticReadRequest> requests;
  requests.reserve(reads->size());
  for (const auto& read : *reads) {
    budget.Check();
    requests.push_back(ReadArguments(read, {}, true));
  }
  return requests;
}

int RunMcp(std::string selected, std::optional<StaticOptions> options,
           bool compact) {
  std::mutex output_mutex;
  const auto write = [&](const Json& response) {
    std::lock_guard lock(output_mutex);
    std::cout << SerializeUtf8(response) << '\n' << std::flush;
  };
  const auto reply = [&](const Json& id, const Json& result) {
    write({{"jsonrpc", "2.0"}, {"id", id}, {"result", result}});
  };
  const auto error = [&](const Json& id, int code, const char* message) {
    write({{"jsonrpc", "2.0"},
           {"id", id},
           {"error", {{"code", code}, {"message", message}}}});
  };
  const auto tool_reply = [&](const Json& id, const Json& result) {
    const bool ok = result.value("ok", false);
    reply(id,
          {{"content",
            Json::array({{{"type", "text"},
                          {"text", compact && ok ? "See structuredContent."
                                                  : SerializeUtf8(result)}}})},
           {"structuredContent", result},
           {"isError", !ok}});
  };

  bool negotiated = false;
  bool ready = false;
  std::atomic_bool busy{false};
  std::atomic_bool cancelled{false};
  std::mutex request_mutex;
  Json current_rpc;
  Json current_session;
  std::string current_wire;
  ReadChannel channel;
  std::jthread worker;
  for (;;) {
    std::string line;
    char c = 0;
    bool too_long = false;
    while (std::cin.get(c) && c != '\n') {
      if (line.size() == kMaxFrame)
        too_long = true;
      if (!too_long)
        line.push_back(c);
    }
    if (too_long) {
      error(nullptr, -32700, "Message exceeds the stdio limit");
      continue;
    }
    if (!std::cin && line.empty())
      break;
    auto message = Json::parse(
        line, [](int depth, Json::parse_event_t, Json&) { return depth <= 32; },
        false);
    if (message.is_discarded()) {
      error(nullptr, -32700, "Parse error");
      continue;
    }
    if (!message.is_object()) {
      error(nullptr, -32600, "Invalid request");
      continue;
    }
    const Json id = message.value("id", Json(nullptr));
    try {
      if (message.value("jsonrpc", "") != "2.0" ||
          !message.at("method").is_string()) {
        error(id, -32600, "Invalid request");
        continue;
      }
      const auto method = message.at("method").get<std::string>();
      const auto params = message.value("params", Json::object());
      if (method == "notifications/initialized") {
        ready = negotiated;
        continue;
      }
      if (method == "notifications/cancelled") {
        Json session;
        std::string request;
        {
          std::lock_guard lock(request_mutex);
          if (busy.load() && params.at("requestId") == current_rpc) {
            cancelled.store(true);
            session = current_session;
            request = current_wire;
          }
        }
        if (!session.is_null()) {
          try {
            xsql::Exchange(session, {{"op", "cancel"}, {"request_id", request}},
                           800);
          } catch (const std::exception&) {
          }
        }
        continue;
      }
      if (!message.contains("id"))
        continue;
      if (method == "initialize") {
        if (negotiated) {
          error(id, -32600, "Already initialized");
          continue;
        }
        const auto requested = params.at("protocolVersion").get<std::string>();
        const auto version =
            requested == "2025-06-18" ? requested : "2025-11-25";
        negotiated = true;
        reply(id,
              {{"protocolVersion", version},
               {"capabilities", {{"tools", Json::object()}}},
               {"serverInfo", {{"name", "x64dbgsql"}, {"version", "0.1.0"}}}});
      } else if (method == "ping") {
        reply(id, Json::object());
      } else if (!ready) {
        error(id, -32000, "Server has not been initialized");
      } else if (method == "tools/list") {
        reply(id, {{"tools", ListTools(options.has_value())}});
      } else if (method == "tools/call") {
        const auto name = params.at("name").get<std::string>();
        const auto args = params.value("arguments", Json::object());
        const bool batch = name == "x64dbgsql_static_read_batch";
        const bool native = batch || name == "x64dbgsql_static_read" ||
                            name == "x64dbgsql_static_catalog";
        if ((!native && name != "x64dbgsql_query" &&
             name != "x64dbgsql_schema") ||
            (native && !options) || !args.is_object()) {
          error(id, -32602, "Unknown tool or invalid arguments");
          continue;
        }
        if (busy.load()) {
          tool_reply(id,
                     Failure(Error("E_BUSY",
                                   "One tool call is already in progress.")));
          continue;
        }
        if (worker.joinable())
          worker.join();
        if (name == "x64dbgsql_schema") {
          try {
            const auto table = args.value("table", "");
            tool_reply(id,
                       RequestSchema(selected.empty() ? Json(nullptr)
                                                      : SelectSession(selected),
                                     table, options.has_value(), &channel));
          } catch (const Error& failure_error) {
            tool_reply(id, Failure(failure_error));
          }
          continue;
        }
        Json session;
        if (!native) {
          session = SelectSession(selected);
          selected = session.at("session").get<std::string>();
        }
        auto wire = NewId();
        {
          std::lock_guard lock(request_mutex);
          current_rpc = id;
          current_session = session;
          current_wire = wire;
          cancelled.store(false);
          busy.store(true);
        }
        worker = std::jthread([&, id, session, args, wire, name, native,
                               batch] {
          const auto complete = [&](const Json& result) {
            busy.store(false);
            tool_reply(id, result);
          };
          try {
            if (native) {
              const auto timeout =
                  OptionalInteger(args, "timeout_ms", 5000, 1, 15000);
              const Budget budget{
                  Clock::now() + std::chrono::milliseconds(timeout), cancelled};
              if (name == "x64dbgsql_static_catalog") {
                complete(StaticCatalog(*options, budget));
              } else if (batch) {
                complete(StaticReadBatch(*options, BatchArguments(args, budget),
                                         budget));
              } else {
                auto source = *options;
                auto read = ReadArguments(args, std::move(source.read), false);
                source.table = std::move(read.table);
                source.read = std::move(read.read);
                complete(StaticRead(source, read.limit, budget));
              }
            } else {
              const bool use_source =
                  args.value("with_static", options.has_value());
              if (use_source && !options)
                throw Error("E_STATIC_UNBOUND",
                            "No static source was configured.");
              complete(SendQuery(session, args, wire, 200,
                                 use_source ? &*options : nullptr, &cancelled,
                                 &channel));
            }
          } catch (const Error& problem) {
            complete(Failure(problem));
          } catch (const Json::exception&) {
            complete(Failure(Error("E_INPUT", "Invalid tool arguments.")));
          } catch (...) {
            complete(Failure(Error("E_INTERNAL", "The MCP query failed.")));
          }
        });
      } else {
        error(id, -32601, "Method not found");
      }
    } catch (const Error& problem) {
      if (message.contains("id"))
        tool_reply(id, Failure(problem));
    } catch (const Json::exception&) {
      if (message.contains("id"))
        error(id, -32602, "Invalid request parameters");
    }
  }
  return 0;
}

}  // namespace xsql::cli
