#include <algorithm>
#include <fstream>

#include "transport/pipe_io.h"

namespace xsql {

using platform::Handle;
using transport::Endpoint;
using transport::IsValidId;
using transport::MillisecondsLeft;
using transport::ParseJson;
using transport::PipeName;
using transport::ReceiveFrame;
using transport::SendFrame;
using transport::Transfer;

namespace {
Json ReadRegistryRecord(const std::filesystem::path& path) {
  if (std::filesystem::file_size(path) > 4096)
    throw Error("E_PROTOCOL", "Invalid session record.");
  std::ifstream input(path, std::ios::binary);
  std::string body((std::istreambuf_iterator<char>(input)), {});
  auto value = ParseJson(body);
  const auto id = RequireString(value, "session", 32);
  if (!IsValidId(id) || path.stem().wstring() != ToWide(id))
    throw Error("E_PROTOCOL", "Invalid session record.");
  return value;
}

Handle OpenPipe(const Json& session, Endpoint endpoint,
                Clock::time_point deadline) {
  const auto name = PipeName(RequireString(session, "session", 32), endpoint);
  Handle pipe;
  do {
    pipe = Handle(CreateFileW(
        name.c_str(), FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 0,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        nullptr));
    if (pipe.valid())
      break;
    if (GetLastError() != ERROR_PIPE_BUSY)
      throw Error("E_NOT_FOUND", "The local session is no longer available.");
  } while (MillisecondsLeft(deadline) &&
           WaitNamedPipeW(name.c_str(), MillisecondsLeft(deadline)));
  if (!pipe.valid())
    throw Error("E_BUSY", "The session's named pipe is busy.");
  ULONG actual = 0;
  if (!GetNamedPipeServerProcessId(pipe.get(), &actual) ||
      actual != session.at("pid").get<ULONG>())
    throw Error("E_PROTOCOL",
                "The named pipe server does not match the advertised process.");
  return pipe;
}

Json Hello(HANDLE pipe, const Json& session, Clock::time_point deadline) {
  SendFrame(pipe, nullptr,
            {{"op", "hello"}, {"version", kProtocolVersion}}, deadline);
  auto welcome = ReceiveFrame(pipe, nullptr, deadline);
  if (!welcome.value("ok", false))
    return welcome;
  if (welcome.at("session") != session.at("session") ||
      welcome.at("pid") != session.at("pid"))
    throw Error("E_PROTOCOL",
                "The server returned a different session identity.");
  if (welcome.value("version", 0) != kProtocolVersion ||
      welcome.value("schema_hash", "") != SchemaHash())
    throw Error("E_VERSION",
                "CLI and plugin protocol or schema versions differ.");
  return welcome;
}

Json Request(Handle& pipe, const Json& request, Clock::time_point deadline) {
  SendFrame(pipe.get(), nullptr, request, deadline);
  auto result = ReceiveFrame(pipe.get(), nullptr, deadline);
  char acknowledgement = 1;
  try {
    Transfer(pipe.get(), nullptr, &acknowledgement, 1, true, deadline);
  } catch (const Error&) {
    pipe = Handle();
  }
  return result;
}
}  // namespace

struct ReadChannel::Impl {
  Handle pipe;
  Json session;
  Clock::time_point reuse_until{};
};

ReadChannel::ReadChannel() : impl_(std::make_unique<Impl>()) {}
ReadChannel::~ReadChannel() = default;

Json ReadChannel::Exchange(const Json& session, const Json& request,
                           int timeout_ms) {
  const auto op = request.value("op", "");
  if (op != "query" && op != "schema")
    return xsql::Exchange(session, request, timeout_ms);
  const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
  auto& state = *impl_;
  if (state.session != session || Clock::now() >= state.reuse_until)
    state.pipe = Handle();
  if (!state.pipe.valid()) {
    try {
      state.pipe = OpenPipe(session, Endpoint::kStream,
                            std::min(deadline, Clock::now() +
                                                   std::chrono::milliseconds(10)));
    } catch (const Error& error) {
      if (error.code == "E_BUSY" || error.code == "E_NOT_FOUND")
        return xsql::Exchange(session, request,
                              static_cast<int>(MillisecondsLeft(deadline)));
      throw;
    }
    try {
      auto welcome = Hello(state.pipe.get(), session, deadline);
      if (!welcome.value("ok", false)) {
        state.pipe = Handle();
        return welcome;
      }
      state.session = session;
    } catch (...) {
      state.pipe = Handle();
      throw;
    }
  }
  try {
    auto result = Request(state.pipe, request, deadline);
    state.reuse_until = Clock::now() + transport::kStreamIdle -
                        std::chrono::seconds(2);
    return result;
  } catch (...) {
    state.pipe = Handle();
    throw;
  }
}

Json Exchange(const Json& session, const Json& request, int timeout_ms,
              ReadChannel* channel) {
  if (channel)
    return channel->Exchange(session, request, timeout_ms);
  const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
  const auto operation = request.is_null() ? "" : request.value("op", "");
  const bool status = request.is_null() || operation == "status" ||
                      operation == "cancel" || operation == "action_status";
  auto pipe = OpenPipe(session, status ? Endpoint::kStatus : Endpoint::kQuery,
                       deadline);
  auto welcome = Hello(pipe.get(), session, deadline);
  if (request.is_null() || !welcome.value("ok", false))
    return welcome;
  return Request(pipe, request, deadline);
}

Json ListSessions() {
  Json result = Json::array();
  const auto directory = SessionDirectory();
  if (!std::filesystem::is_directory(directory))
    return result;
  for (const auto& entry : std::filesystem::directory_iterator(directory)) {
    if (entry.path().extension() != L".json")
      continue;
    try {
      auto record = ReadRegistryRecord(entry.path());
      const auto welcome = Exchange(record, nullptr, 500);
      if (welcome.value("ok", false))
        result.push_back(welcome);
      else if (welcome.at("error").value("code", "") == "E_VERSION") {
        record["compatible"] = false;
        result.push_back(std::move(record));
      }
    } catch (const Error& error) {
      if (error.code == "E_VERSION") {
        try {
          auto record = ReadRegistryRecord(entry.path());
          record["compatible"] = false;
          result.push_back(std::move(record));
        } catch (...) {
        }
      }
    } catch (const std::exception&) {
    }
  }
  auto& entries = result.get_ref<Json::array_t&>();
  std::ranges::sort(entries, [](const Json& a, const Json& b) {
    return a.at("session") < b.at("session");
  });
  return result;
}

Json SelectSession(std::string_view id) {
  if (!id.empty()) {
    PipeName(id);
    const auto file = SessionDirectory() / (ToWide(id) + L".json");
    if (!std::filesystem::is_regular_file(file))
      throw Error("E_NOT_FOUND", "No registered session has that ID.");
    return ReadRegistryRecord(file);
  }
  auto available = ListSessions();
  if (available.empty())
    throw Error("E_NOT_FOUND",
                "No live x64dbgSQL session. Try doctor or schema --offline.");
  if (available.size() != 1)
    throw Error(
        "E_AMBIGUOUS",
        "Multiple sessions are available. Use sessions and --session <id>.");
  return available.front();
}

}  // namespace xsql
