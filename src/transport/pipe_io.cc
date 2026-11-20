#include "transport/pipe_io.h"

#include <algorithm>
#include <array>

namespace xsql::transport {

using platform::Handle;

bool IsValidId(std::string_view id) {
  return id.size() == 32 && std::ranges::all_of(id, [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

std::wstring PipeName(std::string_view id, Endpoint endpoint) {
  if (!IsValidId(id))
    throw Error("E_INPUT", "Invalid session ID.");
  auto name = L"\\\\.\\pipe\\x64dbgsql-" + ToWide(id);
  if (endpoint == Endpoint::kStatus)
    name += L"-status";
  if (endpoint == Endpoint::kStream)
    name += L"-stream";
  return name;
}

DWORD MillisecondsLeft(Clock::time_point deadline) {
  const auto ticks = std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - Clock::now())
                         .count();
  return static_cast<DWORD>(std::clamp<std::int64_t>(ticks, 0, 60000));
}

DWORD FinishIo(HANDLE pipe, OVERLAPPED& io, HANDLE stop,
               Clock::time_point deadline) {
  const HANDLE signals[]{io.hEvent, stop};
  const auto waited = WaitForMultipleObjects(stop ? 2 : 1, signals, FALSE,
                                             MillisecondsLeft(deadline));
  DWORD size = 0;
  if (waited == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &io, &size, FALSE))
    return size;
  if (waited != WAIT_OBJECT_0) {
    CancelIoEx(pipe, &io);
    GetOverlappedResult(pipe, &io, &size, TRUE);
    throw Error("E_TRANSPORT", "Pipe operation timed out or stopped.");
  }
  throw Error("E_TRANSPORT", "The pipe connection ended.");
}

void Transfer(HANDLE pipe, HANDLE stop, char* data, DWORD size, bool write,
              Clock::time_point deadline) {
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event.valid())
    throw Error("E_TRANSPORT", "Could not initialize pipe I/O.");
  while (size != 0) {
    OVERLAPPED io{};
    io.hEvent = event.get();
    ResetEvent(io.hEvent);
    DWORD used = 0;
    const auto immediate = write ? WriteFile(pipe, data, size, &used, &io)
                                 : ReadFile(pipe, data, size, &used, &io);
    if (!immediate) {
      if (GetLastError() != ERROR_IO_PENDING)
        throw Error("E_TRANSPORT", "Pipe I/O failed.");
      used = FinishIo(pipe, io, stop, deadline);
    }
    if (!used)
      throw Error("E_TRANSPORT", "The pipe connection ended.");
    data += used;
    size -= used;
  }
}

Json ParseJson(const std::string& value) {
  return Json::parse(value, [](int depth, Json::parse_event_t, Json&) {
    if (depth > 32)
      throw Error("E_PROTOCOL", "JSON nesting exceeds the protocol limit.");
    return true;
  });
}

Json ReceiveFrame(HANDLE pipe, HANDLE stop, Clock::time_point deadline) {
  std::array<unsigned char, 4> header{};
  Transfer(pipe, stop, reinterpret_cast<char*>(header.data()), 4, false,
           deadline);
  const auto size = static_cast<std::uint32_t>(header[0]) |
                    (static_cast<std::uint32_t>(header[1]) << 8) |
                    (static_cast<std::uint32_t>(header[2]) << 16) |
                    (static_cast<std::uint32_t>(header[3]) << 24);
  if (!size || size > kMaxFrame)
    throw Error("E_PROTOCOL", "Invalid frame length.");
  std::string body(size, '\0');
  Transfer(pipe, stop, body.data(), size, false, deadline);
  try {
    auto document = ParseJson(body);
    if (!document.is_object())
      throw Error("E_PROTOCOL", "The frame must contain a JSON object.");
    return document;
  } catch (const Json::exception&) {
    throw Error("E_PROTOCOL", "The frame is not valid UTF-8 JSON.");
  }
}

void SendFrame(HANDLE pipe, HANDLE stop, const Json& data,
               Clock::time_point deadline) {
  auto body = SerializeUtf8(data);
  if (body.size() > kMaxFrame)
    throw Error("E_PROTOCOL", "Frame exceeds the wire limit.");
  auto size = static_cast<std::uint32_t>(body.size());
  std::array<char, 4> header{};
  for (auto& byte : header) {
    byte = static_cast<char>(size & 0xff);
    size >>= 8;
  }
  Transfer(pipe, stop, header.data(), 4, true, deadline);
  Transfer(pipe, stop, body.data(), static_cast<DWORD>(body.size()), true,
           deadline);
}

}  // namespace xsql::transport
