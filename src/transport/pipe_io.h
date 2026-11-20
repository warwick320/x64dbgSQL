#ifndef X64DBGSQL_TRANSPORT_PIPE_IO_HPP
#define X64DBGSQL_TRANSPORT_PIPE_IO_HPP

#include "ipc.h"
#include "platform/windows_handle.h"

namespace xsql::transport {

enum class Endpoint { kQuery, kStatus, kStream };
inline constexpr auto kStreamIdle = std::chrono::seconds(30);

bool IsValidId(std::string_view id);
std::wstring PipeName(std::string_view id, Endpoint endpoint = Endpoint::kQuery);
DWORD MillisecondsLeft(Clock::time_point deadline);
DWORD FinishIo(HANDLE pipe, OVERLAPPED& io, HANDLE stop,
               Clock::time_point deadline);
void Transfer(HANDLE pipe, HANDLE stop, char* data, DWORD size, bool write,
              Clock::time_point deadline);
Json ParseJson(const std::string& value);
Json ReceiveFrame(HANDLE pipe, HANDLE stop, Clock::time_point deadline);
void SendFrame(HANDLE pipe, HANDLE stop, const Json& data,
               Clock::time_point deadline);

}  // namespace xsql::transport

#endif  // X64DBGSQL_TRANSPORT_PIPE_IO_HPP
