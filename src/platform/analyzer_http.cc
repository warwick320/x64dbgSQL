#include "platform/analyzer_http.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <memory>

#include "ipc.h"

namespace xsql::platform {
namespace {

using HttpHandle = std::unique_ptr<void, decltype(&WinHttpCloseHandle)>;

unsigned short LoopbackPort(std::string_view url) {
  constexpr std::string_view kNumeric = "http://127.0.0.1:";
  constexpr std::string_view kLocalhost = "http://localhost:";
  if (url.starts_with(kNumeric)) {
    url.remove_prefix(kNumeric.size());
  } else if (url.starts_with(kLocalhost)) {
    url.remove_prefix(kLocalhost.size());
  } else {
    throw Error("E_INPUT",
                "Use a loopback HTTP endpoint such as http://127.0.0.1:8080.");
  }
  if (url.ends_with('/'))
    url.remove_suffix(1);
  unsigned short port = 0;
  const auto last = url.data() + url.size();
  const auto [end, status] = std::from_chars(url.data(), last, port);
  if (status != std::errc{} || end != last || !port) {
    throw Error("E_INPUT",
                "Analyzer URL must contain a port and no path or credentials.");
  }
  return port;
}

std::wstring Token() {
  std::array<wchar_t, 4097> buffer{};
  const auto size =
      GetEnvironmentVariableW(L"X64DBGSQL_STATIC_TOKEN", buffer.data(),
                              static_cast<DWORD>(buffer.size()));
  if (size >= buffer.size())
    throw Error("E_INPUT", "Analyzer token exceeds 4096 characters.");
  std::wstring token(buffer.data(), size);
  if (!std::ranges::all_of(token,
                           [](wchar_t c) { return c >= 0x21 && c <= 0x7e; })) {
    throw Error("E_INPUT",
                "Analyzer token contains disallowed header characters.");
  }
  return token;
}

int Milliseconds(const Budget& budget) {
  budget.Check();
  return static_cast<int>(std::clamp<std::int64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(budget.deadline -
                                                            Clock::now())
          .count(),
      1, 15000));
}

void RequireHttp(BOOL success, const Budget& budget) {
  if (success)
    return;
  const auto status = GetLastError();
  budget.Check();
  if (status == ERROR_WINHTTP_TIMEOUT)
    throw Error("E_TIMEOUT", "The analyzer HTTP request timed out.");
  throw Error("E_STATIC_CONNECTION",
              "Could not reach the analyzer SQL endpoint.",
              "Check that its /query server is listening on the configured "
              "local port.");
}

struct AnalyzerConnection {
  unsigned short port;
  std::wstring token;
  HttpHandle internet{nullptr, WinHttpCloseHandle};
  HttpHandle server{nullptr, WinHttpCloseHandle};

  HINTERNET Connect(const Budget& budget) {
    if (!internet) {
      internet.reset(WinHttpOpen(L"x64dbgSQL", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                 WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0));
      if (!internet)
        RequireHttp(FALSE, budget);
    }
    if (!server) {
      server.reset(WinHttpConnect(internet.get(), L"127.0.0.1", port, 0));
      if (!server)
        RequireHttp(FALSE, budget);
    }
    return server.get();
  }
};

Json Post(AnalyzerConnection& connection, std::string_view sql,
          const Budget& budget) {
  const auto timeout = Milliseconds(budget);
  HttpHandle request(
      WinHttpOpenRequest(connection.Connect(budget), L"POST", L"/query", nullptr,
                         WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0),
      WinHttpCloseHandle);
  if (!request)
    RequireHttp(FALSE, budget);
  DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES |
                   WINHTTP_DISABLE_AUTHENTICATION;
  RequireHttp(WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE,
                               &disabled, sizeof(disabled)),
              budget);
  RequireHttp(
      WinHttpSetTimeouts(request.get(), timeout, timeout, timeout, timeout),
      budget);
  auto headers =
      L"Content-Type: text/plain; charset=utf-8\r\nAccept: "
      L"application/json\r\nX-XSQL-Timeout: " +
      std::to_wstring(timeout) + L"\r\n";
  if (!connection.token.empty())
    headers += L"Authorization: Bearer " + connection.token + L"\r\n";
  auto body = std::string(sql);
  const auto length = static_cast<DWORD>(body.size());
  RequireHttp(WinHttpSendRequest(request.get(), headers.c_str(),
                                 static_cast<DWORD>(headers.size()),
                                 body.data(), length, length, 0),
              budget);
  RequireHttp(WinHttpReceiveResponse(request.get(), nullptr), budget);
  DWORD status = 0;
  DWORD status_size = sizeof(status);
  RequireHttp(
      WinHttpQueryHeaders(request.get(),
                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                          WINHTTP_NO_HEADER_INDEX),
      budget);
  if (status == 401 || status == 403) {
    throw Error("E_STATIC_AUTH", "Analyzer rejected authentication.",
                "Set X64DBGSQL_STATIC_TOKEN for this endpoint.");
  }
  if (status != 200) {
    throw Error("E_STATIC_QUERY", "Analyzer HTTP endpoint returned status " +
                                      std::to_string(status) + ".");
  }
  std::string response;
  std::array<char, 8192> block{};
  DWORD received = 0;
  do {
    const auto remaining = Milliseconds(budget);
    RequireHttp(WinHttpSetTimeouts(request.get(), remaining, remaining,
                                   remaining, remaining),
                budget);
    RequireHttp(WinHttpReadData(request.get(), block.data(),
                                static_cast<DWORD>(block.size()), &received),
                budget);
    if (response.size() + received > analysis::kMaxRemoteBytes) {
      throw Error(
          "E_STATIC_LIMIT",
          "Analyzer response exceeded 512 KiB. Narrow the range or row limit.");
    }
    response.append(block.data(), received);
  } while (received);
  budget.Check();
  return Json::parse(response, [](int depth, Json::parse_event_t, Json&) {
    if (depth > 32)
      throw Error("E_STATIC_PROTOCOL",
                  "Analyzer JSON exceeds the nesting limit.");
    return true;
  });
}

}  // namespace

analysis::Source::Transport AnalyzerHttp(std::string_view url) {
  auto connection = std::make_shared<AnalyzerConnection>(
      AnalyzerConnection{LoopbackPort(url), Token()});
  return [connection = std::move(connection)](std::string_view sql,
                                              const Budget& budget) {
    return Post(*connection, sql, budget);
  };
}

}  // namespace xsql::platform
