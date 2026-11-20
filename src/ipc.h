#ifndef X64DBGSQL_IPC_H_
#define X64DBGSQL_IPC_H_

#include <filesystem>
#include <functional>
#include <memory>

#include "core.h"

namespace xsql {

std::string NewId();
std::filesystem::path SessionDirectory();
Json ListSessions();
class ReadChannel {
 public:
  ReadChannel();
  ~ReadChannel();
  ReadChannel(const ReadChannel&) = delete;
  ReadChannel& operator=(const ReadChannel&) = delete;
  Json Exchange(const Json& session, const Json& request, int timeout_ms);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

Json Exchange(const Json& session, const Json& request, int timeout_ms = 18000,
              ReadChannel* channel = nullptr);
Json SelectSession(std::string_view id);
std::string ToUtf8(std::wstring_view text);
std::wstring ToWide(std::string_view text);
std::string FileSha256(const std::filesystem::path& file,
                       const Budget* budget = nullptr);

class PipeServer {
 public:
  using Handler = std::function<Json(const Json&, std::uint32_t)>;
  PipeServer(std::string id, Json information, Handler handler);
  ~PipeServer();
  PipeServer(const PipeServer&) = delete;
  PipeServer& operator=(const PipeServer&) = delete;
  void Stop();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace xsql

#endif  // X64DBGSQL_IPC_H_
