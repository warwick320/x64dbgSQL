#ifndef X64DBGSQL_DEBUGGER_SESSION_HPP
#define X64DBGSQL_DEBUGGER_SESSION_HPP

#include <map>

#include "debugger/fixture.h"
#include "debugger/provider.h"

namespace xsql::debugger {

inline constexpr int kAnnotationMenu = 1;
inline constexpr auto kApplyCommand = "x64dbgsql_apply_local";
struct Action {
  Json request;
  State state;
  std::string ticket;
  std::string status = "accepted";
  std::string detail;
  std::int64_t first_seq = 0;
  Clock::time_point accepted = Clock::now();
  DWORD client = 0;
  bool dispatched = false;
  bool issued = false;
  bool audit_recorded = true;
};

class Plugin {
 public:
  explicit Plugin(int handle) : handle_(handle), provider_(timeline_) {}
  void Start();
  void Stop();
  void SetUpGui(int menu);
  void OnEvent(CBTYPE type, void* info);
  void Dispatch(std::string_view ticket);

 private:
  Json HandleRequest(const Json& value, DWORD client);
  Json ActionResult(const std::string& key);
  Json Submit(const Json& request, const std::string& operation, DWORD client);
  void Refresh();
  void Complete(const std::string& key, const std::string& status,
                const std::string& detail);
  bool Audit(std::string_view operation, const std::string& key,
             const std::string& reason, const std::string& outcome,
             DWORD client) noexcept;
  void EditAnnotation(const Json& request);
  void EditBreakpoint(const Json& request);
  int handle_;
  std::atomic_bool active_{true};
  std::atomic_bool cancelled_{false};
  std::mutex query_mutex_;
  std::mutex cancel_mutex_;
  std::string current_query_;
  DWORD query_client_ = 0;
  Timeline timeline_;
  bool enable_annotations_at_start_ = false;
  Provider provider_;
  Fixture fixture_;
  std::optional<duint> fixture_bp_;
  std::mutex actions_mutex_;
  std::map<std::string, Action> actions_;
  std::string pending_;
  std::string id_;
  std::filesystem::path audit_path_;
  std::mutex audit_mutex_;
  std::unique_ptr<PipeServer> server_;
};

}  // namespace xsql::debugger

#endif  // X64DBGSQL_DEBUGGER_SESSION_HPP
