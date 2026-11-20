#ifndef X64DBGSQL_DEBUGGER_FIXTURE_HPP
#define X64DBGSQL_DEBUGGER_FIXTURE_HPP

#include <optional>

#include "debugger/timeline.h"
#include "platform/windows_handle.h"

namespace xsql::debugger {

class Fixture {
 public:
  Fixture();
  bool configured() const;
  bool Matches(const State& state, Timeline& timeline);
  duint MarkerAddress() const;

 private:
  std::wstring path_;
  platform::Handle file_;
  std::mutex identity_mutex_;
  std::optional<FILETIME> created_;
};

}  // namespace xsql::debugger

#endif  // X64DBGSQL_DEBUGGER_FIXTURE_HPP
