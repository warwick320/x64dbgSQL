#include "debugger/fixture.h"

#include <_scriptapi_module.h>

#if __has_include("fixture_hash.h")
#include "fixture_hash.h"
#else
#define XSQL_FIXTURE_SHA256 ""
#endif

namespace xsql::debugger {

namespace {
std::wstring ExecutablePath(HANDLE process) {
  std::wstring path(32768, L'\0');
  DWORD size = static_cast<DWORD>(path.size());
  if (!QueryFullProcessImageNameW(process, 0, path.data(), &size))
    return {};
  path.resize(size);
  return path;
}

}  // namespace

Fixture::Fixture() {
  if (std::string_view(XSQL_FIXTURE_SHA256).empty())
    return;
  const auto executable =
      std::filesystem::path(ExecutablePath(GetCurrentProcess()))
          .filename()
          .wstring();
  if (_wcsicmp(executable.c_str(), L"headless.exe") != 0)
    return;
  std::wstring requested(32768, L'\0');
  const auto length =
      GetEnvironmentVariableW(L"X64DBGSQL_FIXTURE", requested.data(),
                              static_cast<DWORD>(requested.size()));
  if (!length || length >= requested.size())
    return;
  requested.resize(length);
  try {
    path_ = std::filesystem::canonical(requested).wstring();
    const auto candidate =
        CreateFileW(path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                    OPEN_EXISTING, 0, nullptr);
    if (candidate == INVALID_HANDLE_VALUE)
      return;
    file_ = platform::Handle(candidate);
    if (FileSha256(path_) != XSQL_FIXTURE_SHA256) {
      file_ = platform::Handle();
    }
  } catch (...) {
    file_ = platform::Handle();
  }
}

bool Fixture::configured() const { return file_.valid(); }

bool Fixture::Matches(const State& state, Timeline& timeline) {
  if (!configured() || !state.pid || state.generation != 1)
    return false;
  {
    std::lock_guard lock(timeline.mutex);
    if (timeline.attached || timeline.exited ||
        timeline.generation != state.generation || timeline.pid != state.pid)
      return false;
  }
  const auto target = DbgGetProcessHandle();
  if (!target || GetProcessId(target) != state.pid ||
      WaitForSingleObject(target, 0) != WAIT_TIMEOUT ||
      _wcsicmp(ExecutablePath(target).c_str(), path_.c_str()) != 0)
    return false;
  FILETIME created{}, exited{}, kernel{}, user{};
  if (!GetProcessTimes(target, &created, &exited, &kernel, &user))
    return false;
  std::lock_guard lock(identity_mutex_);
  if (!created_)
    created_ = created;
  return CompareFileTime(&*created_, &created) == 0;
}

duint Fixture::MarkerAddress() const {
  Script::Module::ModuleInfo module{};
  if (!Script::Module::GetMainModuleInfo(&module))
    throw Error("E_STATE", "Fixture image is unavailable.");
  SdkList<Script::Module::ModuleExport> exports;
  if (!Script::Module::GetExports(&module, &exports.info))
    throw Error("E_STATE", "Fixture marker is unavailable.");
  for (const auto& value : exports.values()) {
    const auto name = SdkText(value.name);
    if ((name == "xsql_fixture_marker" || name == "_xsql_fixture_marker") &&
        !value.forwarded)
      return value.va;
  }
  throw Error("E_STATE", "The approved fixture marker was not found.");
}

}  // namespace xsql::debugger
