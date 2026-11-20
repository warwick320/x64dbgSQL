#ifndef X64DBGSQL_DEBUGGER_SDK_HPP
#define X64DBGSQL_DEBUGGER_SDK_HPP

#include <_plugins.h>
#include <windows.h>

#include <bit>
#include <cstring>
#include <span>
#include <utility>

#include "ipc.h"

namespace xsql::debugger {

inline constexpr std::size_t kMaxProviderRows = 8192;
inline constexpr const char* arch = sizeof(duint) == 8 ? "x64" : "x86";

inline std::int64_t SqlInteger(duint value) {
  return std::bit_cast<std::int64_t>(static_cast<std::uint64_t>(value));
}

template <std::size_t Size>
std::string SdkText(const char (&field)[Size]) {
  const auto length = strnlen_s(field, Size);
  std::string value(field, length);
  try {
    ToWide(value);
  } catch (const Error&) {
    throw Error("E_RESULT_TYPE", "The debugger returned invalid UTF-8.");
  }
  return value;
}

template <class T>
void AppendRow(Json& rows, T&& row, const Budget& budget) {
  budget.Check();
  if (rows.size() >= kMaxProviderRows)
    throw Error("E_LIMIT", "Debugger table exceeds the snapshot row limit.");
  rows.push_back(std::forward<T>(row));
}

template <class T>
std::span<const T> CheckedList(const T* data, int count) {
  if (count < 0 || static_cast<std::size_t>(count) > kMaxProviderRows ||
      (count != 0 && !data))
    throw Error("E_LIMIT", "Debugger list exceeds its row limit.");
  return {data, static_cast<std::size_t>(count)};
}

template <class T>
struct SdkList {
  ListInfo info{};
  ~SdkList() {
    if (info.data)
      BridgeFree(info.data);
  }
  std::span<const T> values() const {
    const auto result = CheckedList(static_cast<T*>(info.data), info.count);
    if (info.size != result.size_bytes())
      throw Error("E_PROVIDER", "Invalid SDK list layout.");
    return result;
  }
};

}  // namespace xsql::debugger

#endif  // X64DBGSQL_DEBUGGER_SDK_HPP
