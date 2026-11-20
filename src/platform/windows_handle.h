#ifndef X64DBGSQL_PLATFORM_WINDOWS_HANDLE_HPP
#define X64DBGSQL_PLATFORM_WINDOWS_HANDLE_HPP

#include <windows.h>

#include <utility>

namespace xsql::platform {

class Handle {
 public:
  explicit Handle(HANDLE value = nullptr) : value_(value) {}
  Handle(Handle&& other) noexcept
      : value_(std::exchange(other.value_, nullptr)) {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (valid())
        CloseHandle(value_);
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }
  ~Handle() {
    if (valid())
      CloseHandle(value_);
  }
  bool valid() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
  HANDLE get() const { return value_; }

 private:
  HANDLE value_;
};

}  // namespace xsql::platform

#endif  // X64DBGSQL_PLATFORM_WINDOWS_HANDLE_HPP
