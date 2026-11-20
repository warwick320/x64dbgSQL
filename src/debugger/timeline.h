#ifndef X64DBGSQL_DEBUGGER_TIMELINE_HPP
#define X64DBGSQL_DEBUGGER_TIMELINE_HPP

#include <algorithm>
#include <array>
#include <mutex>

#include "debugger/sdk.h"

namespace xsql::debugger {

inline constexpr std::size_t kEventCount = 2048;

inline std::int64_t UnixTimeMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

enum class EventType {
  init,
  create,
  exit,
  stop,
  pause,
  resume,
  step,
  breakpoint,
  exception,
  load,
  unload,
  thread_start,
  thread_exit,
  attach,
  detach,
  annotation
};
inline constexpr const char* kEventNames[]{
    "init",        "create",      "exit",          "stop",
    "pause",       "resume",      "step",          "breakpoint",
    "exception",   "module_load", "module_unload", "thread_start",
    "thread_exit", "attach",      "detach",        "annotation"};

struct Event {
  std::int64_t seq = 0;
  std::int64_t time = 0;
  std::int64_t generation = 0;
  EventType type = EventType::init;
  duint addr = 0;
  DWORD tid = 0;
  DWORD code = 0;
  std::int64_t monotonic = 0;
};

struct Timeline {
  std::mutex mutex;
  std::array<Event, kEventCount> events{};
  std::int64_t newest = 0;
  std::int64_t generation = 0;
  std::int64_t epoch = 0;
  DWORD pid = 0;
  bool annotation_enabled = false;
  bool attached = false;
  bool exited = false;
  const Clock::time_point started = Clock::now();

  std::int64_t oldest() const {
    return newest ? std::max<std::int64_t>(
                        1, newest - static_cast<std::int64_t>(kEventCount) + 1)
                  : 0;
  }
  void record(EventType type, duint address = 0, DWORD tid = 0,
              DWORD code = 0) {
    ++epoch;
    ++newest;
    events[static_cast<std::size_t>(newest - 1) % kEventCount] = {
        newest,
        UnixTimeMs(),
        generation,
        type,
        address,
        tid,
        code,
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                              started)
            .count()};
  }
};

}  // namespace xsql::debugger

#endif  // X64DBGSQL_DEBUGGER_TIMELINE_HPP
