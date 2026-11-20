#include <_scriptapi_bookmark.h>
#include <_scriptapi_comment.h>
#include <_scriptapi_debug.h>
#include <_scriptapi_label.h>

#include <charconv>
#include <fstream>

#include "debugger/session.h"

namespace xsql::debugger {

namespace {
duint AddressFromRequest(const Json& request) {
  auto text = RequireString(request, "addr", 20);
  const bool hex = text.starts_with("0x") || text.starts_with("0X");
  const auto* start = text.data() + (hex ? 2 : 0);
  duint value = 0;
  const auto [end, error] =
      std::from_chars(start, text.data() + text.size(), value, hex ? 16 : 10);
  if (error != std::errc{} || end != text.data() + text.size() || !value)
    throw Error("E_INPUT", "Address must fit the target architecture.");
  return value;
}

}  // namespace

void Plugin::Dispatch(std::string_view ticket) {
  if (!active_.load())
    return;
  std::string key;
  Action action;
  {
    std::lock_guard lock(actions_mutex_);
    if (pending_.empty())
      return;
    key = pending_;
    auto& entry = actions_.at(key);
    if (entry.ticket != ticket || entry.dispatched ||
        entry.status != "accepted")
      return;
    entry.dispatched = true;
    action = entry;
  }
  try {
    const auto current = provider_.GetState();
    if (!(current == action.state))
      throw Error("E_STATE_CHANGED",
                  "The target state changed before dispatch.");
    const auto operation = action.request.at("op").get<std::string>();
    if (operation == "annotation") {
      EditAnnotation(action.request);
      Complete(key, "done", "");
    } else {
      if (!fixture_.Matches(current, timeline_))
        throw Error("E_PERM",
                    "This target is not the approved local fixture instance.");
      if (operation == "breakpoint") {
        EditBreakpoint(action.request);
        Complete(key, "done", "");
      } else {
        const auto verb = action.request.at("verb").get<std::string>();
        const auto* command = verb == "run"     ? "run"
                              : verb == "pause" ? "pause"
                                                : "StepInto";
        std::int64_t watermark;
        {
          std::lock_guard lock(timeline_.mutex);
          watermark = timeline_.newest;
        }
        {
          std::lock_guard lock(actions_mutex_);
          auto& original = actions_.at(key);
          if (original.status != "accepted")
            return;
          original.first_seq = watermark;
        }
        if (!DbgCmdExecDirect(command))
          throw Error("E_PROVIDER",
                      "The debugger rejected the fixture action.");
        std::lock_guard lock(actions_mutex_);
        actions_.at(key).issued = true;
      }
    }
  } catch (const Error& error) {
    Complete(key, "rejected", error.code + ": " + error.what());
  } catch (...) {
    Complete(key, "unknown", "The debugger did not return a verified result.");
  }
}

Json Plugin::ActionResult(const std::string& key) {
  const auto match = actions_.find(key);
  if (match == actions_.end())
    throw Error("E_NOT_FOUND", "Unknown or expired action ID.");
  return {{"ok", true},
          {"action_id", key},
          {"status", match->second.status},
          {"detail", match->second.detail},
          {"generation", match->second.state.generation},
          {"audit_recorded", match->second.audit_recorded}};
}

Json Plugin::Submit(const Json& request, const std::string& operation,
                    DWORD client) {
  const auto verb = RequireString(request, "verb", 10);
  const auto reason = RequireString(request, "reason", 256);
  const auto key = RequireString(request, "id", 64);
  const auto current = provider_.GetState();
  try {
    Refresh();
    const auto ticket = NewId();
    {
      std::lock_guard lock(actions_mutex_);
      if (const auto existing = actions_.find(key);
          existing != actions_.end()) {
        if (existing->second.request != request)
          throw Error("E_CONFLICT",
                      "This action key was used with a different request.");
        return ActionResult(key);
      }
    }
    if (request.at("expected_epoch") != current.epoch ||
        request.at("generation") != current.generation)
      throw Error("E_STATE_CHANGED",
                  "The requested epoch or target generation is stale.");
    const bool pause = operation == "control" && verb == "pause";
    if (current.name != (pause ? "running" : "paused"))
      throw Error("E_STATE", "The action requires a different debugger state.");
    if (operation == "annotation") {
      if (verb != "set" && verb != "remove")
        throw Error("E_INPUT", "Expected annotation set or remove.");
      const auto kind = RequireString(request, "kind", 8);
      if (kind != "label" && kind != "comment" && kind != "bookmark")
        throw Error("E_INPUT", "Unknown annotation kind.");
      AddressFromRequest(request);
      if (verb == "set" && kind != "bookmark") {
        const auto body = RequireString(
            request, "text",
            kind == "label" ? MAX_LABEL_SIZE - 1 : MAX_COMMENT_SIZE - 2);
        if (body.front() == '\x01')
          throw Error("E_INPUT", "Reserved debugger annotation prefix.");
      }
      std::lock_guard lock(timeline_.mutex);
      if (!timeline_.annotation_enabled)
        throw Error("E_PERM",
                    "Enable annotations through the x64dbg plugin menu or "
                    "start the debugger with X64DBGSQL_ENABLE_ANNOTATIONS=1.");
    } else {
      if (!fixture_.Matches(current, timeline_))
        throw Error("E_PERM", "This session has no approved fixture instance.");
      if ((operation == "breakpoint" && verb != "add" && verb != "remove") ||
          (operation == "control" && verb != "run" && verb != "pause" &&
           verb != "step"))
        throw Error("E_INPUT", "Unknown fixture action.");
    }
    std::int64_t watermark;
    {
      std::lock_guard lock(timeline_.mutex);
      watermark = timeline_.newest;
    }
    {
      std::lock_guard lock(actions_mutex_);
      if (!pending_.empty())
        throw Error("E_BUSY", "A local action is pending.");
      const auto expiry = Clock::now() - std::chrono::minutes(10);
      std::erase_if(actions_, [expiry](const auto& entry) {
        return entry.second.accepted < expiry;
      });
      if (actions_.size() >= 256)
        throw Error("E_LIMIT", "The local action history is full.");
      actions_.emplace(key, Action{request,
                                   current,
                                   ticket,
                                   "accepted",
                                   {},
                                   watermark,
                                   Clock::now(),
                                   client});
      pending_ = key;
    }
    if (!Audit(operation, key, reason, "accepted", client)) {
      Complete(key, "rejected", "Could not write the local audit log.");
    } else {
      const auto command = std::string(kApplyCommand) + " " + ticket;
      if (!DbgCmdExec(command.c_str()))
        Complete(key, "rejected", "Could not schedule the debugger command.");
    }
    std::lock_guard lock(actions_mutex_);
    return ActionResult(key);
  } catch (const Error& error) {
    Audit(operation, key, reason, error.code, client);
    throw;
  }
}

void Plugin::Refresh() {
  std::string key;
  Action action;
  {
    std::lock_guard lock(actions_mutex_);
    if (pending_.empty())
      return;
    key = pending_;
    action = actions_.at(key);
  }
  const auto state = provider_.GetState();
  if (state.generation != action.state.generation) {
    Complete(key, "unknown",
             "The debuggee changed before the action could be verified.");
    return;
  }
  if (action.issued && action.request.at("op") == "control") {
    const auto verb = action.request.at("verb").get<std::string>();
    bool matched = false;
    bool exited = false;
    {
      std::lock_guard lock(timeline_.mutex);
      const auto first = std::max(timeline_.oldest(), action.first_seq + 1);
      for (auto seq = first; seq <= timeline_.newest; ++seq) {
        const auto& event =
            timeline_.events[static_cast<std::size_t>(seq - 1) % kEventCount];
        if (event.generation != action.state.generation)
          continue;
        matched |= (verb == "run" && event.type == EventType::resume) ||
                   (verb == "pause" && event.type == EventType::pause) ||
                   (verb == "step" && event.type == EventType::step);
        exited |=
            event.type == EventType::exit || event.type == EventType::stop;
      }
    }
    if ((verb == "run" && (matched || state.name == "running")) ||
        (verb != "run" && matched && state.name == "paused")) {
      Complete(key, "done", "");
      return;
    }
    if (exited) {
      Complete(key, "unknown",
               "The test program exited before the action could be verified.");
      return;
    }
  }
  if (Clock::now() - action.accepted > std::chrono::seconds(5))
    Complete(key, "unknown",
             "The action could not be verified within its observation window.");
}

void Plugin::Complete(const std::string& key, const std::string& status,
                      const std::string& detail) {
  std::lock_guard lock(actions_mutex_);
  auto& action = actions_.at(key);
  if (action.status != "accepted")
    return;
  action.status = status;
  action.detail = detail;
  if (key == pending_)
    pending_.clear();
  action.audit_recorded = Audit(action.request.at("op").get<std::string>(), key,
                                action.request.at("reason").get<std::string>(),
                                status, action.client);
}

bool Plugin::Audit(std::string_view operation, const std::string& key,
                   const std::string& reason, const std::string& outcome,
                   DWORD client) noexcept {
  try {
    std::lock_guard lock(audit_mutex_);
    std::error_code error;
    const auto size = std::filesystem::file_size(audit_path_, error);
    if (!error && size >= 256 * 1024) {
      auto previous = audit_path_;
      previous += L".1";
      if (!MoveFileExW(audit_path_.c_str(), previous.c_str(),
                       MOVEFILE_REPLACE_EXISTING))
        return false;
    }
    std::ofstream output(audit_path_, std::ios::binary | std::ios::app);
    output << Json{{"time_ms", UnixTimeMs()}, {"session", id_},
                   {"client_pid", client},    {"operation", operation},
                   {"action_id", key},        {"reason", reason},
                   {"outcome", outcome}}
                  .dump()
           << '\n';
    output.close();
    return static_cast<bool>(output);
  } catch (...) {
    return false;
  }
}

void Plugin::EditAnnotation(const Json& request) {
  {
    std::lock_guard lock(timeline_.mutex);
    if (!timeline_.annotation_enabled)
      throw Error("E_PERM", "Session annotation permission is disabled.");
  }
  const auto address = AddressFromRequest(request);
  const auto kind = request.at("kind").get<std::string>();
  const bool set = request.at("verb") == "set";
  const auto body =
      set && kind != "bookmark" ? request.at("text").get<std::string>() : "";
  bool verified = false;
  if (kind == "label") {
    if (set)
      Script::Label::Set(address, body.c_str(), true, false);
    else
      Script::Label::Delete(address);
    Script::Label::LabelInfo result{};
    const auto exists = Script::Label::GetInfo(address, &result);
    verified = set ? exists && SdkText(result.text) == body : !exists;
  } else if (kind == "comment") {
    if (set)
      Script::Comment::Set(address, body.c_str(), true);
    else
      Script::Comment::Delete(address);
    std::array<char, MAX_COMMENT_SIZE> result{};
    const auto exists = Script::Comment::Get(address, result.data());
    verified = set ? exists && result.data() == body : !exists;
  } else {
    if (set)
      Script::Bookmark::Set(address, true);
    else
      Script::Bookmark::Delete(address);
    verified = Script::Bookmark::Get(address) == set;
  }
  if (!verified)
    throw Error("E_PROVIDER",
                "The debugger did not verify the annotation change.");
  {
    std::lock_guard lock(timeline_.mutex);
    timeline_.record(EventType::annotation, address);
  }
}

void Plugin::EditBreakpoint(const Json& request) {
  const auto address = fixture_.MarkerAddress();
  const auto current = static_cast<unsigned>(DbgGetBpxTypeAt(address));
  if (request.at("verb") == "add") {
    if (current != bp_none)
      throw Error("E_CONFLICT",
                  "A breakpoint already exists at the fixture marker.");
    if (!Script::Debug::SetBreakpoint(address) ||
        !(DbgGetBpxTypeAt(address) & bp_normal))
      throw Error("E_PROVIDER",
                  "The fixture breakpoint could not be verified.");
    fixture_bp_ = address;
  } else {
    if (fixture_bp_ != address)
      throw Error("E_PERM",
                  "Only this session's fixture breakpoint can be removed.");
    if (!Script::Debug::DeleteBreakpoint(address) ||
        (DbgGetBpxTypeAt(address) & bp_normal))
      throw Error("E_PROVIDER",
                  "The breakpoint removal could not be verified.");
    fixture_bp_.reset();
  }
  std::lock_guard lock(timeline_.mutex);
  ++timeline_.epoch;
}

}  // namespace xsql::debugger
