#include "debugger/session.h"

namespace xsql::debugger {

void Plugin::Start() {
  const auto session = NewId();
  id_ = session;
  audit_path_ = SessionDirectory() / (ToWide(session) + L".audit.jsonl");
  server_ = std::make_unique<PipeServer>(session,
                                         Json{{"session", session},
                                              {"pid", GetCurrentProcessId()},
                                              {"version", kProtocolVersion},
                                              {"arch", arch}},
                                         [this](const Json& value, DWORD pid) {
                                           return HandleRequest(value, pid);
                                         });
}

void Plugin::Stop() {
  active_.store(false);
  cancelled_.store(true);
  if (server_)
    server_->Stop();
}

void Plugin::SetUpGui(int menu) {
  wchar_t option[2]{};
  {
    std::lock_guard lock(timeline_.mutex);
    enable_annotations_at_start_ =
        GetEnvironmentVariableW(L"X64DBGSQL_ENABLE_ANNOTATIONS", option, 2) ==
            1 &&
        option[0] == L'1';
  }
  _plugin_menuaddentry(menu, kAnnotationMenu,
                       "Enable SQL CLI annotation edits for this session");
}

void Plugin::OnEvent(CBTYPE type, void* info) {
  if (!active_.load())
    return;
  if (type == CB_MENUENTRY) {
    if (static_cast<PLUG_CB_MENUENTRY*>(info)->hEntry != kAnnotationMenu ||
        !DbgIsDebugging())
      return;
    bool enabled;
    {
      std::lock_guard lock(timeline_.mutex);
      enabled = timeline_.annotation_enabled = !timeline_.annotation_enabled;
    }
    _plugin_menuentrysetchecked(handle_, kAnnotationMenu, enabled);
    return;
  }
  std::unique_lock lock(timeline_.mutex);
  const bool previously_enabled = timeline_.annotation_enabled;
  switch (type) {
    case CB_INITDEBUG:
      ++timeline_.generation;
      timeline_.pid = 0;
      timeline_.annotation_enabled = enable_annotations_at_start_;
      timeline_.attached = false;
      timeline_.exited = false;
      timeline_.record(EventType::init);
      break;
    case CB_CREATEPROCESS: {
      const auto& process = *static_cast<PLUG_CB_CREATEPROCESS*>(info);
      if (process.fdProcessInfo)
        timeline_.pid = process.fdProcessInfo->dwProcessId;
      timeline_.record(EventType::create);
      break;
    }
    case CB_EXITPROCESS:
      timeline_.exited = true;
      timeline_.annotation_enabled = false;
      timeline_.record(EventType::exit);
      break;
    case CB_STOPDEBUG:
      timeline_.exited = true;
      timeline_.pid = 0;
      timeline_.annotation_enabled = false;
      timeline_.record(EventType::stop);
      break;
    case CB_ATTACH:
      timeline_.attached = true;
      timeline_.record(EventType::attach);
      break;
    case CB_DETACH:
      timeline_.exited = true;
      timeline_.annotation_enabled = false;
      timeline_.record(EventType::detach);
      break;
    case CB_PAUSEDEBUG:
      timeline_.record(EventType::pause);
      break;
    case CB_RESUMEDEBUG:
      timeline_.record(EventType::resume);
      break;
    case CB_STEPPED:
      timeline_.record(EventType::step);
      break;
    case CB_BREAKPOINT: {
      const auto* bp = static_cast<PLUG_CB_BREAKPOINT*>(info)->breakpoint;
      timeline_.record(EventType::breakpoint, bp ? bp->addr : 0, 0,
                       bp ? bp->type : 0);
      break;
    }
    case CB_EXCEPTION: {
      const auto* exception = static_cast<PLUG_CB_EXCEPTION*>(info)->Exception;
      timeline_.record(
          EventType::exception,
          exception ? reinterpret_cast<duint>(
                          exception->ExceptionRecord.ExceptionAddress)
                    : 0,
          0, exception ? exception->ExceptionRecord.ExceptionCode : 0);
      break;
    }
    case CB_LOADDLL: {
      const auto* value = static_cast<PLUG_CB_LOADDLL*>(info)->LoadDll;
      timeline_.record(EventType::load,
                       value ? reinterpret_cast<duint>(value->lpBaseOfDll) : 0);
      break;
    }
    case CB_UNLOADDLL: {
      const auto* value = static_cast<PLUG_CB_UNLOADDLL*>(info)->UnloadDll;
      timeline_.record(EventType::unload,
                       value ? reinterpret_cast<duint>(value->lpBaseOfDll) : 0);
      break;
    }
    case CB_CREATETHREAD:
      timeline_.record(EventType::thread_start, 0,
                       static_cast<PLUG_CB_CREATETHREAD*>(info)->dwThreadId);
      break;
    case CB_EXITTHREAD:
      timeline_.record(EventType::thread_exit, 0,
                       static_cast<PLUG_CB_EXITTHREAD*>(info)->dwThreadId);
      break;
    default:
      break;
  }
  const bool enabled = timeline_.annotation_enabled;
  lock.unlock();
  if (enabled != previously_enabled)
    _plugin_menuentrysetchecked(handle_, kAnnotationMenu, enabled);
}

Json Plugin::HandleRequest(const Json& value, DWORD client) {
  if (!active_.load())
    throw Error("E_STATE", "The plugin is shutting down.");
  const auto op = RequireString(value, "op", 24);
  if (op == "status") {
    const auto state = provider_.GetState();
    std::lock_guard lock(timeline_.mutex);
    return {{"ok", true},
            {"session", id_},
            {"state", state.name},
            {"epoch", state.epoch},
            {"generation", state.generation},
            {"debuggee_pid", state.pid},
            {"annotation_enabled", timeline_.annotation_enabled},
            {"fixture_profile", fixture_.configured()}};
  }
  if (op == "schema") {
    auto reply = DescribeSchema(value.value("table", ""));
    const auto state = provider_.GetState();
    reply["state"] = state.name;
    for (auto& table : reply["tables"])
      table["available"] =
          !table.value("requires_static_analysis", false) &&
          (!table.at("requires_paused").get<bool>() || state.name == "paused");
    return reply;
  }
  if (op == "cancel") {
    const auto id = RequireString(value, "request_id", 64);
    std::lock_guard lock(cancel_mutex_);
    const bool found =
        client && query_client_ == client && current_query_ == id;
    if (found)
      cancelled_.store(true);
    return {{"ok", true}, {"cancelled", found}};
  }
  if (op == "query") {
    const auto id = RequireString(value, "request_id", 64);
    std::unique_lock lock(query_mutex_, std::try_to_lock);
    if (!lock)
      throw Error("E_BUSY", "A query is already running.");
    {
      std::lock_guard cancel_lock(cancel_mutex_);
      cancelled_.store(!active_.load());
      current_query_ = id;
      query_client_ = client;
    }
    struct Reset {
      Plugin& plugin;
      ~Reset() {
        std::lock_guard lock(plugin.cancel_mutex_);
        plugin.current_query_.clear();
        plugin.query_client_ = 0;
      }
    } reset{*this};
    return ExecuteQuery(provider_, value, cancelled_);
  }
  if (op == "action_status") {
    Refresh();
    std::lock_guard lock(actions_mutex_);
    return ActionResult(RequireString(value, "id", 64));
  }
  if (op == "annotation" || op == "breakpoint" || op == "control")
    return Submit(value, op, client);
  throw Error("E_PROTOCOL", "Unknown plugin request.");
}

}  // namespace xsql::debugger
