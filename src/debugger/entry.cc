#include "debugger/session.h"

namespace {
using xsql::debugger::kApplyCommand;
using xsql::debugger::Plugin;

std::atomic<Plugin*> plugin{nullptr};
constexpr CBTYPE callbacks[]{
    CB_INITDEBUG, CB_CREATEPROCESS, CB_EXITPROCESS, CB_STOPDEBUG,
    CB_ATTACH,    CB_DETACH,        CB_PAUSEDEBUG,  CB_RESUMEDEBUG,
    CB_STEPPED,   CB_BREAKPOINT,    CB_EXCEPTION,   CB_LOADDLL,
    CB_UNLOADDLL, CB_CREATETHREAD,  CB_EXITTHREAD,  CB_MENUENTRY};

void OnEvent(CBTYPE type, void* info) noexcept {
  try {
    if (auto* current = plugin.load())
      current->OnEvent(type, info);
  } catch (...) {
  }
}

bool Dispatch(int argc, char** argv) noexcept {
  try {
    if (argc != 2)
      return false;
    if (auto* current = plugin.load())
      current->Dispatch(argv[1]);
    return true;
  } catch (...) {
    return false;
  }
}
}  // namespace

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* info) {
  if (plugin.load())
    return false;
  try {
    auto instance = std::make_unique<Plugin>(info->pluginHandle);
    instance->Start();
    if (!_plugin_registercommand(info->pluginHandle, kApplyCommand, Dispatch,
                                 true))
      return false;
    plugin.store(instance.release());
    for (const auto type : callbacks)
      _plugin_registercallback(info->pluginHandle, type, OnEvent);
    info->sdkVersion = PLUG_SDKVERSION;
    info->pluginVersion = 1;
    strcpy_s(info->pluginName, "x64dbgSQL");
    return true;
  } catch (const std::exception& error) {
    _plugin_logprintf("[x64dbgSQL] Startup failed: %s\n", error.what());
    return false;
  }
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* info) {
  if (auto* current = plugin.load(); current && info->hwndDlg && info->hMenu != -1)
    current->SetUpGui(info->hMenu);
}

extern "C" __declspec(dllexport) bool plugstop() {
  if (auto* current = plugin.load())
    current->Stop();
  // Upstream copies callbacks before invoking them. Retain this DLL through
  // process exit.
  return false;
}
