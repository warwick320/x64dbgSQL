#include "debugger/provider.h"

#include <_scriptapi_bookmark.h>
#include <_scriptapi_comment.h>
#include <_scriptapi_label.h>
#include <_scriptapi_memory.h>
#include <_scriptapi_module.h>
#include <_dbgfunctions.h>

#include <limits>
#include <optional>

namespace xsql::debugger {

namespace {
std::optional<duint> ResolveAnnotationAddress(const char* module, duint rva) {
  if (!module[0])
    return rva;
  const auto base = Script::Module::BaseFromName(module);
  if (!base || rva > std::numeric_limits<duint>::max() - base)
    return {};
  return base + rva;
}

}  // namespace

State Provider::GetState() {
  State state;
  {
    std::lock_guard lock(timeline_.mutex);
    state.epoch = timeline_.epoch;
    state.generation = timeline_.generation;
    state.pid = timeline_.pid;
  }
  if (!DbgIsDebugging())
    return state;
  state.pid = DbgGetProcessId();
  state.name = DbgIsRunning() ? "running" : "paused";
  if (state.name == "paused") {
    state.tid = DbgGetThreadId();
    REGDUMP_AVX512 registers{};
    if (DbgGetRegDumpEx(&registers, sizeof(registers)))
      state.ip = SqlInteger(registers.regcontext.cip);
  }
  return state;
}

Json Provider::ReadRows(std::string_view table, const State& state,
                        Budget& budget) {
  if (table == "session" || table == "events")
    return ReadHistory(table, state, budget);
  Json result = Json::array();
  if (table == "modules" || table == "sections") {
    SdkList<Script::Module::ModuleInfo> list;
    if (!Script::Module::GetList(&list.info))
      throw Error("E_PROVIDER", "Could not enumerate modules.");
    for (const auto& entry : list.values()) {
      budget.Check();
      if (table == "modules") {
        AppendRow(result,
                  Json::array({SqlInteger(entry.base), SqlInteger(entry.size),
                               SqlInteger(entry.entry), SdkText(entry.name),
                               SdkText(entry.path)}),
                  budget);
        continue;
      }
      SdkList<Script::Module::ModuleSectionInfo> sections;
      if (!Script::Module::SectionListFromAddr(entry.base, &sections.info))
        throw Error(
            "E_STATE_CHANGED",
            "A module changed while its PE sections were being collected.");
      for (const auto& section : sections.values())
        AppendRow(result,
                  Json::array({SqlInteger(entry.base), SdkText(entry.name),
                               SdkText(section.name), SqlInteger(section.addr),
                               section.addr >= entry.base
                                   ? Json(SqlInteger(section.addr - entry.base))
                                   : Json(nullptr),
                               SqlInteger(section.size)}),
                  budget);
    }
  } else if (table == "memory_map") {
    MEMMAP map{};
    const bool ok = DbgMemMap(&map);
    const std::unique_ptr<MEMPAGE, decltype(&BridgeFree)> owned(map.page,
                                                                BridgeFree);
    if (!ok)
      throw Error("E_PROVIDER", "Could not enumerate memory regions.");
    for (const auto& entry : CheckedList(map.page, map.count))
      AppendRow(result,
                Json::array(
                    {SqlInteger(reinterpret_cast<duint>(entry.mbi.BaseAddress)),
                     SqlInteger(entry.mbi.RegionSize), entry.mbi.Protect,
                     entry.mbi.State, entry.mbi.Type, SdkText(entry.info)}),
                budget);
  } else if (table == "threads") {
    THREADLIST list{};
    DbgGetThreadList(&list);
    const std::unique_ptr<THREADALLINFO, decltype(&BridgeFree)> owned(
        list.list, BridgeFree);
    for (const auto& entry : CheckedList(list.list, list.count))
      AppendRow(
          result,
          Json::array({entry.BasicInfo.ThreadId, SqlInteger(entry.ThreadCip),
                       SqlInteger(entry.BasicInfo.ThreadStartAddress),
                       SdkText(entry.BasicInfo.threadName),
                       entry.BasicInfo.ThreadId == state.tid}),
          budget);
  } else if (table == "call_stack") {
    DBGCALLSTACK frames{};
    const auto* functions = DbgFunctions();
    if (!functions || !functions->GetCallStack)
      throw Error("E_PROVIDER", "Could not read the active thread stack.");
    functions->GetCallStack(&frames);
    const std::unique_ptr<DBGCALLSTACKENTRY, decltype(&BridgeFree)> owned(
        frames.entries, BridgeFree);
    for (const auto& frame : CheckedList(frames.entries, frames.total))
      AppendRow(result, Json::array({state.tid, result.size(),
                                   SqlInteger(frame.addr), SqlInteger(frame.from),
                                   SqlInteger(frame.to), SdkText(frame.comment)}),
                budget);
  } else if (table == "registers") {
    REGDUMP_AVX512 registers{};
    if (!DbgGetRegDumpEx(&registers, sizeof(registers)))
      throw Error("E_PROVIDER", "Could not read registers.");
    const auto& r = registers.regcontext;
#ifdef _WIN64
    constexpr char prefix = 'r';
#else
    constexpr char prefix = 'e';
#endif
    const auto add = [&](std::string name, duint value) {
      AppendRow(result,
                Json::array({state.tid, std::move(name), SqlInteger(value)}),
                budget);
    };
    const std::pair<const char*, duint> common[]{
        {"ax", r.cax}, {"bx", r.cbx}, {"cx", r.ccx},
        {"dx", r.cdx}, {"si", r.csi}, {"di", r.cdi},
        {"bp", r.cbp}, {"sp", r.csp}, {"ip", r.cip}};
    for (const auto& [name, value] : common)
      add(prefix + std::string(name), value);
    add(std::string(1, prefix) + "flags", r.eflags);
#ifdef _WIN64
    const duint extended[]{r.r8,  r.r9,  r.r10, r.r11,
                           r.r12, r.r13, r.r14, r.r15};
    for (std::size_t i = 0; i < std::size(extended); ++i)
      add("r" + std::to_string(i + 8), extended[i]);
#endif
  } else if (table == "labels") {
    SdkList<Script::Label::LabelInfo> list;
    if (!Script::Label::GetList(&list.info))
      throw Error("E_PROVIDER", "Could not enumerate labels.");
    for (const auto& entry : list.values()) {
      budget.Check();
      if (const auto address = ResolveAnnotationAddress(entry.mod, entry.rva))
        AppendRow(result,
                  Json::array({SqlInteger(*address), SdkText(entry.text),
                               entry.manual}),
                  budget);
    }
  } else if (table == "comments") {
    SdkList<Script::Comment::CommentInfo> list;
    if (!Script::Comment::GetList(&list.info))
      throw Error("E_PROVIDER", "Could not enumerate comments.");
    for (const auto& entry : list.values()) {
      budget.Check();
      if (const auto address = ResolveAnnotationAddress(entry.mod, entry.rva))
        AppendRow(result,
                  Json::array({SqlInteger(*address), SdkText(entry.text),
                               entry.manual}),
                  budget);
    }
  } else if (table == "bookmarks") {
    SdkList<Script::Bookmark::BookmarkInfo> list;
    if (!Script::Bookmark::GetList(&list.info))
      throw Error("E_PROVIDER", "Could not enumerate bookmarks.");
    for (const auto& entry : list.values()) {
      budget.Check();
      if (const auto address = ResolveAnnotationAddress(entry.mod, entry.rva))
        AppendRow(result, Json::array({SqlInteger(*address), entry.manual}),
                  budget);
    }
  } else if (table == "breakpoints") {
    BPMAP map{};
    const auto count = DbgGetBpList(bp_none, &map);
    const std::unique_ptr<BRIDGEBP, decltype(&BridgeFree)> owned(map.bp,
                                                                 BridgeFree);
    for (const auto& entry : CheckedList(map.bp, count))
      AppendRow(
          result,
          Json::array({SqlInteger(entry.addr), static_cast<int>(entry.type),
                       entry.enabled, SdkText(entry.name), SdkText(entry.mod)}),
          budget);
  } else {
    throw Error("E_NO_TABLE",
                "The debugger provider does not supply that table.");
  }
  return result;
}

std::vector<std::uint8_t> Provider::ReadMemory(std::uint64_t address,
                                               unsigned size, Budget& budget) {
  budget.Check();
  if (address > std::numeric_limits<duint>::max() ||
      size - 1 > std::numeric_limits<duint>::max() - address)
    throw Error("E_INPUT", "Address does not fit this target architecture.");
  const HANDLE process = DbgGetProcessHandle();
  auto current = address;
  const auto end = address + size;
  while (current < end) {
    budget.Check();
    MEMORY_BASIC_INFORMATION page{};
    if (!process ||
        !VirtualQueryEx(
            process, reinterpret_cast<const void*>(static_cast<duint>(current)),
            &page, sizeof(page)) ||
        page.State != MEM_COMMIT ||
        (page.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
      throw Error("E_UNREADABLE",
                  "The range crosses an inaccessible or guarded region.");
    const auto next =
        static_cast<std::uint64_t>(reinterpret_cast<duint>(page.BaseAddress)) +
        page.RegionSize;
    if (next <= current)
      throw Error("E_UNREADABLE", "Invalid memory region returned by Windows.");
    current = next;
  }
  std::vector<std::uint8_t> bytes(size);
  duint read = 0;
  if (!Script::Memory::Read(static_cast<duint>(address), bytes.data(), size,
                            &read) ||
      read != size)
    throw Error("E_UNREADABLE",
                "The debugger could not read the entire requested range.");
  return bytes;
}

Json Provider::ReadInstructions(std::uint64_t address, unsigned count,
                                Budget& budget) {
  Json rows = Json::array();
  constexpr auto high_address = std::min(
      static_cast<std::uint64_t>(std::numeric_limits<duint>::max()),
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()));
  for (unsigned row = 0; row < count; ++row) {
    budget.Check();
    if (address > high_address)
      throw Error("E_INPUT", "Instruction address exceeds this architecture.");
    const auto current = static_cast<duint>(address);
    if (!DbgMemIsValidReadPtr(current))
      throw Error("E_UNREADABLE", "Instruction memory could not be read.");
    BASIC_INSTRUCTION_INFO instruction{};
    DbgDisasmFastAt(current, &instruction);
    if (instruction.size < 1 || instruction.size > 15 ||
        !instruction.instruction[0])
      throw Error("E_UNREADABLE", "The debugger could not decode an instruction.");
    AppendRow(rows, Json::array({SqlInteger(current), instruction.size,
                                SdkText(instruction.instruction)}),
              budget);
    address += static_cast<unsigned>(instruction.size);
  }
  return rows;
}

Json Provider::ReadHistory(std::string_view table, const State& state,
                           const Budget& budget) {
  std::vector<Event> copy;
  {
    std::lock_guard lock(timeline_.mutex);
    const auto oldest = timeline_.oldest();
    if (table == "session")
      return Json::array({Json::array(
          {state.name, state.epoch, state.generation, state.pid, state.tid,
           state.ip, arch, oldest, timeline_.newest, oldest > 1})});
    if (oldest) {
      copy.reserve(kEventCount);
      for (auto at = oldest; at <= timeline_.newest; ++at)
        copy.push_back(
            timeline_.events[static_cast<std::size_t>(at - 1) % kEventCount]);
    }
  }
  Json result = Json::array();
  for (const auto& event : copy)
    AppendRow(
        result,
        Json::array({event.seq, event.time, event.generation,
                     kEventNames[static_cast<unsigned>(event.type)],
                     event.tid ? Json(event.tid) : Json(nullptr),
                     event.addr ? Json(SqlInteger(event.addr)) : Json(nullptr),
                     event.code ? Json(event.code) : Json(nullptr),
                     event.monotonic}),
        budget);
  return result;
}

}  // namespace xsql::debugger
