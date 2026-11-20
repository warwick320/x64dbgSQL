#include "analysis/bound_provider.h"

#include <algorithm>
#include <limits>

#include "analysis/source.h"

namespace xsql::analysis {
namespace {

void CheckModuleRecord(const Json& module) {
  if (!module.is_array() || module.size() != 4 || !module.at(2).is_string() ||
      !module.at(3).is_string()) {
    throw Error("E_STATIC_PROTOCOL", "Malformed loaded module binding.");
  }
}

}  // namespace

bool IsStaticTable(std::string_view name) {
  return name == "static_program" || name == "static_functions" ||
         name == "static_rows";
}

BoundProvider::BoundProvider(IDebuggerProvider& live, const Json& binding,
                             const State& state, Budget& budget)
    : live_(live), functions_(Json::array()), native_rows_(Json::array()) {
  try {
    if (state.name != "paused" || binding.at("epoch") != state.epoch ||
        binding.at("generation") != state.generation ||
        binding.at("pid") != state.pid) {
      throw Error("E_STATE_CHANGED",
                  "The debuggee changed while static data was fetched.",
                  "Pause the same target and retry the combined query.");
    }
    const auto& module = binding.at("module");
    CheckModuleRecord(module);
    const auto base = ParseAddress(module.at(0));
    const auto size = ParseAddress(module.at(1));
    const auto hash = RequireString(binding, "sha256", 64);
    const auto backend = RequireString(binding, "backend", 16);
    const auto& chunks = binding.at("functions");
    if (!size || base > std::numeric_limits<std::int64_t>::max() - size ||
        !IsSha256(hash) || (backend != "idasql" && backend != "ghidrasql") ||
        !chunks.is_array() || chunks.size() > kMaxFunctions) {
      throw Error("E_STATIC_PROTOCOL", "Invalid static snapshot bounds.");
    }
    const auto image_base = ParseAddress(binding.at("image_base"));
    if (image_base > std::numeric_limits<std::int64_t>::max() - size) {
      throw Error("E_STATIC_ADDRESS", "Static image range overflow.");
    }
    modules_ = live_.ReadRows("modules", state, budget);
    const auto matching = std::ranges::count_if(modules_, [&](const Json& row) {
      return row.at(0) == base && row.at(1) == size &&
             row.at(3) == module.at(2) && row.at(4) == module.at(3);
    });
    if (matching != 1) {
      throw Error(
          "E_STATE_CHANGED",
          "The bound module is no longer loaded at the verified address.");
    }
    const auto focus = binding.value("focus_rva", Json(nullptr));
    if (!focus.is_null() && ParseAddress(focus) >= size) {
      throw Error("E_STATIC_ADDRESS", "Invalid static point scope.");
    }
    program_ = Json::array({Json::array(
        {backend, module.at(2), hash, image_base, base, size, focus,
         binding.value("version", ""), binding.value("revision", "")})});
    for (const auto& chunk : chunks) {
      budget.Check();
      if (!chunk.is_array() || chunk.size() != 4 || !chunk.at(3).is_string()) {
        throw Error("E_STATIC_PROTOCOL", "Malformed static function chunk.");
      }
      const auto entry = ParseAddress(chunk.at(0));
      const auto first = ParseAddress(chunk.at(1));
      const auto last = ParseAddress(chunk.at(2));
      const auto& name = chunk.at(3).get_ref<const std::string&>();
      if (entry >= size || first >= last || last > size || name.size() > 1024 ||
          (!focus.is_null() &&
           (ParseAddress(focus) < first || ParseAddress(focus) >= last))) {
        throw Error("E_STATIC_ADDRESS",
                    "A function chunk is outside its declared image scope.");
      }
      functions_.push_back(
          Json::array({backend, name, image_base + entry, base + entry,
                       base + first, base + last, entry, first, last}));
    }
    if (const auto native = binding.find("native"); native != binding.end()) {
      const auto table = RequireString(*native, "table", 128);
      const auto& rows = native->at("rows");
      if (!rows.is_array() || rows.size() > kMaxNativeRows) {
        throw Error("E_STATIC_LIMIT",
                    "Too many native rows for a combined query.");
      }
      for (const auto& row : rows) {
        budget.Check();
        if (!row.is_object())
          throw Error("E_STATIC_PROTOCOL", "Malformed native analyzer row.");
        auto data = SerializeUtf8(row);
        if (data.size() > kMaxNativeRowBytes) {
          throw Error(
              "E_STATIC_LIMIT",
              "A native analyzer row exceeds the combined-query size limit.");
        }
        native_rows_.push_back(Json::array(
            {backend, table, native_rows_.size(), std::move(data)}));
      }
    }
  } catch (const Json::exception&) {
    throw Error("E_STATIC_PROTOCOL", "Malformed static query binding.");
  }
}

Json BoundProvider::ReadRows(std::string_view table, const State& state,
                             Budget& budget) {
  if (table == "static_program")
    return program_;
  if (table == "static_functions")
    return functions_;
  if (table == "static_rows")
    return native_rows_;
  if (table == "modules")
    return modules_;
  return live_.ReadRows(table, state, budget);
}

}  // namespace xsql::analysis
