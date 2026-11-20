#include "core.h"

namespace xsql {

Json Envelope(const State& state) {
  return {{"ok", true},
          {"columns", Json::array()},
          {"rows", Json::array()},
          {"row_count", 0},
          {"truncated", false},
          {"elapsed_ms", 0},
          {"state", state.name},
          {"epoch", state.epoch},
          {"generation", state.generation},
          {"error", nullptr}};
}

Error::Error(std::string code_value, std::string message,
             std::string hint_value)
    : std::runtime_error(std::move(message)),
      code(std::move(code_value)),
      hint(std::move(hint_value)) {}

void Budget::Check() const {
  if (cancelled.load(std::memory_order_relaxed))
    throw Error("E_CANCELLED", "The query was cancelled.");
  if (Clock::now() >= deadline)
    throw Error("E_TIMEOUT", "The query exceeded its deadline.",
                "Narrow the query or range.");
}

std::string SerializeUtf8(const Json& value) {
  try {
    return value.dump(-1, ' ', false, Json::error_handler_t::strict);
  } catch (const Json::type_error&) {
    throw Error("E_RESULT_TYPE", "Result text is not valid UTF-8.");
  }
}

Json Failure(const Error& error, const State& state) {
  auto value = Envelope(state);
  value["ok"] = false;
  value["error"] = {
      {"code", error.code}, {"message", error.what()}, {"hint", error.hint}};
  return value;
}

std::string RequireString(const Json& data, const char* key,
                          std::size_t max_size) {
  const auto item = data.find(key);
  if (item == data.end() || !item->is_string())
    throw Error("E_INPUT", std::string("Expected string: ") + key);
  const auto& value = item->get_ref<const std::string&>();
  if (value.empty() || value.size() > max_size ||
      value.find('\0') != std::string::npos)
    throw Error("E_INPUT",
                std::string("Invalid length or embedded NUL: ") + key);
  return value;
}

int OptionalInteger(const Json& data, const char* key, int fallback,
                    int minimum, int maximum) {
  const auto item = data.find(key);
  if (item == data.end())
    return fallback;
  if (!item->is_number_integer() ||
      (item->is_number_unsigned() &&
       item->get<std::uint64_t>() > static_cast<std::uint64_t>(maximum)))
    throw Error("E_INPUT", std::string("Expected integer in range: ") + key);
  const auto value = item->get<std::int64_t>();
  if (value < minimum || value > maximum)
    throw Error("E_INPUT", std::string("Integer out of range: ") + key);
  return static_cast<int>(value);
}

}  // namespace xsql
