#include <windows.h>

#include <fstream>

#include "cli/commands.h"

namespace xsql::cli {

static constexpr auto kCheckpointSql = R"(
SELECT 'session' AS kind, 'state' AS key, json_array(oldest_seq,newest_seq,tid,printf('0x%X',ip)) AS data FROM session
UNION ALL SELECT 'register',printf('%d:%s',tid,name),json_array(tid,name,printf('0x%X',value)) FROM registers
UNION ALL SELECT 'module',printf('%X:%s',base,name),json_array(name,printf('0x%X',base),size,printf('0x%X',entry)) FROM modules
UNION ALL SELECT 'breakpoint',printf('%X:%d',addr,type),json_array(printf('0x%X',addr),type,enabled,module) FROM breakpoints
ORDER BY kind,key
)";

void PublishCheckpoint(const std::filesystem::path& path,
                       const Json& document) {
  if (std::filesystem::exists(path))
    throw Error("E_CONFLICT", "The checkpoint file already exists.");
  auto temporary = path;
  temporary += L"." + ToWide(NewId()) + L".tmp";
  struct Cleanup {
    std::filesystem::path path;
    ~Cleanup() {
      std::error_code error;
      std::filesystem::remove(path, error);
    }
  } cleanup{temporary};
  {
    std::ofstream output(temporary, std::ios::binary);
    output << SerializeUtf8(document) << '\n';
    output.close();
    if (!output)
      throw Error("E_INPUT", "Could not write the checkpoint file.");
  }
  if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
    throw Error(
        "E_INPUT",
        "Could not publish checkpoint without overwriting an existing file.");
}

Json CaptureCheckpoint(const Json& session, const std::filesystem::path& path) {
  const auto response =
      SendQuery(session, {{"sql", kCheckpointSql}}, NewId(), 1000);
  if (!response.value("ok", false))
    return response;
  if (response.at("truncated").get<bool>())
    throw Error("E_LIMIT",
                "The checkpoint could not fit in one complete query response.");
  Json objects = Json::object();
  Json position;
  for (const auto& row : response.at("rows")) {
    const auto key =
        row.at(0).get<std::string>() + ":" + row.at(1).get<std::string>();
    auto value = Json::parse(row.at(2).get<std::string>());
    if (key == "session:state")
      position = std::move(value);
    else {
      if (objects.contains(key))
        throw Error("E_CONFLICT", "Checkpoint rows have a duplicate identity.");
      objects[key] = std::move(value);
    }
  }
  if (!position.is_array())
    throw Error("E_INTERNAL",
                "The checkpoint is missing its session position.");
  Json document{{"version", 1},
                {"schema_hash", SchemaHash()},
                {"session", session.at("session")},
                {"generation", response.at("generation")},
                {"epoch", response.at("epoch")},
                {"position", position},
                {"objects", std::move(objects)}};
  PublishCheckpoint(path, document);
  return {{"ok", true},
          {"checkpoint", ToUtf8(path.c_str())},
          {"session", document.at("session")},
          {"generation", document.at("generation")},
          {"epoch", document.at("epoch")},
          {"newest_seq", position.at(1)},
          {"objects", document.at("objects").size()}};
}

Json ReadCheckpoint(const std::filesystem::path& path) {
  try {
    auto value = Json::parse(
        ReadFile(path, kMaxFrame), [](int depth, Json::parse_event_t, Json&) {
          if (depth > 12)
            throw Error("E_INPUT", "Invalid checkpoint nesting.");
          return true;
        });
    if (value.at("version") != 1 || value.at("schema_hash") != SchemaHash() ||
        !value.at("objects").is_object() || value.at("objects").size() > 1000 ||
        !value.at("position").is_array() || value.at("position").size() != 4 ||
        !value.at("position").at(1).is_number_integer() ||
        !value.at("epoch").is_number_integer())
      throw Error("E_VERSION", "Unsupported checkpoint format or schema.");
    return value;
  } catch (const Json::exception&) {
    throw Error("E_INPUT", "Invalid checkpoint file.");
  }
}

Json DiffCheckpoints(const std::filesystem::path& before_path,
                     const std::filesystem::path& after_path) {
  const auto before = ReadCheckpoint(before_path);
  const auto after = ReadCheckpoint(after_path);
  if (before.at("session") != after.at("session") ||
      before.at("generation") != after.at("generation"))
    throw Error("E_STATE_CHANGED",
                "Checkpoint comparison requires the same session and debuggee "
                "generation.");
  if (before.at("epoch") > after.at("epoch") ||
      before.at("position").at(1) > after.at("position").at(1))
    throw Error("E_INPUT",
                "Checkpoint files must be ordered from earlier to later.");
  const auto& left = before.at("objects");
  const auto& right = after.at("objects");
  Json changes = Json::array();
  for (const auto& [key, value] : left.items()) {
    const auto found = right.find(key);
    if (found == right.end())
      changes.push_back({{"key", key},
                         {"change", "removed"},
                         {"before", value},
                         {"after", nullptr}});
    else if (value != *found)
      changes.push_back({{"key", key},
                         {"change", "changed"},
                         {"before", value},
                         {"after", *found}});
  }
  for (const auto& [key, value] : right.items())
    if (!left.contains(key))
      changes.push_back({{"key", key},
                         {"change", "added"},
                         {"before", nullptr},
                         {"after", value}});
  return {{"ok", true},
          {"session", before.at("session")},
          {"generation", before.at("generation")},
          {"before_epoch", before.at("epoch")},
          {"after_epoch", after.at("epoch")},
          {"before_seq", before.at("position").at(1)},
          {"after_seq", after.at("position").at(1)},
          {"before_ip", before.at("position").at(3)},
          {"after_ip", after.at("position").at(3)},
          {"changes", std::move(changes)}};
}

}  // namespace xsql::cli
