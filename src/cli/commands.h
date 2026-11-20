#ifndef X64DBGSQL_CLI_COMMANDS_HPP
#define X64DBGSQL_CLI_COMMANDS_HPP

#include <istream>

#include "cli/analysis.h"
#include "ipc.h"

namespace xsql::cli {

std::string ReadBounded(std::istream& stream, std::size_t limit);
std::string ReadFile(const std::filesystem::path& path, std::size_t limit);
void PrintResult(const Json& value, bool table);
Json RequestSchema(const Json& session, const std::string& table,
                   bool static_configured = false, ReadChannel* channel = nullptr);
Json SendQuery(const Json& session, const Json& arguments,
               const std::string& id, int default_rows,
               const StaticOptions* options = nullptr,
               const std::atomic_bool* cancelled = nullptr,
               ReadChannel* channel = nullptr);
Json CaptureCheckpoint(const Json& session, const std::filesystem::path& path);
Json DiffCheckpoints(const std::filesystem::path& before_path,
                     const std::filesystem::path& after_path);
int RunMcp(std::string selected, std::optional<StaticOptions> options,
           bool compact);

}  // namespace xsql::cli

#endif  // X64DBGSQL_CLI_COMMANDS_HPP
