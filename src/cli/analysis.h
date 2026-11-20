#ifndef X64DBGSQL_CLI_ANALYSIS_HPP_
#define X64DBGSQL_CLI_ANALYSIS_HPP_

#include "analysis/source.h"

namespace xsql {
class ReadChannel;
}

namespace xsql::cli {

struct StaticOptions {
  analysis::Backend backend;
  std::string url;
  std::string module;
  std::string rva;
  std::string table;
  analysis::ReadOptions read;
};

struct StaticReadRequest {
  std::string table;
  analysis::ReadOptions read;
  int limit;
};

inline constexpr std::size_t kMaxStaticBatchReads = 32;

Json StaticInfo(const StaticOptions& options, const Budget& budget);
Json StaticCatalog(const StaticOptions& options, const Budget& budget);
Json StaticRead(const StaticOptions& options, int limit, const Budget& budget);
Json StaticReadBatch(const StaticOptions& options,
                     const std::vector<StaticReadRequest>& reads,
                     const Budget& budget);
Json BindStaticAnalysis(const StaticOptions& options, const Json& session,
                        const Budget& budget, ReadChannel* channel);

}  // namespace xsql::cli

#endif  // X64DBGSQL_CLI_ANALYSIS_HPP_
