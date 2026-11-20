#ifndef X64DBGSQL_PLATFORM_ANALYZER_HTTP_HPP_
#define X64DBGSQL_PLATFORM_ANALYZER_HTTP_HPP_

#include "analysis/source.h"

namespace xsql::platform {

analysis::Source::Transport AnalyzerHttp(std::string_view url);

}  // namespace xsql::platform

#endif  // X64DBGSQL_PLATFORM_ANALYZER_HTTP_HPP_
