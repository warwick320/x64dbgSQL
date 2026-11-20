#ifndef X64DBGSQL_DEBUGGER_PROVIDER_HPP
#define X64DBGSQL_DEBUGGER_PROVIDER_HPP

#include "debugger/timeline.h"

namespace xsql::debugger {

class Provider final : public IDebuggerProvider {
 public:
  explicit Provider(Timeline& timeline) : timeline_(timeline) {}
  State GetState() override;
  Json ReadRows(std::string_view table, const State& state,
                Budget& budget) override;
  std::vector<std::uint8_t> ReadMemory(std::uint64_t address, unsigned size,
                                       Budget& budget) override;
  Json ReadInstructions(std::uint64_t address, unsigned count,
                        Budget& budget) override;

 private:
  Json ReadHistory(std::string_view table, const State& state,
                   const Budget& budget);
  Timeline& timeline_;
};

}  // namespace xsql::debugger

#endif  // X64DBGSQL_DEBUGGER_PROVIDER_HPP
