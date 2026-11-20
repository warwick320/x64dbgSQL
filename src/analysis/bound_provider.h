#ifndef X64DBGSQL_ANALYSIS_BOUND_PROVIDER_HPP_
#define X64DBGSQL_ANALYSIS_BOUND_PROVIDER_HPP_

#include "core.h"

namespace xsql::analysis {

bool IsStaticTable(std::string_view name);

// Adapts a bounded, query-scoped static snapshot to the existing provider port.
class BoundProvider final : public IDebuggerProvider {
 public:
  BoundProvider(IDebuggerProvider& live, const Json& binding,
                const State& state, Budget& budget);

  State GetState() override { return live_.GetState(); }
  Json ReadRows(std::string_view table, const State& state,
                Budget& budget) override;
  std::vector<std::uint8_t> ReadMemory(std::uint64_t address, unsigned size,
                                       Budget& budget) override {
    return live_.ReadMemory(address, size, budget);
  }
  Json ReadInstructions(std::uint64_t address, unsigned count,
                        Budget& budget) override {
    return live_.ReadInstructions(address, count, budget);
  }

 private:
  IDebuggerProvider& live_;
  Json modules_;
  Json program_;
  Json functions_;
  Json native_rows_;
};

}  // namespace xsql::analysis

#endif  // X64DBGSQL_ANALYSIS_BOUND_PROVIDER_HPP_
