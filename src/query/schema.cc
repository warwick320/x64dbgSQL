#include "query/schema.h"

#include "core.h"

namespace xsql::sql {
constexpr Table kTables[] = {
    {"session",
     "state TEXT,epoch INTEGER,generation INTEGER,pid INTEGER,tid INTEGER,ip "
     "INTEGER,arch TEXT,oldest_seq INTEGER,newest_seq INTEGER,event_gap "
     "INTEGER",
     "Current debugger state and retained event range", false},
    {"events",
     "seq INTEGER,time_ms INTEGER,generation INTEGER,type TEXT,tid "
     "INTEGER,addr INTEGER,code INTEGER,monotonic_ms INTEGER",
     "Retained debugger events with UTC and session-relative timestamps",
     false},
    {"modules", "base INTEGER,size INTEGER,entry INTEGER,name TEXT,path TEXT",
     "Loaded modules"},
    {"sections",
     "module_base INTEGER,module TEXT,name TEXT,addr INTEGER,rva INTEGER,size "
     "INTEGER",
     "PE sections reported by the debugger for loaded images"},
    {"memory_map",
     "base INTEGER,size INTEGER,protect INTEGER,state INTEGER,type "
     "INTEGER,name TEXT",
     "Mapped memory regions"},
    {"threads", "tid INTEGER,ip INTEGER,start INTEGER,name TEXT,active INTEGER",
     "Debuggee threads"},
    {"registers", "tid INTEGER,name TEXT,value INTEGER",
     "Active thread integer registers and flags"},
    {"labels", "addr INTEGER,text TEXT,manual INTEGER", "Debugger labels"},
    {"comments", "addr INTEGER,text TEXT,manual INTEGER", "Debugger comments"},
    {"bookmarks", "addr INTEGER,manual INTEGER", "Debugger bookmarks"},
    {"breakpoints",
     "addr INTEGER,type INTEGER,enabled INTEGER,name TEXT,module TEXT",
     "Debugger breakpoints, with SDK numeric type"},
    {"call_stack",
     "tid INTEGER,frame INTEGER,addr INTEGER,from_addr INTEGER,to_addr "
     "INTEGER,comment TEXT",
     "Call stack reported for the active paused thread"},
    {"memory",
     "addr INTEGER,size INTEGER,bytes BLOB,input_addr INTEGER "
     "HIDDEN,input_size INTEGER HIDDEN",
     "Bounded memory range as memory(addr,size)"},
    {"disassembly",
     "addr INTEGER,size INTEGER,text TEXT,input_addr INTEGER "
     "HIDDEN,input_count INTEGER HIDDEN",
     "Live instruction text as disassembly(addr,count)"},
    {"static_program",
     "backend TEXT,module TEXT,sha256 TEXT,image_base INTEGER,runtime_base "
     "INTEGER,image_size INTEGER,focus_rva INTEGER,version TEXT,revision TEXT",
     "Verified static analyzer binding to a loaded PE"},
    {"static_functions",
     "backend TEXT,name TEXT,static_addr INTEGER,runtime_addr "
     "INTEGER,chunk_start INTEGER,chunk_end INTEGER,rva INTEGER,chunk_rva "
     "INTEGER,chunk_end_rva INTEGER",
     "Static function ownership with runtime and original addresses"},
    {"static_rows", "backend TEXT,native_table TEXT,ordinal INTEGER,data TEXT",
     "Selected native analyzer relation, one JSON object per row"},
};

constexpr View kViews[] = {
    {{"static_stop_context",
      "ip INTEGER,tid INTEGER,module TEXT,rva INTEGER,label TEXT,comment "
      "TEXT,static_function TEXT,static_addr INTEGER,runtime_addr "
      "INTEGER,backend TEXT",
      "Paused instruction pointer resolved to verified static function chunks"},
     "SELECT s.ip,s.tid,s.module,s.rva,s.label,s.comment,f.name AS "
     "static_function,"
     "f.static_addr,f.runtime_addr,p.backend FROM stop_context s CROSS JOIN "
     "static_program p "
     "LEFT JOIN static_functions f ON s.ip>=f.chunk_start AND s.ip<f.chunk_end "
     "WHERE s.ip>=p.runtime_base AND s.ip-p.runtime_base<p.image_size"},
    {{"stop_context",
      "ip INTEGER,tid INTEGER,module TEXT,rva INTEGER,label TEXT,comment TEXT",
      "Current stop with resolved module-relative address and annotations"},
     "SELECT s.ip,s.tid,m.name AS module,s.ip-m.base AS rva,l.text AS "
     "label,c.text AS comment "
     "FROM session s LEFT JOIN modules m ON s.ip >= m.base AND s.ip-m.base < "
     "m.size "
     "LEFT JOIN labels l ON l.addr=s.ip LEFT JOIN comments c ON c.addr=s.ip "
     "WHERE s.state='paused'"},
    {{"register_context",
      "tid INTEGER,name TEXT,value INTEGER,module TEXT,rva "
      "INTEGER,region_protect INTEGER",
      "Register values resolved against modules and the memory map"},
     "SELECT r.tid,r.name,r.value,m.name AS module,r.value-m.base AS "
     "rva,p.protect AS region_protect "
     "FROM registers r LEFT JOIN modules m ON r.value>=m.base AND "
     "r.value-m.base<m.size "
     "LEFT JOIN memory_map p ON r.value>=p.base AND r.value-p.base<p.size"},
    {{"image_layout",
      "module TEXT,section TEXT,rva INTEGER,section_addr INTEGER,section_size "
      "INTEGER,region_base INTEGER,region_size INTEGER,protect "
      "INTEGER,region_state INTEGER",
      "PE section ranges joined with overlapping runtime memory regions"},
     "SELECT s.module,s.name AS section,s.rva,s.addr AS section_addr,s.size AS "
     "section_size,"
     "p.base AS region_base,p.size AS region_size,p.protect,p.state AS "
     "region_state "
     "FROM sections s LEFT JOIN memory_map p ON s.size>0 AND p.size>0 "
     "AND s.addr<p.base+p.size AND p.base<s.addr+s.size"},
    {{"event_spans",
      "seq INTEGER,generation INTEGER,type TEXT,time_ms INTEGER,next_seq "
      "INTEGER,elapsed_ms INTEGER",
      "Timeline with duration until the next retained event of the same "
      "debuggee"},
     "SELECT seq,generation,type,time_ms,lead(seq) OVER w AS next_seq,"
     "lead(monotonic_ms) OVER w-monotonic_ms AS elapsed_ms FROM events "
     "WINDOW w AS (PARTITION BY generation ORDER BY seq)"},
};

bool IsMemory(const Table& table) {
  return std::string_view(table.name) == "memory";
}

bool IsDisassembly(const Table& table) {
  return std::string_view(table.name) == "disassembly";
}

const Table* FindTable(std::string_view name) {
  for (const auto& table : kTables)
    if (name == table.name)
      return &table;
  for (const auto& view : kViews)
    if (name == view.table.name)
      return &view.table;
  return nullptr;
}

std::span<const Table> Tables() { return kTables; }
std::span<const View> Views() { return kViews; }
}  // namespace xsql::sql

namespace xsql {
using sql::IsMemory;
using sql::IsDisassembly;
using sql::Table;
using sql::Tables;
using sql::Views;

Json DescribeSchema(std::string_view name) {
  Json entries = Json::array();
  const auto add = [&](const Table& table, const char* kind) {
    if (!name.empty() && name != table.name)
      return;
    Json columns = Json::array();
    auto definitions = std::string_view(table.columns);
    while (!definitions.empty()) {
      const auto comma = definitions.find(',');
      const auto definition = definitions.substr(0, comma);
      const auto space = definition.find(' ');
      const auto type = definition.substr(space + 1);
      const auto modifier = type.find(' ');
      columns.push_back({{"name", definition.substr(0, space)},
                         {"type", type.substr(0, modifier)},
                         {"hidden", modifier != std::string_view::npos}});
      if (comma == std::string_view::npos)
        break;
      definitions.remove_prefix(comma + 1);
    }
    entries.push_back({{"name", table.name},
                       {"kind", kind},
                       {"columns", std::move(columns)},
                       {"description", table.description},
                       {"requires_paused", table.paused}});
    if (std::string_view(table.name).starts_with("static_"))
      entries.back()["requires_static_analysis"] = true;
  };
  for (const auto& table : Tables())
    add(table, (IsMemory(table) || IsDisassembly(table)) ? "function" : "table");
  for (const auto& view : Views())
    add(view.table, "view");
  if (entries.empty())
    throw Error("E_NO_TABLE", "Table not found in the public schema.");
  return {{"ok", true},
          {"protocol_version", kProtocolVersion},
          {"tables", std::move(entries)},
          {"limits",
           {{"max_rows", 1000},
            {"max_result_bytes", kMaxResult},
            {"max_sql_bytes", kMaxSql},
            {"max_timeout_ms", 15000},
            {"max_memory_range", 4096},
            {"max_memory_bytes", 65536},
            {"max_distinct_memory_reads", 256},
            {"max_disassembly_rows", kMaxDisassemblyRows},
            {"max_statement_instructions", kMaxStatementInstructions}}}};
}

std::string SchemaHash() {
  static const auto hash = [] {
    std::uint64_t value = 14695981039346656037ULL;
    for (const auto byte : DescribeSchema().dump()) {
      value ^= static_cast<unsigned char>(byte);
      value *= 1099511628211ULL;
    }
    return std::to_string(value);
  }();
  return hash;
}

}  // namespace xsql
