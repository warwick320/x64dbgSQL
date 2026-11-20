# x64dbg-MCP v1.8 기능 비교

공식 v1.8의 `tools/list`에서 확인한 80개 도구를 기능 단위로 대조합니다. 하나의 SQL 문장으로 여러 MCP 도구의 결과에 대응할 수 있으므로 도구 개수는 기능 개수와 일치하지 않습니다.

| 범위 | MCP 도구 | x64dbgSQL 경로 |
|---|---|---|
| 라이브 상태·데이터 | `GetDebugState`, `GetCurrentAddress`, `GetEventLog`, `ReadMemory`, `GetAllRegisters`, `GetCallStack`, `Disassemble`, `ListModules`, `ListBreakpoints`, `GetMemoryMap`, `GetThreads`, `ListBookmarks` | `session`, `events`, `memory`, `registers`, `call_stack`, `disassembly`, `modules`, `breakpoints`, `memory_map`, `threads`, `bookmarks` |
| 정적 데이터 | `SearchForStrings`, `GetStrings`, `GetImports`, `GetExports`, `GetReferences`, `GetFunctions`, `DisassembleFunction`, `SearchSymbols`, `ListSymbols` | IDASQL·GhidraSQL의 네이티브 읽기·조인. 개별 분석기 데이터와 x64dbg의 런타임 심볼은 의미가 다릅니다. |
| 승인된 로컬 편집 | `CommentOrLabelAtAddress`, `SetBookmark`, `DeleteBookmark` | 승인된 세션의 CLI `annotation`. MCP는 조회를 제공합니다. |
| 전용 테스트 제어 | `run`, `StepInto`, `PauseDebug`, `SetBreakpoint`, `DeleteBreakpoint` | 해시가 고정된 자체 테스트 대상에 제한된 동작 |
| SQL로 조합하거나 추가 구현이 필요한 조회·편의 기능 | `ListCommandsByCategory`, `EvalExpression`, `Echo`, `WaitForEvent`, `WaitForPause`, `GetPatches`, `FindPattern`, `FollowPointer`, `WatchExpressions`, `GetSEHChain`, `GetPEB`, `GetArguments`, `DumpMemory`, `DumpModule`, `DetectOEP`, `GetDumpableRegions` | 상태·이벤트·범위 조합 및 원시 조회의 구성 요소만 일부 제공 |
| 디버거·대상 제어 및 DB 명령 | `LoadBinary`, `ExecuteDebuggerCommand`, `ClearEventLog`, `AttachProcess`, `StepOver`, `StepOut`, `StopDebug`, `RestartDebug`, `WriteMemToAddress`, `SetRegister`, `SwitchThread`, `Assemble`, `SetHardwareBreakpoint`, `SetMemoryBreakpoint`, `RunToAddress`, `TraceInto`, `SetConditionalBreakpoint`, `AllocateMemory`, `FreeMemory`, `EnableBreakpoint`, `DisableBreakpoint`, `ToggleBreakpoint`, `DeleteAllBreakpoints`, `ResetHitCount`, `SuspendThread`, `ResumeThread`, `AnalyzeModule`, `RestorePatches`, `SetExceptionBreakpoint`, `DeleteExceptionBreakpoint`, `AnalyzeCode`, `TraceOver`, `SetBreakpointCommand`, `SetBreakpointFastResume`, `SaveDatabase` | x64dbg 또는 해당 정적 분석기의 기존 UI와 자체 명령 사용 |
