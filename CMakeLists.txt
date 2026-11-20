cmake_minimum_required(VERSION 3.25)
project(x64dbgSQL VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
include(cmake/Dependencies.cmake)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_library(sqlite STATIC "${sqlite_dir}/sqlite3.c")
target_include_directories(sqlite PUBLIC "${sqlite_dir}")
target_compile_definitions(sqlite PRIVATE SQLITE_OMIT_LOAD_EXTENSION SQLITE_DQS=0
  SQLITE_TEMP_STORE=3 SQLITE_PRINTF_PRECISION_LIMIT=131072)
if(UNIX)
  find_package(Threads REQUIRED)
  target_link_libraries(sqlite PRIVATE Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

add_library(x64dbgsql_core STATIC
  src/analysis/bound_provider.cc
  src/analysis/source.cc
  src/query/contracts.cc
  src/query/engine.cc
  src/query/schema.cc
  src/query/virtual_table.cc)
target_compile_features(x64dbgsql_core PUBLIC cxx_std_20)
target_include_directories(x64dbgsql_core PUBLIC src)
target_include_directories(x64dbgsql_core SYSTEM PUBLIC "${json_dir}")
target_link_libraries(x64dbgsql_core PRIVATE sqlite)
if(MSVC)
  add_compile_options(/utf-8 /W4)
  target_compile_options(x64dbgsql_core PRIVATE /utf-8 /W4)
endif()

if(WIN32)
  add_library(x64dbgsql_ipc STATIC
    src/platform/windows.cc
    src/transport/pipe_client.cc
    src/transport/pipe_io.cc
    src/transport/pipe_server.cc)
  target_link_libraries(x64dbgsql_ipc PUBLIC x64dbgsql_core advapi32 bcrypt shell32 ole32)
  target_compile_definitions(x64dbgsql_ipc PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

  add_library(x64dbgsql_cli_objects OBJECT
    src/cli/analysis.cc
    src/cli/checkpoint.cc
    src/cli/console.cc
    src/cli/main.cc
    src/cli/mcp.cc
    src/platform/analyzer_http.cc)
  target_link_libraries(x64dbgsql_cli_objects PUBLIC x64dbgsql_ipc winhttp)

  add_executable(x64dbgsql_cli src/cli/x64dbgsql.manifest)
  set_target_properties(x64dbgsql_cli PROPERTIES OUTPUT_NAME x64dbgsql)
  target_link_libraries(x64dbgsql_cli PRIVATE x64dbgsql_cli_objects)

  add_executable(x64dbgsql_headless WIN32)
  set_target_properties(x64dbgsql_headless PROPERTIES OUTPUT_NAME x64dbgsql-headless)
  target_link_libraries(x64dbgsql_headless PRIVATE x64dbgsql_cli_objects)
  # Both executables use the same wide-argument CRT entry point.
  if(MSVC)
    target_link_options(x64dbgsql_headless PRIVATE /ENTRY:wmainCRTStartup)
  else()
    target_link_options(x64dbgsql_headless PRIVATE -municode -Wl,-e,wmainCRTStartup)
  endif()

  add_library(x64dbgsql_plugin SHARED
    src/debugger/actions.cc
    src/debugger/entry.cc
    src/debugger/fixture.cc
    src/debugger/provider.cc
    src/debugger/session.cc)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(plugin_suffix .dp64)
    set(sdk_prefix x64)
  else()
    set(plugin_suffix .dp32)
    set(sdk_prefix x32)
  endif()
  set_target_properties(x64dbgsql_plugin PROPERTIES OUTPUT_NAME x64dbgsql SUFFIX "${plugin_suffix}")
  target_include_directories(x64dbgsql_plugin SYSTEM PRIVATE "${sdk_dir}/pluginsdk")
  target_link_libraries(x64dbgsql_plugin PRIVATE x64dbgsql_ipc
    "${sdk_dir}/pluginsdk/${sdk_prefix}dbg.lib"
    "${sdk_dir}/pluginsdk/${sdk_prefix}bridge.lib")

  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS x64dbgsql_cli x64dbgsql_headless RUNTIME DESTINATION . COMPONENT Runtime)
  endif()
  install(TARGETS x64dbgsql_plugin RUNTIME DESTINATION "${sdk_prefix}/plugins" COMPONENT Runtime)
endif()

if(BUILD_TESTING)
  add_executable(core_tests tests/core_tests.cc)
  target_link_libraries(core_tests PRIVATE x64dbgsql_core)
  add_test(NAME core COMMAND core_tests)
  if(WIN32)
    add_executable(x64dbgsql_fixture WIN32 tests/fixture.cc)
    target_compile_features(x64dbgsql_fixture PRIVATE cxx_std_20)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(fixture_arch x64)
    else()
      set(fixture_arch x86)
    endif()
    install(TARGETS x64dbgsql_fixture RUNTIME DESTINATION "fixtures/${fixture_arch}" COMPONENT TestFixtures)
    set(fixture_header "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/fixture_hash.h")
    add_custom_command(OUTPUT "${fixture_header}"
      COMMAND "${CMAKE_COMMAND}" "-Dfixture=$<TARGET_FILE:x64dbgsql_fixture>"
        "-Doutput=${fixture_header}" -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FixtureHash.cmake"
      DEPENDS x64dbgsql_fixture cmake/FixtureHash.cmake VERBATIM)
    target_sources(x64dbgsql_plugin PRIVATE "${fixture_header}")
    target_include_directories(x64dbgsql_plugin PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
    add_test(NAME headless COMMAND powershell -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/headless.ps1"
      -Debugger "${debugger_dir}/release/${sdk_prefix}/headless.exe"
      -Plugin "$<TARGET_FILE:x64dbgsql_plugin>"
      -Cli "$<TARGET_FILE:x64dbgsql_cli>"
      -AlternateCli "${CMAKE_SOURCE_DIR}/out/windows-x64/$<CONFIG>/x64dbgsql.exe"
      -Fixture "$<TARGET_FILE:x64dbgsql_fixture>")
    set_tests_properties(headless PROPERTIES TIMEOUT 90)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
      add_test(NAME console COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/console.py"
        "$<TARGET_FILE:x64dbgsql_cli>" "$<TARGET_FILE:x64dbgsql_fixture>")
      set_tests_properties(console PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 20)
      add_test(NAME windowless COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/windowless.py"
        "$<TARGET_FILE:x64dbgsql_headless>"
        "${debugger_dir}/release/${sdk_prefix}/headless.exe"
        "$<TARGET_FILE:x64dbgsql_plugin>" "$<TARGET_FILE:x64dbgsql_fixture>")
      set_tests_properties(windowless PROPERTIES TIMEOUT 45)
      add_test(NAME federation COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/federation.py"
        --debugger "${debugger_dir}/release/${sdk_prefix}/headless.exe"
        --plugin "$<TARGET_FILE:x64dbgsql_plugin>"
        --cli "$<TARGET_FILE:x64dbgsql_cli>"
        --fixture "$<TARGET_FILE:x64dbgsql_fixture>")
      set_tests_properties(federation PROPERTIES TIMEOUT 90)
      add_test(NAME benchmark_measurement COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/test_measurement.py")
      set_tests_properties(benchmark_measurement PROPERTIES TIMEOUT 20)
    endif()
  endif()
endif()
