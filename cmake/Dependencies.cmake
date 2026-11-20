set(cache "${CMAKE_SOURCE_DIR}/.deps")
file(MAKE_DIRECTORY "${cache}")

function(fetch_asset filename url sha256)
  file(LOCK "${cache}/${filename}.lock" GUARD FUNCTION TIMEOUT 120)
  set(path "${cache}/${filename}")
  if(NOT EXISTS "${path}")
    file(DOWNLOAD "${url}" "${path}.part" TLS_VERIFY ON
      EXPECTED_HASH "SHA256=${sha256}" TIMEOUT 120)
    file(RENAME "${path}.part" "${path}")
  endif()
  file(SHA256 "${path}" actual)
  if(NOT actual STREQUAL sha256)
    message(FATAL_ERROR "Checksum mismatch: ${path}")
  endif()
  if(ARGC EQUAL 4)
    set(destination "${cache}/${ARGV3}")
    if(NOT EXISTS "${destination}/.archive-${sha256}")
      file(MAKE_DIRECTORY "${destination}")
      file(ARCHIVE_EXTRACT INPUT "${path}" DESTINATION "${destination}")
      file(TOUCH "${destination}/.archive-${sha256}")
    endif()
  endif()
endfunction()

fetch_asset(sqlite.zip https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
  0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9 sqlite)
fetch_asset(json.hpp https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp
  aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63)
set(sqlite_dir "${cache}/sqlite/sqlite-amalgamation-3540100")
set(json_dir "${cache}")

if(WIN32)
  set(release https://github.com/x64dbg/x64dbg/releases/download/2026.05.27)
  fetch_asset(sdk.zip "${release}/x64dbg-pluginsdk-cmake.zip"
    b669d6364816cbaed5257adad0df34a98a1791810a81941191d6f4aea74eb04e sdk)
  set(sdk_dir "${cache}/sdk")
  if(BUILD_TESTING)
    fetch_asset(snapshot.zip "${release}/snapshot_2026-05-27_12-11.zip"
      d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697 debugger)
    set(debugger_dir "${cache}/debugger")
  endif()
endif()
