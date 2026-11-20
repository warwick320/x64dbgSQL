#include <windows.h>

volatile DWORD fixture_counter = 42;

extern "C" __declspec(dllexport) __declspec(noinline) void
xsql_fixture_marker() {
  fixture_counter = fixture_counter + 1;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  for (int i = 0; i < 120; ++i) {
    xsql_fixture_marker();
    Sleep(250);
  }
  return 0;
}
