// Windows SDK types must precede the component headers.
// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
// clang-format on

#include <array>
#include <fstream>
#include <span>

#include "ipc.h"
#include "platform/windows_handle.h"

namespace xsql {

using platform::Handle;

namespace {
std::string EncodeHex(std::span<const unsigned char> bytes) {
  std::string value;
  value.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    value.push_back("0123456789abcdef"[byte >> 4]);
    value.push_back("0123456789abcdef"[byte & 15]);
  }
  return value;
}

}  // namespace

std::wstring LogonSid() {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
    throw Error("E_TRANSPORT", "Could not open the Windows logon token.");
  Handle token(raw_token);
  DWORD size = 0;
  GetTokenInformation(token.get(), TokenLogonSid, nullptr, 0, &size);
  if (!size)
    throw Error("E_TRANSPORT", "This Windows token has no logon SID.");
  std::vector<std::byte> buffer(size);
  if (!GetTokenInformation(token.get(), TokenLogonSid, buffer.data(), size,
                           &size))
    throw Error("E_TRANSPORT", "Could not read the Windows logon SID.");
  const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
  if (groups->GroupCount != 1)
    throw Error("E_TRANSPORT", "Windows returned an unexpected logon SID.");
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(groups->Groups[0].Sid, &sid))
    throw Error("E_TRANSPORT", "Could not format the Windows logon SID.");
  const std::unique_ptr<wchar_t, decltype(&LocalFree)> owned(sid, LocalFree);
  return sid;
}

std::string ToUtf8(std::wstring_view text) {
  if (text.empty())
    return {};
  const auto count = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
      nullptr, 0, nullptr, nullptr);
  if (!count)
    throw Error("E_INPUT", "Windows text could not be converted to UTF-8.");
  std::string output(count, '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                      static_cast<int>(text.size()), output.data(), count,
                      nullptr, nullptr);
  return output;
}

std::wstring ToWide(std::string_view text) {
  if (text.empty())
    return {};
  const auto count =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                          static_cast<int>(text.size()), nullptr, 0);
  if (!count)
    throw Error("E_INPUT", "Invalid UTF-8.");
  std::wstring output(count, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                      static_cast<int>(text.size()), output.data(), count);
  return output;
}

std::string NewId() {
  std::array<unsigned char, 16> random{};
  if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    throw Error("E_INTERNAL",
                "Could not generate a Windows random identifier.");
  return EncodeHex(random);
}

std::string FileSha256(const std::filesystem::path& file,
                       const Budget* budget) {
  std::ifstream input(file, std::ios::binary);
  if (!input)
    throw Error("E_INPUT", "Could not open the fixture image.");
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0))
    throw Error("E_INTERNAL", "Could not initialize SHA-256.");
  struct AlgorithmGuard {
    BCRYPT_ALG_HANDLE value;
    ~AlgorithmGuard() { BCryptCloseAlgorithmProvider(value, 0); }
  } algorithm_guard{algorithm};
  BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0))
    throw Error("E_INTERNAL", "Could not create SHA-256 state.");
  struct HashGuard {
    BCRYPT_HASH_HANDLE value;
    ~HashGuard() { BCryptDestroyHash(value); }
  } hash_guard{hash};
  std::array<unsigned char, 16384> buffer{};
  while (input) {
    if (budget)
      budget->Check();
    input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    if (BCryptHashData(hash, buffer.data(), static_cast<ULONG>(input.gcount()),
                       0))
      throw Error("E_INTERNAL", "Could not hash the fixture image.");
  }
  if (!input.eof())
    throw Error("E_INPUT", "Could not read the fixture image.");
  std::array<unsigned char, 32> result{};
  if (BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()),
                       0))
    throw Error("E_INTERNAL", "Could not finish SHA-256.");
  return EncodeHex(result);
}

std::filesystem::path SessionDirectory() {
  PWSTR value = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &value)))
    throw Error("E_TRANSPORT", "Windows LocalAppData is unavailable.");
  const std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> owned(value,
                                                                 CoTaskMemFree);
  return std::filesystem::path(value) / L"x64dbgsql" / L"sessions" / LogonSid();
}

}  // namespace xsql
