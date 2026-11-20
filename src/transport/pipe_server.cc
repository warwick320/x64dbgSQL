// clang-format off
#include <windows.h>
#include <sddl.h>
// clang-format on

#include <array>
#include <fstream>
#include <thread>

#include "transport/pipe_io.h"

namespace xsql {

std::wstring LogonSid();
using platform::Handle;
using transport::Endpoint;
using transport::PipeName;
using transport::ReceiveFrame;
using transport::SendFrame;
using transport::Transfer;

struct PipeServer::Impl {
  std::string id;
  Json information;
  Handler handler;
  Handle stop_signal{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
  std::filesystem::path record;
  std::vector<std::thread> workers;

  Impl(std::string session_id, Json info, Handler receive_request)
      : id(std::move(session_id)),
        information(std::move(info)),
        handler(std::move(receive_request)) {}

  void Start() {
    if (!stop_signal.valid())
      throw Error("E_TRANSPORT", "Could not initialize server shutdown.");
    const auto sddl = L"D:P(A;;0x00120183;;;" + LogonSid() + L")";
    PSECURITY_DESCRIPTOR security = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &security, nullptr))
      throw Error("E_TRANSPORT", "Could not create local pipe security.");
    const std::unique_ptr<void, decltype(&LocalFree)> owned(security,
                                                            LocalFree);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), security,
                                   FALSE};
    constexpr std::array endpoints{Endpoint::kQuery, Endpoint::kStatus,
                                   Endpoint::kStream};
    std::array<Handle, endpoints.size()> pipes;
    for (std::size_t i = 0; i < endpoints.size(); ++i) {
      const auto name = PipeName(id, endpoints[i]);
      const auto mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                        FILE_FLAG_FIRST_PIPE_INSTANCE;
      Handle pipe(CreateNamedPipeW(
          name.c_str(), mode,
          PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1,
          65536, 65536, 0, &attributes));
      if (!pipe.valid())
        throw Error("E_TRANSPORT", "Could not create the named pipe.");
      pipes[i] = std::move(pipe);
    }
    for (std::size_t i = 0; i < pipes.size(); ++i)
      workers.emplace_back(
          [this, endpoint = endpoints[i], connection = std::move(pipes[i])] {
            AcceptLoop(connection.get(), endpoint);
          });

    const auto directory = SessionDirectory();
    std::filesystem::create_directories(directory);
    record = directory / (ToWide(id) + L".json");
    auto temporary = record;
    temporary += L".tmp";
    {
      std::ofstream stream(temporary, std::ios::binary);
      stream << SerializeUtf8(information);
      stream.close();
      if (!stream)
        throw Error("E_TRANSPORT", "Could not write the session record.");
    }
    if (!MoveFileExW(temporary.c_str(), record.c_str(),
                     MOVEFILE_WRITE_THROUGH)) {
      std::error_code error;
      std::filesystem::remove(temporary, error);
      throw Error("E_TRANSPORT", "Could not publish the session record.");
    }
  }

  Json Dispatch(const Json& request, Endpoint endpoint, ULONG pid) {
    try {
      const auto op = RequireString(request, "op", 24);
      if (endpoint == Endpoint::kStatus && op != "status" && op != "cancel" &&
          op != "action_status")
        throw Error("E_PROTOCOL",
                    "Only status and cancellation operations use this pipe.");
      if (endpoint == Endpoint::kStream && op != "query" && op != "schema")
        throw Error("E_PROTOCOL", "Only read requests use the stream pipe.");
      return handler(request, pid);
    } catch (const Error& error) {
      return Failure(error);
    } catch (const Json::exception&) {
      return Failure(Error("E_INPUT", "Invalid request fields."));
    } catch (...) {
      return Failure(
          Error("E_INTERNAL", "The plugin could not complete the request."));
    }
  }

  void AcceptLoop(HANDLE pipe, Endpoint endpoint) noexcept {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.valid())
      return;
    while (WaitForSingleObject(stop_signal.get(), 0) == WAIT_TIMEOUT) {
      try {
        OVERLAPPED io{};
        io.hEvent = event.get();
        ResetEvent(io.hEvent);
        if (!ConnectNamedPipe(pipe, &io)) {
          const auto error = GetLastError();
          if (error == ERROR_IO_PENDING) {
            const HANDLE signals[]{io.hEvent, stop_signal.get()};
            if (WaitForMultipleObjects(2, signals, FALSE, INFINITE) !=
                WAIT_OBJECT_0) {
              CancelIoEx(pipe, &io);
              DWORD size = 0;
              GetOverlappedResult(pipe, &io, &size, TRUE);
              return;
            }
            DWORD size = 0;
            if (!GetOverlappedResult(pipe, &io, &size, FALSE))
              continue;
          } else if (error != ERROR_PIPE_CONNECTED)
            continue;
        }
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        const auto hello = ReceiveFrame(pipe, stop_signal.get(), deadline);
        if (hello.value("op", "") != "hello" ||
            hello.value("version", 0) != kProtocolVersion) {
          SendFrame(
              pipe, stop_signal.get(),
              Failure(Error("E_VERSION", "Protocol version 1 is required.")),
              deadline);
        } else {
          auto welcome = information;
          welcome["ok"] = true;
          welcome["schema_hash"] = SchemaHash();
          SendFrame(pipe, stop_signal.get(), welcome, deadline);
          ULONG pid = 0;
          GetNamedPipeClientProcessId(pipe, &pid);
          const bool stream = endpoint == Endpoint::kStream;
          do {
            const auto request = ReceiveFrame(
                pipe, stop_signal.get(),
                stream ? Clock::now() + transport::kStreamIdle : deadline);
            const auto result = Dispatch(request, endpoint, pid);
            SendFrame(pipe, stop_signal.get(), result,
                      Clock::now() + std::chrono::seconds(3));
            // Bound the acknowledgement wait even when retaining the stream.
            char acknowledgement = 0;
            Transfer(pipe, stop_signal.get(), &acknowledgement, 1, false,
                     Clock::now() + std::chrono::seconds(1));
          } while (stream);
        }
      } catch (...) {
      }
      DisconnectNamedPipe(pipe);
    }
  }

  void Stop() {
    if (stop_signal.valid())
      SetEvent(stop_signal.get());
    for (auto& worker : workers)
      if (worker.joinable())
        worker.join();
    workers.clear();
    if (!record.empty()) {
      std::error_code error;
      std::filesystem::remove(record, error);
      record.clear();
    }
  }

  ~Impl() { Stop(); }
};

PipeServer::PipeServer(std::string id, Json information, Handler handler)
    : impl_(std::make_unique<Impl>(std::move(id), std::move(information),
                                   std::move(handler))) {
  impl_->Start();
}
PipeServer::~PipeServer() = default;
void PipeServer::Stop() { impl_->Stop(); }

}  // namespace xsql
