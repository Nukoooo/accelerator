#include <filesystem>
#include <config.h>

#include "client/linux/handler/exception_handler.h"
#include "third_party/lss/linux_syscall_support.h"

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <array>
#include <ctime>
#include <dirent.h>
#include <fmt/base.h>
#include <fmt/chrono.h>
#include <fmt/core.h>
#include <thread>

#include <sys/stat.h>

#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/stack_frame.h"
#include "google_breakpad/processor/stack_frame_cpu.h"
#include "google_breakpad/processor/call_stack.h"
#include "processor/simple_symbol_supplier.h"
#include "processor/stackwalk_common.h"
#include "processor/pathname_stripper.h"

static constexpr std::array<int, 5> kExceptionSignals = { SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS };
void (*SignalHandler)(int, siginfo_t*, void*);
constexpr std::string_view dumpPath                 = "./breakpad";
google_breakpad::ExceptionHandler* exceptionHandler = nullptr;

bool g_should_stop = false;
#define MAX_PATH_LENGTH 260

static void kill_myself()
{
    kill(getpid(), SIGKILL);
}

static bool DumpCallback(const google_breakpad::MinidumpDescriptor& descriptor, void* context, bool succeeded)
{
    g_should_stop = true;

    try
    {
        std::filesystem::create_directories("./breakpad");
    }
    catch (const std::exception& e)
    {
        FILE* error_log = fopen("./breakpad_error.log", "a");
        if (error_log)
        {
            fprintf(error_log, "Failed to create breakpad directory: %s\n", e.what());
            fclose(error_log);
            
        }
        kill_myself();
        return false;
    }

    auto t               = std::time(nullptr);
    auto timestamp       = fmt::format("{:%Y-%m-%d-%H-%M-%S}", fmt::localtime(t));
    auto base_path       = fmt::format("./breakpad/crashdump_{}", timestamp);
    std::string log_path = base_path + ".log";

    // Open a log file for errors
    FILE* log_file = fopen(log_path.c_str(), "w");
    if (!log_file)
    {
        // Last resort - try to open a generic log
        log_file = fopen("./breakpad/crash_error.log", "a");
        if (!log_file)
            return false;
        fprintf(log_file, "[%s] Failed to open log file at %s\n", timestamp.c_str(), log_path.c_str());
    }

    if (!succeeded)
    {
        fprintf(log_file, "Failed to write minidump to %s\n", base_path.c_str());
        fclose(log_file);
        kill_myself();
        return false;
    }

    std::unique_ptr<google_breakpad::SimpleSymbolSupplier> symbolSupplier;
    google_breakpad::BasicSourceLineResolver resolver;
    google_breakpad::MinidumpProcessor minidump_processor(symbolSupplier.get(), &resolver);

    // Increase the maximum number of threads and regions.
    google_breakpad::MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
    google_breakpad::MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());

    // Process the minidump.
    google_breakpad::Minidump miniDump(descriptor.path());
    if (!miniDump.Read())
    {
        fprintf(log_file, "Failed to read minidump from %s\n", descriptor.path());
        fclose(log_file);
        kill_myself();
        return succeeded;
    }

    fprintf(log_file, "Successfully read minidump from %s\n", descriptor.path());

    google_breakpad::ProcessState processState;
    if (minidump_processor.Process(&miniDump, &processState) != google_breakpad::PROCESS_OK)
    {
        fprintf(log_file, "MinidumpProcessor::Process failed for %s\n", descriptor.path());
        fclose(log_file);
        kill_myself();
        return succeeded;
    }

    fprintf(log_file, "Successfully processed minidump\n");

    std::string info_path = base_path + ".txt";
    FILE* info_file       = fopen(info_path.c_str(), "w");
    if (info_file)
    {
        FILE* old_stdout = stdout;
        stdout           = info_file;
        PrintProcessState(processState, true, false, &resolver);
        fflush(stdout);
        stdout = old_stdout;
        fclose(info_file);
        fprintf(log_file, "Successfully wrote process state to %s\n", info_path.c_str());
    }
    else
    {
        fprintf(log_file, "Failed to open file for process state at %s: %s\n", info_path.c_str(), strerror(errno));
    }

    try
    {
        std::filesystem::remove(descriptor.path());
        fprintf(log_file, "Successfully removed raw minidump\n");
    }
    catch (const std::exception& e)
    {
        fprintf(log_file, "Failed to remove raw minidump: %s\n", e.what());
    }

    fclose(log_file);
    return succeeded;
}

extern "C" __attribute__((visibility("default"))) bool InitBreakpad()
{
    struct stat st = { 0 };
    if (stat(dumpPath.data(), &st) == -1)
    {
        if (mkdir(dumpPath.data(), 0770) == -1)
        {
            fmt::println("[Breakpad] Failed to create file path: {}", dumpPath.data());
            return false;
        }
    }
    else
    {
        chmod(dumpPath.data(), 0770);
    }

    google_breakpad::MinidumpDescriptor descriptor(dumpPath.data());
    exceptionHandler = new google_breakpad::ExceptionHandler(descriptor, nullptr, DumpCallback, nullptr, true, -1);

    struct sigaction oact;
    sigaction(SIGSEGV, NULL, &oact);
    SignalHandler = oact.sa_sigaction;

    std::thread(
      []()
      {
          using namespace std::chrono_literals;
          while (!g_should_stop)
          {
              bool needs_to_replace = false;
              struct sigaction oact;

              for (auto signal : kExceptionSignals)
              {
                  sigaction(signal, NULL, &oact);

                  if (oact.sa_sigaction != SignalHandler)
                  {
                      needs_to_replace = true;
                      break;
                  }
              }

              if (!needs_to_replace)
              {
                  std::this_thread::sleep_for(500ms);
                  return;
              }

              struct sigaction act;
              memset(&act, 0, sizeof(act));
              sigemptyset(&act.sa_mask);

              for (auto signal : kExceptionSignals)
                  sigaddset(&act.sa_mask, signal);

              act.sa_sigaction = SignalHandler;
              act.sa_flags     = SA_ONSTACK | SA_SIGINFO;

              for (auto signal : kExceptionSignals)
                  sigaction(signal, &act, NULL);
          }
      })
      .detach();

    return true;
}