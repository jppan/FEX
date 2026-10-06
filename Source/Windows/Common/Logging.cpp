// SPDX-License-Identifier: MIT
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/LogManager.h>

#include <cstdio>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <winnt.h>

#ifdef FEX_IOS_HOST
#include <unistd.h>
#endif

#include "Logging.h"

namespace {
void (*WineDbgOut)(const char* Message);
FILE* LogFile;

/* iOS-Madeira ml194: FEX's log output was being DISCARDED, which is why no LogMan
 * message (e.g. "[TI-IC] lookupcache-alloc") has ever appeared in madeira-log.txt and why
 * every FEX-side question this session had to be answered indirectly from ntdll probes.
 *
 * Logging::Init() IS called (ARM64EC Module.cpp ProcessInit) and ProcessInit completes,
 * yet even its own install trace never showed up. Cause: this is a PE module, so
 * ::write(2, ...) goes through the CRT's descriptor table bound to the Windows stderr
 * HANDLE — NOT the unix fd 2 that the app redirects into madeira-log.txt. Writing to the
 * process's real hStdError is the path already proven to work here (see the FEX-iOS FATAL
 * message in ARM64EC/Module.cpp). */
#ifdef FEX_IOS_HOST
static void IosLogWrite(const char* Str, size_t Len) {
  FEX::Windows::Logging::RawWrite(Str, Len);
}

/* MADEIRA ml2033: Do not use fmt while dispatching an iOS LogMan message.
 *
 * Besides being needlessly recursive (fmt can itself report failures through
 * LogMan), the ARM64EC build of fmt 12 has been observed underflowing its
 * decimal-output cursor here.  The resulting `strh [base, w22, uxtw]` uses
 * 0xffffffff as an offset and writes 4 GiB past this stack buffer.  Keep the
 * early logging path leaf-like and bounded.  RawWrite ultimately passes this
 * C string to __wine_dbg_output, so assemble one complete, terminated line. */
static size_t IosAppend(char* Output, size_t Capacity, size_t Offset, const char* Input) {
  if (!Input) {
    Input = "(null)";
  }
  while (*Input && Offset + 2 < Capacity) {
    Output[Offset++] = *Input++;
  }
  return Offset;
}

static size_t IosAppendHex(char* Output, size_t Capacity, size_t Offset, DWORD Value) {
  char Reverse[sizeof(Value) * 2];
  size_t Digits {};
  do {
    const unsigned Nibble = Value & 0xf;
    Reverse[Digits++] = Nibble < 10 ? '0' + Nibble : 'A' + Nibble - 10;
    Value >>= 4;
  } while (Value);
  while (Digits && Offset + 2 < Capacity) {
    Output[Offset++] = Reverse[--Digits];
  }
  return Offset;
}

static void IosMsgWrite(LogMan::DebugLevels Level, const char* Message) {
  char Output[1024];
  size_t Offset {};
  Offset = IosAppend(Output, sizeof(Output), Offset, LogMan::DebugLevelStr(Level));
  Offset = IosAppend(Output, sizeof(Output), Offset, " ");
  Offset = IosAppendHex(Output, sizeof(Output), Offset, GetCurrentThreadId());
  Offset = IosAppend(Output, sizeof(Output), Offset, " ");
  Offset = IosAppend(Output, sizeof(Output), Offset, Message);
  Output[Offset++] = '\n';
  Output[Offset] = 0;
  IosLogWrite(Output, Offset);
}

static void IosAssertWrite(const char* Message) {
  char Output[1024];
  size_t Offset = IosAppend(Output, sizeof(Output), 0, "A ");
  Offset = IosAppend(Output, sizeof(Output), Offset, Message);
  Output[Offset++] = '\n';
  Output[Offset] = 0;
  IosLogWrite(Output, Offset);
}
#endif

static void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
#ifdef FEX_IOS_HOST
  /* iOS-Madeira: route directly to stderr (which is dup2'd to madeira-log.txt
   * by WineProcessBridge). __wine_dbg_output is exported but doesn't always
   * resolve via GetProcAddress on our embedded ntdll, so go around it. */
  IosMsgWrite(Level, Message);
  return;
#else
  const auto Output = fextl::fmt::format("{} {:X} {}\n", LogMan::DebugLevelStr(Level), GetCurrentThreadId(), Message);
  if (WineDbgOut) {
    WineDbgOut(Output.c_str());
  } else if (LogFile) {
    fwrite(Output.c_str(), 1, Output.size(), LogFile);
  }
#endif
}

static void AssertHandler(const char* Message) {
#ifdef FEX_IOS_HOST
  IosAssertWrite(Message);
  return;
#else
  const auto Output = fextl::fmt::format("A {}\n", Message);
  if (WineDbgOut) {
    WineDbgOut(Output.c_str());
  } else if (LogFile) {
    fwrite(Output.c_str(), 1, Output.size(), LogFile);
  }
#endif
}
} // namespace

namespace FEX::Windows::Logging {
/* ml195: hStdError is NULL in this context, so the WriteFile path produced nothing
 * (which also means the pre-existing "[FEX-iOS] FATAL" message was never functional).
 * Prefer __wine_dbg_output: it IS exported by our PE ntdll (export table ordinal 1464)
 * and is exactly what that ntdll's own ERR() lines go through — those reach
 * madeira-log.txt reliably. Keep WriteFile as a fallback.
 *
 * MADEIRA ml800: promoted out of the anonymous namespace so a module can report a fatal
 * reason BEFORE Init() has installed the LogMan handlers. Nothing here depends on LogMan,
 * on the config layer, or on a usable TEB TLS slot. */
void RawWrite(const char* Str, size_t Len) {
  static int (__cdecl *DbgOut)(const char*);
  static bool Resolved;
  if (!Resolved) {
    Resolved = true;
    DbgOut = reinterpret_cast<decltype(DbgOut)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "__wine_dbg_output"));
  }
  if (DbgOut) {
    DbgOut(Str);
    return;
  }
  /* MADEIRA: NtCurrentTeb() is a bare x18 read, and this is the fallback path of the function a
   * module uses to report why it is about to die - so it must never be the thing that kills it.
   * iOS zeroes x18 on the paths where a fatal report is most likely (pre-init, in a Mach handler),
   * and the chain below would then fault twice before printing anything. No output is a worse
   * answer than a printed message, but it is a far better one than a second fault with no message
   * at all. */
  auto* Teb = reinterpret_cast<__TEB*>(NtCurrentTeb());
  if (!Teb || !Teb->Peb || !Teb->Peb->ProcessParameters) {
    return;
  }
  HANDLE h = reinterpret_cast<HANDLE>(reinterpret_cast<RTL_USER_PROCESS_PARAMETERS64*>(Teb->Peb->ProcessParameters)->hStdError);
  if (h) {
    ULONG Written = 0;
    WriteFile(h, Str, static_cast<DWORD>(Len), &Written, nullptr);
  }
}

void Init() {
#ifndef FEX_IOS_HOST
  FEX_CONFIG_OPT(SilentLog, SILENTLOG);
  if (SilentLog()) {
    return;
  }
#endif

#ifdef FEX_IOS_HOST
  /* iOS-Madeira: trace install via stderr directly to confirm Init() ran. */
  const char *m = "[FEX-iOS] Logging::Init installing MsgHandler (ml2033 raw-prefix)\n";
  IosLogWrite(m, __builtin_strlen(m));
#endif

  WineDbgOut = reinterpret_cast<decltype(WineDbgOut)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "__wine_dbg_output"));
  if (!WineDbgOut) {
    const auto Path = fextl::fmt::format("{}\\fex-{}.log", getenv("LOCALAPPDATA"), GetCurrentProcessId());
    LogFile = fopen(Path.c_str(), "a");
  }
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);
}
} // namespace FEX::Windows::Logging
