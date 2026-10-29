// RenoDXDLSSGuard.cpp
//
// SKSE plugin for Skyrim SE/AE (x64). Standalone: no CommonLibSSE, no SKSE headers.
//
// WHAT IT GUARDS AGAINST
//   renodx-dlss.addon64 handing ReShade an output pointer that lies inside the add-on's
//   own image, on a page that is not writable. ReShade's dxgi.dll then faults with
//       EXCEPTION_ACCESS_VIOLATION (write)  at  dxgi.dll+...   mov [rdi], rax
//       fault address = renodx-dlss.addon64 + <offset>
//   (seen when Community Shaders' Upscaling runs DLSS through Streamline).
//
// HOW IT RECOVERS
//   A vectored exception handler catches ONLY write-access-violations whose target
//   address is inside a module whose file name matches TargetModules, then:
//
//   A) The target page belongs to a section the PE header declares WRITABLE (.data/.bss)
//      but its current protection is read-only. Someone flipped the page. Restore
//      PAGE_READWRITE and retry the instruction. Lossless.
//
//   B) The target page belongs to a section declared read-only (.rdata/.text). The add-on
//      is writing to something it should not. Controlled by ReadOnlyWriteMode:
//        skip       - drop that one store (decoded, cross-checked) and continue.   [default]
//        unprotect  - make the page writable and let the write happen.
//        crash      - do nothing; only log.
//
//   Anything unrecognised falls through untouched, so behaviour is never worse than without
//   the plugin. Every event is logged with registers, a stack scan, and the bytes at the target.

#ifndef _WIN64
#error "x64 only"
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>

#include "StoreDecoder.h"

#define GUARD_VERSION "1.0.0"

// ---------------------------------------------------------------------------------------
// SKSE plugin interface (hand-declared; we never call back into SKSE)
// ---------------------------------------------------------------------------------------
struct SKSEInterface;

struct SKSEPluginVersionData {
    std::uint32_t dataVersion;
    std::uint32_t pluginVersion;
    char          name[256];
    char          author[256];
    char          supportEmail[252];
    std::uint32_t versionIndependenceEx;    // bit0: NoStructUse
    std::uint32_t versionIndependence;      // bit1: Signatures (no hard-coded addresses), bit2: StructsPost629
    std::uint32_t compatibleVersions[16];   // zero-terminated
    std::uint32_t seVersionRequired;
};
static_assert(sizeof(SKSEPluginVersionData) == 0x350, "SKSEPluginVersionData layout");

extern "C" {
__declspec(dllexport) extern const SKSEPluginVersionData SKSEPlugin_Version;
__declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface* skse);
}

const SKSEPluginVersionData SKSEPlugin_Version = {
    1, 1, "RenoDXDLSSGuard", "community", "",
    1, 2 | 4,
    { 0x01064920u /* 1.6.1170 */, 0 },
    0
};

namespace {

// ---------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------
enum class WriteMode { Skip, Unprotect, Crash };

struct Config {
    bool         enabled        = true;
    bool         selfTest       = false;
    WriteMode    roMode         = WriteMode::Skip;
    unsigned     maxRecoveries  = 0;          // 0 = unlimited
    int          targetCount    = 0;
    wchar_t      targets[8][64] = {};
};

Config               g_cfg;
std::atomic<bool>    g_installed{false};
std::atomic<bool>    g_disabled{false};
std::atomic<bool>    g_selfTestActive{false};
std::atomic<unsigned> g_events{0};
std::atomic<unsigned> g_recoveries{0};
PVOID                g_veh = nullptr;
HMODULE              g_self = nullptr;

// ---------------------------------------------------------------------------------------
// Logging (no heap allocation: this runs inside an exception handler)
// ---------------------------------------------------------------------------------------
HANDLE           g_log = INVALID_HANDLE_VALUE;
CRITICAL_SECTION g_logLock;

void Logf(const char* fmt, ...)
{
    char buf[1100];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int n = std::snprintf(buf, sizeof(buf), "[%02u:%02u:%02u.%03u] ",
                          st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (n < 0) return;
    va_list ap;
    va_start(ap, fmt);
    int m = std::vsnprintf(buf + n, sizeof(buf) - static_cast<size_t>(n) - 3, fmt, ap);
    va_end(ap);
    if (m < 0) return;
    size_t len = static_cast<size_t>(n) + static_cast<size_t>(m);
    if (len > sizeof(buf) - 3) len = sizeof(buf) - 3;
    buf[len++] = '\r';
    buf[len++] = '\n';
    buf[len] = 0;

    EnterCriticalSection(&g_logLock);
    if (g_log != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_log, buf, static_cast<DWORD>(len), &written, nullptr);
    }
    LeaveCriticalSection(&g_logLock);
    OutputDebugStringA(buf);
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------
bool IsExecProtect(DWORD p)
{
    return (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool IsWritableProtect(DWORD p)
{
    return (p & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Lower-cased file name of a loaded module (narrow, ASCII-lossy is fine for matching/logging).
bool ModuleBaseName(HMODULE mod, wchar_t* out, size_t cap)
{
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(mod, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    const wchar_t* base = path;
    for (const wchar_t* c = path; *c; ++c)
        if (*c == L'\\' || *c == L'/') base = c + 1;
    size_t i = 0;
    for (; base[i] && i + 1 < cap; ++i) out[i] = base[i];
    out[i] = 0;
    return true;
}

void ToNarrow(const wchar_t* w, char* out, size_t cap)
{
    int r = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, static_cast<int>(cap), nullptr, nullptr);
    if (r <= 0) out[0] = 0;
}

// "name.dll+0xOFFSET" for any address inside a mapped image. If requireExec, the page must be executable.
bool DescribeAddress(std::uintptr_t addr, char* out, size_t cap, bool requireExec)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) return false;
    if (mbi.Type != MEM_IMAGE || mbi.State != MEM_COMMIT) return false;
    if (requireExec && !IsExecProtect(mbi.Protect)) return false;
    wchar_t wname[128];
    if (!ModuleBaseName(static_cast<HMODULE>(mbi.AllocationBase), wname, 128)) return false;
    char name[256];
    ToNarrow(wname, name, sizeof(name));
    std::snprintf(out, cap, "%s+0x%llX", name,
                  static_cast<unsigned long long>(addr - reinterpret_cast<std::uintptr_t>(mbi.AllocationBase)));
    return true;
}

// Only reached for write-faults into mapped images, which are rare, so no caching.
bool IsTargetModule(HMODULE mod)
{
    if (mod == g_self && g_selfTestActive.load()) return true;
    wchar_t name[128];
    if (!ModuleBaseName(mod, name, 128)) return false;
    for (wchar_t* c = name; *c; ++c) *c = static_cast<wchar_t>(std::towlower(*c));
    for (int i = 0; i < g_cfg.targetCount; ++i)
        if (std::wcsstr(name, g_cfg.targets[i]) != nullptr) return true;
    return false;
}

const IMAGE_NT_HEADERS64* GetNt(HMODULE mod)
{
    auto base = reinterpret_cast<const std::uint8_t*>(mod);
    auto dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE ? nt : nullptr;
}

const IMAGE_SECTION_HEADER* FindSection(HMODULE mod, std::uintptr_t addr)
{
    const IMAGE_NT_HEADERS64* nt = GetNt(mod);
    if (!nt) return nullptr;
    const DWORD rva = static_cast<DWORD>(addr - reinterpret_cast<std::uintptr_t>(mod));
    const IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s) {
        const DWORD size = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (rva >= s->VirtualAddress && rva < s->VirtualAddress + size) return s;
    }
    return nullptr;
}

bool SafeRead(const void* src, void* dst, size_t len, size_t* got)
{
    SIZE_T n = 0;
    BOOL ok = ReadProcessMemory(GetCurrentProcess(), src, dst, len, &n);
    if (got) *got = n;
    return ok || n > 0;
}

bool GetReg(const CONTEXT* c, int r, std::uint64_t& v)
{
    switch (r) {
    case 0:  v = c->Rax; return true;   case 1:  v = c->Rcx; return true;
    case 2:  v = c->Rdx; return true;   case 3:  v = c->Rbx; return true;
    case 4:  v = c->Rsp; return true;   case 5:  v = c->Rbp; return true;
    case 6:  v = c->Rsi; return true;   case 7:  v = c->Rdi; return true;
    case 8:  v = c->R8;  return true;   case 9:  v = c->R9;  return true;
    case 10: v = c->R10; return true;   case 11: v = c->R11; return true;
    case 12: v = c->R12; return true;   case 13: v = c->R13; return true;
    case 14: v = c->R14; return true;   case 15: v = c->R15; return true;
    default: return false;
    }
}

// ---------------------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------------------
void DumpEvent(const EXCEPTION_POINTERS* ep, HMODULE target, const IMAGE_SECTION_HEADER* sec,
               const MEMORY_BASIC_INFORMATION& mbi, std::uintptr_t fault)
{
    const CONTEXT* c = ep->ContextRecord;
    char where[300];

    wchar_t wname[128] = L"?";
    ModuleBaseName(target, wname, 128);
    char tname[256];
    ToNarrow(wname, tname, sizeof(tname));
    const IMAGE_NT_HEADERS64* nt = GetNt(target);
    Logf("  target module : %s  base=%p  SizeOfImage=0x%X  TimeDateStamp=0x%08X",
         tname, static_cast<void*>(target),
         nt ? nt->OptionalHeader.SizeOfImage : 0u, nt ? nt->FileHeader.TimeDateStamp : 0u);

    if (sec) {
        char sname[9] = {};
        std::memcpy(sname, sec->Name, 8);
        Logf("  target section: %s  declared %s%s%s  | current page protect=0x%02lX (%s)",
             sname,
             (sec->Characteristics & IMAGE_SCN_MEM_READ)    ? "R" : "-",
             (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   ? "W" : "-",
             (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? "X" : "-",
             static_cast<unsigned long>(mbi.Protect),
             IsWritableProtect(mbi.Protect) ? "writable" : "NOT writable");
    } else {
        Logf("  target section: <none/headers>  | current page protect=0x%02lX", static_cast<unsigned long>(mbi.Protect));
    }

    if (DescribeAddress(c->Rip, where, sizeof(where), false))
        Logf("  faulting RIP  : %p = %s", reinterpret_cast<void*>(c->Rip), where);
    Logf("  fault address : %p = target+0x%llX", reinterpret_cast<void*>(fault),
         static_cast<unsigned long long>(fault - reinterpret_cast<std::uintptr_t>(target)));

    std::uint8_t b[32];
    size_t got = 0;
    if (SafeRead(reinterpret_cast<const void*>(c->Rip), b, 16, &got) && got) {
        char hex[64] = {};
        for (size_t i = 0; i < got && i < 16; ++i) std::snprintf(hex + i * 3, 4, "%02X ", b[i]);
        Logf("  insn bytes    : %s", hex);
    }
    if (SafeRead(reinterpret_cast<const void*>(fault), b, 32, &got) && got) {
        char hex[128] = {};
        for (size_t i = 0; i < got && i < 32; ++i) std::snprintf(hex + i * 3, 4, "%02X ", b[i]);
        Logf("  bytes at target: %s", hex);
    }

    Logf("  RAX=%016llX RCX=%016llX RDX=%016llX RBX=%016llX", c->Rax, c->Rcx, c->Rdx, c->Rbx);
    Logf("  RSP=%016llX RBP=%016llX RSI=%016llX RDI=%016llX", c->Rsp, c->Rbp, c->Rsi, c->Rdi);
    Logf("  R8 =%016llX R9 =%016llX R10=%016llX R11=%016llX", c->R8, c->R9, c->R10, c->R11);
    Logf("  R12=%016llX R13=%016llX R14=%016llX R15=%016llX", c->R12, c->R13, c->R14, c->R15);

    std::uint64_t stack[192];
    if (SafeRead(reinterpret_cast<const void*>(c->Rsp), stack, sizeof(stack), &got) && got >= 8) {
        unsigned shown = 0;
        for (size_t i = 0; i < got / 8 && shown < 40; ++i) {
            if (DescribeAddress(static_cast<std::uintptr_t>(stack[i]), where, sizeof(where), true)) {
                Logf("  [rsp+%03zX] %s", i * 8, where);
                ++shown;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------------------
// Loop breaker for "fix the page and retry" paths: if the very same instruction faults on the
// very same address again and again within a second, our fix is not sticking - stop retrying.
std::uintptr_t g_lastRetryRip = 0, g_lastRetryAddr = 0;
ULONGLONG      g_lastRetryTick = 0;
unsigned       g_retryCount    = 0;

bool NoteRetry(std::uintptr_t rip, std::uintptr_t addr)
{
    const ULONGLONG now = GetTickCount64();
    if (rip == g_lastRetryRip && addr == g_lastRetryAddr && now - g_lastRetryTick < 1000) {
        g_lastRetryTick = now;
        if (++g_retryCount > 3) return false;
    } else {
        g_lastRetryRip = rip;
        g_lastRetryAddr = addr;
        g_lastRetryTick = now;
        g_retryCount = 1;
    }
    return true;
}

LONG CALLBACK Handler(PEXCEPTION_POINTERS ep)
{
    const EXCEPTION_RECORD* er = ep->ExceptionRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || er->NumberParameters < 2 ||
        er->ExceptionInformation[0] != 1 /* write */)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_cfg.enabled || g_disabled.load(std::memory_order_relaxed))
        return EXCEPTION_CONTINUE_SEARCH;

    const std::uintptr_t fault = static_cast<std::uintptr_t>(er->ExceptionInformation[1]);

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(fault), &mbi, sizeof(mbi)) || mbi.Type != MEM_IMAGE)
        return EXCEPTION_CONTINUE_SEARCH;
    HMODULE target = static_cast<HMODULE>(mbi.AllocationBase);
    if (!IsTargetModule(target))
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* ctx = ep->ContextRecord;
    const unsigned ev = ++g_events;
    const bool verbose = ev <= 8;
    const IMAGE_SECTION_HEADER* sec = FindSection(target, fault);

    if (verbose) {
        Logf("---- write fault #%u into guarded module ----", ev);
        DumpEvent(ep, target, sec, mbi, fault);
    } else if ((ev & 0xFF) == 0) {
        Logf("write fault #%u (recovered so far: %u)", ev, g_recoveries.load());
    }

    if (g_cfg.maxRecoveries && g_recoveries.load() >= g_cfg.maxRecoveries) {
        g_disabled.store(true);
        Logf("MaxRecoveries (%u) reached - guard disabled, exceptions pass through.", g_cfg.maxRecoveries);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    auto protectPage = [&](bool keepExec) -> bool {
        DWORD old = 0;
        void* page = reinterpret_cast<void*>(fault & ~static_cast<std::uintptr_t>(0xFFF));
        const DWORD want = (keepExec && IsExecProtect(mbi.Protect)) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        return VirtualProtect(page, 0x1000, want, &old) != FALSE;
    };

    // Page is writable right now (another thread fixed it between the fault and here): just retry.
    if (IsWritableProtect(mbi.Protect)) {
        if (!NoteRetry(ctx->Rip, fault)) return EXCEPTION_CONTINUE_SEARCH;
        if (verbose) Logf("  action: page already writable - retrying");
        ++g_recoveries;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Case A: section is declared writable, but the page protection was changed.
    const bool declaredWritable = sec && (sec->Characteristics & IMAGE_SCN_MEM_WRITE) &&
                                  !(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE);
    if (declaredWritable) {
        if (!NoteRetry(ctx->Rip, fault)) { Logf("  action: restore did not stick - giving up"); return EXCEPTION_CONTINUE_SEARCH; }
        if (protectPage(false)) {
            if (verbose) Logf("  action: CASE A - writable section had a read-only page; restored PAGE_READWRITE, retrying");
            ++g_recoveries;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        Logf("  action: VirtualProtect failed (err %lu) - letting the crash through", GetLastError());
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Case B: the add-on is writing into data/code that is declared read-only.
    switch (g_cfg.roMode) {
    case WriteMode::Crash:
        if (verbose) Logf("  action: CASE B - read-only section, ReadOnlyWriteMode=crash -> passing through");
        return EXCEPTION_CONTINUE_SEARCH;

    case WriteMode::Unprotect:
        if (!NoteRetry(ctx->Rip, fault)) return EXCEPTION_CONTINUE_SEARCH;
        if (protectPage(true)) {
            if (verbose) Logf("  action: CASE B - read-only section; made page writable (unprotect), retrying");
            ++g_recoveries;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        Logf("  action: VirtualProtect failed (err %lu) - letting the crash through", GetLastError());
        return EXCEPTION_CONTINUE_SEARCH;

    case WriteMode::Skip: {
        std::uint8_t code[16];
        size_t got = 0;
        guard::StoreInsn insn;
        if (!SafeRead(reinterpret_cast<const void*>(ctx->Rip), code, sizeof(code), &got) ||
            !guard::DecodeStore(code, got, insn)) {
            if (verbose) Logf("  action: CASE B - instruction not a recognised plain store, cannot skip -> passing through");
            return EXCEPTION_CONTINUE_SEARCH;
        }

        std::uint64_t ea = 0;
        bool ok = true;
        if (insn.ripRelative) {
            ea = ctx->Rip + insn.length;
        } else {
            if (insn.base >= 0)  { std::uint64_t v; ok = GetReg(ctx, insn.base, v) && ok;  ea += v; }
            if (insn.index >= 0) { std::uint64_t v; ok = GetReg(ctx, insn.index, v) && ok; ea += v * insn.scale; }
        }
        ea += static_cast<std::uint64_t>(insn.disp);
        const std::uint64_t delta = fault >= ea ? fault - ea : ea - fault;
        if (!ok || delta >= 64) {
            if (verbose) Logf("  action: CASE B - decoded effective address %llX does not match fault %llX -> passing through",
                              static_cast<unsigned long long>(ea), static_cast<unsigned long long>(fault));
            return EXCEPTION_CONTINUE_SEARCH;
        }

        ctx->Rip += insn.length;
        ++g_recoveries;
        if (verbose) Logf("  action: CASE B - read-only section; skipped the %u-byte store at RIP (write dropped)", insn.length);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ---------------------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------------------
void LoadConfig(const wchar_t* ini)
{
    g_cfg.enabled       = GetPrivateProfileIntW(L"General", L"Enabled", 1, ini) != 0;
    g_cfg.selfTest      = GetPrivateProfileIntW(L"General", L"SelfTest", 0, ini) != 0;
    g_cfg.maxRecoveries = static_cast<unsigned>(GetPrivateProfileIntW(L"General", L"MaxRecoveries", 0, ini));

    wchar_t mode[32];
    GetPrivateProfileStringW(L"General", L"ReadOnlyWriteMode", L"skip", mode, 32, ini);
    for (wchar_t* c = mode; *c; ++c) *c = static_cast<wchar_t>(std::towlower(*c));
    g_cfg.roMode = !std::wcscmp(mode, L"crash")     ? WriteMode::Crash
                 : !std::wcscmp(mode, L"unprotect") ? WriteMode::Unprotect
                                                    : WriteMode::Skip;

    wchar_t list[512];
    GetPrivateProfileStringW(L"General", L"TargetModules", L"renodx-dlss", list, 512, ini);
    g_cfg.targetCount = 0;
    wchar_t* p = list;
    while (*p && g_cfg.targetCount < 8) {
        while (*p == L' ' || *p == L';' || *p == L',' || *p == L'\t') ++p;
        wchar_t* start = p;
        while (*p && *p != L';' && *p != L',') ++p;
        wchar_t* end = p;
        while (end > start && (end[-1] == L' ' || end[-1] == L'\t')) --end;
        size_t len = static_cast<size_t>(end - start);
        if (len == 0) continue;
        if (len > 63) len = 63;
        wchar_t* dst = g_cfg.targets[g_cfg.targetCount];
        for (size_t i = 0; i < len; ++i) dst[i] = static_cast<wchar_t>(std::towlower(start[i]));
        dst[len] = 0;
        ++g_cfg.targetCount;
    }
}

void Install(HMODULE self)
{
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) return;
    g_self = self;
    InitializeCriticalSection(&g_logLock);

    wchar_t dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(self, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    wchar_t* slash = std::wcsrchr(dir, L'\\');
    if (slash) slash[1] = 0;

    wchar_t ini[MAX_PATH], log[MAX_PATH];
    lstrcpynW(ini, dir, MAX_PATH);
    lstrcatW(ini, L"RenoDXDLSSGuard.ini");
    lstrcpynW(log, dir, MAX_PATH);
    lstrcatW(log, L"RenoDXDLSSGuard.log");

    LoadConfig(ini);
    g_log = CreateFileW(log, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    char targets[600] = {};
    for (int i = 0; i < g_cfg.targetCount; ++i) {
        char t[80];
        ToNarrow(g_cfg.targets[i], t, sizeof(t));
        std::snprintf(targets + std::strlen(targets), sizeof(targets) - std::strlen(targets), "%s%s", i ? ", " : "", t);
    }
    Logf("RenoDX DLSS Guard " GUARD_VERSION " loaded. enabled=%d ReadOnlyWriteMode=%s MaxRecoveries=%u targets=[%s]",
         g_cfg.enabled, g_cfg.roMode == WriteMode::Skip ? "skip" : g_cfg.roMode == WriteMode::Unprotect ? "unprotect" : "crash",
         g_cfg.maxRecoveries, targets);

    if (g_cfg.enabled) {
        g_veh = AddVectoredExceptionHandler(1 /* call first */, &Handler);
        Logf("%s", g_veh ? "Exception handler installed." : "FAILED to install exception handler.");
    }
}

// ---------------------------------------------------------------------------------------
// Optional self-test (ini: SelfTest=1). Proves the guard works on this machine in seconds,
// without having to reproduce the real crash. Runs from SKSEPlugin_Load, never under loader lock.
// ---------------------------------------------------------------------------------------
alignas(4096) const unsigned char g_selfRo[8192] = { 0x11 };   // lands in .rdata, page-exclusive
alignas(4096) unsigned char       g_selfRw[8192] = { 0x22 };   // lands in .data,  page-exclusive

void RunSelfTest()
{
    if (!g_cfg.enabled || !g_veh) { Logf("SelfTest skipped (guard not active)."); return; }
    g_selfTestActive.store(true);
    Logf("SelfTest: begin");

    {   // Case A: flip a page of our own .data to read-only, then write to it.
        DWORD old = 0;
        VirtualProtect(g_selfRw, 0x1000, PAGE_READONLY, &old);
        volatile unsigned char* w = g_selfRw;
        *w = 0x5A;
        const bool pass = *w == 0x5A;
        Logf("SelfTest A (read-only page inside a writable section -> restore + retry): %s", pass ? "PASS" : "FAIL");
    }

    if (g_cfg.roMode == WriteMode::Crash) {
        Logf("SelfTest B skipped (ReadOnlyWriteMode=crash would terminate the game).");
    } else {   // Case B: write into our own .rdata.
        volatile unsigned char* r = const_cast<volatile unsigned char*>(g_selfRo);
        *r = 0x5A;
        const unsigned char now = *r;
        const bool pass = (g_cfg.roMode == WriteMode::Skip) ? (now == 0x11) : (now == 0x5A);
        Logf("SelfTest B (write to read-only section, mode=%s): %s",
             g_cfg.roMode == WriteMode::Skip ? "skip" : "unprotect", pass ? "PASS" : "FAIL");
    }

    g_selfTestActive.store(false);
    Logf("SelfTest: end");
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Exports / entry points
// ---------------------------------------------------------------------------------------
extern "C" __declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface*)
{
    Install(g_self);
    if (g_cfg.selfTest) RunSelfTest();
    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        g_self = module;
        Install(module);                       // installed here too, so it works even if SKSE's version check rejects us
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_veh) RemoveVectoredExceptionHandler(g_veh);   // never leave a handler pointing at unloaded code
        g_veh = nullptr;
        if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
    }
    return TRUE;
}
