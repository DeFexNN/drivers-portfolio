// mapper.cpp  –  MidnightSoftware Manual Mapper
// ──────────────────────────────────────────────────────────────
// Maps an x64 DLL into a running process without calling LoadLibrary.
// ALL memory read/write goes through MidnightSoftware driver (\\.\DXGKrnl).
// No WriteProcessMemory / ReadProcessMemory is used anywhere.
//
// Usage:  mapper.exe  <ProcessName.exe>  <path\to\dll.dll>  [--threads=start|end|mid|shuffle]
//
// Mapping steps:
//   1. Read the DLL from disk into a local buffer
//   2. Parse PE headers (DOS, NT, sections, directories)
//   3. Find target PID via MidnightSoftware driver ENUM_PROCS
//   4. OpenProcess with VM_OPERATION rights (for VirtualAllocEx only)
//   5. Allocate RWX memory in target at the preferred base (or anywhere)
//   6. Fix base relocations (IMAGE_REL_BASED_DIR64 / HIGHLOW)
//   7. Resolve import table (shared system DLL bases per-boot)
//   8. Write the fixed-up image via MidnightSoftware driver WRITE_MEM ONLY
//   9. Build x64 shellcode: full context save → TLS/DllMain → done-flag → jmp origRip
//  10. VirtualAllocEx shellcode page; write via MidnightSoftware driver WRITE_MEM ONLY
//  11. Thread Hijacking: snapshot threads, SuspendThread, NtGetContextThread,
//      redirect RIP to shellcode (NtSetContextThread), ResumeThread
//  12. Poll done-flag via MidnightSoftware driver READ_MEM; keep shellcode+flag pages alive
// ──────────────────────────────────────────────────────────────

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>     // UNICODE_STRING, OBJECT_ATTRIBUTES, etc.
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <unordered_map>

#include "../MidnightSoftwareCommon.h"

#pragma comment(lib, "ntdll.lib")

// ─────────────────────────────────────────────────────────────
// NTSTATUS helper (used by DrvQueueApc return value)
// ─────────────────────────────────────────────────────────────
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// ─────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────
static void Log(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("[+] %s\n", buf);
    fflush(stdout);
}

static void Err(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[!] %s\n", buf);
    fflush(stderr);
}

// ─────────────────────────────────────────────────────────────
// MidnightSoftware driver comms (file-scope, initialised in main)
// ─────────────────────────────────────────────────────────────
static HANDLE g_hDev  = INVALID_HANDLE_VALUE;

static bool DrvOpen()
{
    g_hDev = CreateFileW(MS_DEVICE_DXG,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
    return g_hDev != INVALID_HANDLE_VALUE;
}

static bool DrvIoctl(DWORD code,
                     const void* in, DWORD inSz,
                     void* out, DWORD outSz,
                     DWORD* got = nullptr)
{
    DWORD g = 0;
    return DeviceIoControl(g_hDev, code,
                           const_cast<void*>(in), inSz,
                           out, outSz,
                           got ? got : &g, nullptr) != FALSE;
}

static bool DrvWriteMem(uint64_t pid, uint64_t addr, const void* src, size_t size)
{
    // All memory access goes through the driver (Ring-0 CR3 walk).
    // No WriteProcessMemory fallback – that requires a user-mode
    // PROCESS_VM_WRITE handle that anti-cheats strip via ObRegisterCallbacks.
    if (g_hDev == INVALID_HANDLE_VALUE || !addr || !size) return false;
    std::vector<uint8_t> buf(sizeof(WRITE_MEMORY_REQUEST) + size);
    auto* req = reinterpret_cast<WRITE_MEMORY_REQUEST*>(buf.data());
    req->ProcessId = (ULONG_PTR)pid;
    req->Address   = (ULONG_PTR)addr;
    req->Size      = size;
    memcpy(buf.data() + sizeof(WRITE_MEMORY_REQUEST), src, size);
    DWORD got = 0;
    return DrvIoctl(MS_MAGIC_WRITE_MEM,
                    buf.data(), (DWORD)buf.size(),
                    nullptr, 0, &got);
}

static bool DrvReadMem(uint64_t pid, uint64_t addr, void* dst, size_t size)
{
    // All memory access goes through the driver (Ring-0 CR3 walk).
    // No ReadProcessMemory fallback – that requires a user-mode
    // PROCESS_VM_READ handle that anti-cheats strip via ObRegisterCallbacks.
    if (g_hDev == INVALID_HANDLE_VALUE || !addr || !size) return false;
    READ_MEMORY_REQUEST req{};
    req.ProcessId = (ULONG_PTR)pid;
    req.Address   = (ULONG_PTR)addr;
    req.Size      = size;
    DWORD got = 0;
    return DrvIoctl(MS_MAGIC_READ_MEM,
                    &req, (DWORD)sizeof(req),
                    dst, (DWORD)size, &got)
           && got == (DWORD)size;
}

// Enumerate processes and find the PID for the given image name.
static uint64_t DrvFindPid(const char* imageName)
{
    std::vector<uint8_t> buf(MS_MAX_PROCESSES * sizeof(PROCESS_ENTRY));
    DWORD got = 0;
    if (!DrvIoctl(MS_MAGIC_ENUM_PROCS, nullptr, 0, buf.data(), (DWORD)buf.size(), &got))
    {
        Err("ENUM_PROCS IOCTL failed (err=%lu)", GetLastError());
        return 0;
    }
    int n = (int)got / (int)sizeof(PROCESS_ENTRY);
    const auto* entries = reinterpret_cast<const PROCESS_ENTRY*>(buf.data());
    for (int i = 0; i < n; ++i)
    {
        if (entries[i].ProcessId && _stricmp(entries[i].ImageName, imageName) == 0)
            return (uint64_t)entries[i].ProcessId;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────
// FindStompTarget / TailIsPadding / FindCodeCave  — REMOVED
//
// Rationale (Requirement 3 / EAC/Vanguard memory-integrity checks):
//
//   Anti-cheats periodically hash the physical pages backing every
//   MEM_IMAGE region and compare against the on-disk file signature.
//   Writing to the padding tail of wldap32.dll or hiding shellcode in
//   any DLL code cave will trigger a hash mismatch on the first
//   integrity pass → instant ban.  There is no safe way to use
//   MEM_IMAGE regions for payload storage without a hypervisor EPT hook.
//
//   Module stomping also requires a user-mode process handle
//   (PROCESS_VM_OPERATION) for VirtualProtectEx, which is stripped by
//   ObRegisterCallbacks before it can be granted.
//
//   All memory is now allocated through DrvAllocMem (Ring-0 kernel
//   handle + ZwAllocateVirtualMemory), which creates normal MEM_PRIVATE
//   pages invisible to MEM_IMAGE integrity scanners.
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// ResolveApiSetName
//
// Maps a virtual API set name (api-ms-win-*, ext-ms-win-*) to the
// physical DLL that backs it at runtime.  This is a hardcoded
// approximation of the OS ApiSetMap stored in PEB->ApiSetMap,
// covering the CRT, core Win32, security, and event tracing sets.
//
// Returns the host DLL name (lower-case), or nullptr if not an API set.
// ─────────────────────────────────────────────────────────────
static const char* ResolveApiSetName(const char* name)
{
    // prefix helper (case-insensitive)
    auto sw = [&](const char* prefix) -> bool {
        return _strnicmp(name, prefix, strlen(prefix)) == 0;
    };
    if (sw("api-ms-win-crt-"))                  return "ucrtbase.dll";
    if (sw("api-ms-win-core-file-"))             return "kernelbase.dll";
    if (sw("api-ms-win-core-handle-"))           return "kernelbase.dll";
    if (sw("api-ms-win-core-heap-"))             return "kernelbase.dll";
    if (sw("api-ms-win-core-interlocked-"))      return "kernelbase.dll";
    if (sw("api-ms-win-core-libraryloader-"))    return "kernelbase.dll";
    if (sw("api-ms-win-core-localization-"))     return "kernelbase.dll";
    if (sw("api-ms-win-core-memory-"))           return "kernelbase.dll";
    if (sw("api-ms-win-core-namedpipe-"))        return "kernelbase.dll";
    if (sw("api-ms-win-core-processenvironment-")) return "kernelbase.dll";
    if (sw("api-ms-win-core-processthreads-"))   return "kernelbase.dll";
    if (sw("api-ms-win-core-profile-"))          return "kernelbase.dll";
    if (sw("api-ms-win-core-rtlsupport-"))       return "ntdll.dll";
    if (sw("api-ms-win-core-string-"))           return "kernelbase.dll";
    if (sw("api-ms-win-core-synch-"))            return "kernelbase.dll";
    if (sw("api-ms-win-core-sysinfo-"))          return "kernelbase.dll";
    if (sw("api-ms-win-core-util-"))             return "kernelbase.dll";
    if (sw("api-ms-win-core-"))                  return "kernelbase.dll";
    if (sw("api-ms-win-security-"))              return "advapi32.dll";
    if (sw("api-ms-win-service-"))               return "advapi32.dll";
    if (sw("api-ms-win-eventing-"))              return "ntdll.dll";
    if (sw("api-ms-win-"))                       return "kernelbase.dll"; // catch-all
    if (sw("ext-ms-win-"))                       return "kernelbase.dll";
    return nullptr;
}

// ─────────────────────────────────────────────────────────────
// ReadRemoteString
//
// Reads a null-terminated ASCII string from a remote process via
// DrvReadMem, never issuing a read that crosses a 4 KB page boundary.
//
// Why this matters:
//   Export name tables in system DLLs pack short strings end-to-end.
//   A 4-byte name like "Beep" may sit at offset 0xFFD in a page, so
//   any read of more than 3 bytes would cross into the next page,
//   which may be unmapped padding.  The kernel returns STATUS_PARTIAL_COPY
//   for the entire transfer, causing DrvReadMem to fail and the entry
//   to be silently skipped.
//
//   We clamp every chunk to the remainder of the current page so that
//   each DrvReadMem call is guaranteed to stay within a single mapped page.
// ─────────────────────────────────────────────────────────────
static std::string ReadRemoteString(uint64_t pid, uint64_t addr, size_t maxLen = 512)
{
    std::string res;
    res.reserve(64);
    char buf[32];

    while (res.size() < maxLen)
    {
        // Bytes remaining in the current 4 KB page
        size_t offsetInPage  = addr & 0xFFF;
        size_t bytesToPageEnd = 4096 - offsetInPage;

        // Read at most 32 bytes, but never cross the page boundary
        size_t toRead = std::min<size_t>(sizeof(buf), bytesToPageEnd);

        if (!DrvReadMem(pid, addr, buf, toRead))
            break;

        for (size_t i = 0; i < toRead; ++i)
        {
            if (buf[i] == '\0') return res;
            res += buf[i];
        }
        addr += toRead;
    }
    return res;
}

// ─────────────────────────────────────────────────────────────
// GetRemoteProcAddress
//
// Resolves a function export from a module already loaded into the
// target process by reading its EAT (Export Address Table) remotely
// via DrvReadMem.  Never touches the local process's module list.
//
// Why this matters:
//   ASLR in Windows applies a slide ONCE per boot for each module
//   (kernel entropy).  System DLLs (ntdll, kernel32, …) happen to
//   load at the same VA in all processes during the same boot session.
//   BUT third-party DLLs, engine DLLs, and any module with per-process
//   ASLR will load at a completely different VA.  Using local
//   GetProcAddress for those gives a bogus pointer → instant crash.
//   This implementation reads the correct remote VA directly.
//
// funcName : import-by-name string, or nullptr for ordinal import.
// funcOrd  : import-by-ordinal value (used when funcName == nullptr).
// Returns  : absolute VA in the target process, or 0 on failure.
// ─────────────────────────────────────────────────────────────
static uint64_t GetRemoteProcAddress(
    uint64_t    pid,
    uint64_t    remoteModBase,
    const char* funcName,
    uint16_t    funcOrd,
    const std::unordered_map<std::string,uint64_t>* pModules = nullptr,
    int         depth = 0)
{
    // ── Read DOS header ───────────────────────────────────────
    IMAGE_DOS_HEADER dos{};
    if (!DrvReadMem(pid, remoteModBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    // ── Read NT headers ───────────────────────────────────────
    IMAGE_NT_HEADERS64 nt{};
    if (!DrvReadMem(pid, remoteModBase + (uint64_t)dos.e_lfanew, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    // ── Locate export directory ───────────────────────────────
    IMAGE_DATA_DIRECTORY& expEntry =
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expEntry.VirtualAddress || !expEntry.Size) return 0;

    IMAGE_EXPORT_DIRECTORY expDir{};
    if (!DrvReadMem(pid, remoteModBase + expEntry.VirtualAddress, &expDir, sizeof(expDir)))
        return 0;

    // ── Resolve by name ───────────────────────────────────────
    if (funcName)
    {
        uint32_t nNames = expDir.NumberOfNames;
        if (!nNames) return 0;

        // Read name-pointer RVA array and parallel ordinal array
        std::vector<uint32_t> nameRVAs(nNames);
        std::vector<uint16_t> nameOrds(nNames);

        if (!DrvReadMem(pid, remoteModBase + expDir.AddressOfNames,
                        nameRVAs.data(), nNames * sizeof(uint32_t))) return 0;
        if (!DrvReadMem(pid, remoteModBase + expDir.AddressOfNameOrdinals,
                        nameOrds.data(), nNames * sizeof(uint16_t))) return 0;

        for (uint32_t i = 0; i < nNames; ++i)
        {
            // Page-safe string read: never crosses a 4 KB boundary
            std::string remoteName = ReadRemoteString(pid, remoteModBase + nameRVAs[i]);
            if (remoteName.empty() || remoteName != funcName)
                continue;

            // Fetch the function RVA from the functions table
            uint32_t funcRVA = 0;
            uint64_t rvaSlotVA = remoteModBase + expDir.AddressOfFunctions
                               + (uint64_t)nameOrds[i] * sizeof(uint32_t);
            if (!DrvReadMem(pid, rvaSlotVA, &funcRVA, sizeof(funcRVA))) return 0;

            // Forwarded export: the RVA references an ASCII string
            // "TargetDLL.FunctionName" or "TargetDLL.#Ordinal" inside the
            // export directory.  Follow the chain recursively.
            if (funcRVA >= expEntry.VirtualAddress &&
                funcRVA <  expEntry.VirtualAddress + expEntry.Size)
            {
                if (!pModules || depth >= 8)
                {
                    Err("GetRemoteProcAddress: fwd '%s' – no module map or depth limit", funcName);
                    return 0;
                }
                char fwdStr[256] = {};
                if (!DrvReadMem(pid, remoteModBase + funcRVA, fwdStr, sizeof(fwdStr) - 1)) return 0;
                char* dot = strchr(fwdStr, '.');
                if (!dot) return 0;
                *dot = '\0';
                std::string fwdDll(fwdStr); fwdDll += ".dll";
                for (char& c : fwdDll) c = (char)tolower((unsigned char)c);
                char* fwdFunc = dot + 1;
                auto fwdIt = pModules->find(fwdDll);
                if (fwdIt == pModules->end())
                {
                    // The forwarded DLL name may itself be a virtual API set
                    // (e.g. KERNEL32!SleepConditionVariableSRW forwards to
                    // api-ms-win-core-synch-l1-2-0.dll which is not loaded
                    // as a real module).  Resolve it to its physical host DLL.
                    const char* host = ResolveApiSetName(fwdDll.c_str());
                    if (host)
                    {
                        fwdIt = pModules->find(host);
                    }
                    if (fwdIt == pModules->end())
                    {
                        Err("GetRemoteProcAddress: fwd target '%s' not in process", fwdDll.c_str());
                        return 0;
                    }
                }
                if (fwdFunc[0] == '#')
                    return GetRemoteProcAddress(pid, fwdIt->second, nullptr,
                               (uint16_t)atoi(fwdFunc + 1), pModules, depth + 1);
                return GetRemoteProcAddress(pid, fwdIt->second, fwdFunc, 0, pModules, depth + 1);
            }
            return remoteModBase + funcRVA;
        }
        return 0;  // not found
    }

    // ── Resolve by ordinal ────────────────────────────────────
    {
        if (funcOrd < (uint16_t)expDir.Base ||
            (uint32_t)(funcOrd - (uint16_t)expDir.Base) >= expDir.NumberOfFunctions)
            return 0;

        uint16_t idx    = funcOrd - (uint16_t)expDir.Base;
        uint32_t funcRVA = 0;
        uint64_t rvaSlotVA = remoteModBase + expDir.AddressOfFunctions
                           + (uint64_t)idx * sizeof(uint32_t);
        if (!DrvReadMem(pid, rvaSlotVA, &funcRVA, sizeof(funcRVA))) return 0;

        if (funcRVA >= expEntry.VirtualAddress &&
            funcRVA <  expEntry.VirtualAddress + expEntry.Size)
        {
            if (!pModules || depth >= 8)
            {
                Err("GetRemoteProcAddress: fwd ordinal – no module map or depth limit");
                return 0;
            }
            char fwdStr[256] = {};
            if (!DrvReadMem(pid, remoteModBase + funcRVA, fwdStr, sizeof(fwdStr) - 1)) return 0;
            char* dot = strchr(fwdStr, '.');
            if (!dot) return 0;
            *dot = '\0';
            std::string fwdDll(fwdStr); fwdDll += ".dll";
            for (char& c : fwdDll) c = (char)tolower((unsigned char)c);
            char* fwdFunc = dot + 1;
            auto fwdIt = pModules->find(fwdDll);
            if (fwdIt == pModules->end())
            {
                const char* host = ResolveApiSetName(fwdDll.c_str());
                if (host)
                {
                    fwdIt = pModules->find(host);
                }
                if (fwdIt == pModules->end())
                {
                    Err("GetRemoteProcAddress: fwd ordinal target '%s' not in process", fwdDll.c_str());
                    return 0;
                }
            }
            if (fwdFunc[0] == '#')
                return GetRemoteProcAddress(pid, fwdIt->second, nullptr,
                           (uint16_t)atoi(fwdFunc + 1), pModules, depth + 1);
            return GetRemoteProcAddress(pid, fwdIt->second, fwdFunc, 0, pModules, depth + 1);
        }
        return remoteModBase + funcRVA;
    }
}

// ─────────────────────────────────────────────────────────────
// DrvQueueApc
//
// Asks the driver to queue a user-mode APC to thread `tid` in
// the target process.  The driver uses PsLookupThreadByThreadId +
// KeInitializeApc + KeInsertQueueApc at ring-0, bypassing the
// ring-3 OpenThread / NtSetContextThread path that EAC/BattlEye
// block via ObRegisterCallbacks.
// ─────────────────────────────────────────────────────────────
static bool DrvQueueApc(uint64_t pid, DWORD tid, uint64_t shellcodeVA)
{
    QUEUE_APC_REQUEST req{};
    req.ProcessId   = (ULONG_PTR)pid;
    req.ThreadId    = (ULONG_PTR)tid;
    req.ShellcodeVA = (ULONG_PTR)shellcodeVA;
    return DrvIoctl(MS_MAGIC_QUEUE_APC,
                    &req, (DWORD)sizeof(req),
                    nullptr, 0);
}

// ─────────────────────────────────────────────────────────────
// DrvAllocMem
//
// Allocates virtual memory in the target process via a Ring-0
// kernel handle. Never issues OpenProcess – the driver opens the
// PEPROCESS with OBJ_KERNEL_HANDLE + KernelMode so that
// ObRegisterCallbacks AC stripping is completely bypassed.
// ─────────────────────────────────────────────────────────────
static uint64_t DrvAllocMem(uint64_t pid,
                             uint64_t preferredBase,
                             size_t   size,
                             ULONG    protect)
{
    ALLOC_MEMORY_REQUEST req{};
    req.ProcessId    = (ULONG_PTR)pid;
    req.PreferredBase = (ULONG_PTR)preferredBase;
    req.Size          = size;
    req.AllocType     = MEM_COMMIT | MEM_RESERVE;
    req.Protect       = protect;

    ALLOC_MEMORY_RESPONSE resp{};
    DWORD got = 0;
    if (!DrvIoctl(MS_MAGIC_ALLOC_MEM,
                  &req, (DWORD)sizeof(req),
                  &resp, (DWORD)sizeof(resp), &got))
        return 0;
    if (got < (DWORD)sizeof(ALLOC_MEMORY_RESPONSE))
        return 0;
    return (uint64_t)resp.AllocatedBase;
}

// ─────────────────────────────────────────────────────────────
// DrvFreeMem
//
// Releases virtual memory in the target process via Ring-0.
// Paired with DrvAllocMem.
// ─────────────────────────────────────────────────────────────
static bool DrvFreeMem(uint64_t pid, uint64_t addr)
{
    FREE_MEMORY_REQUEST req{};
    req.ProcessId = (ULONG_PTR)pid;
    req.Address   = (ULONG_PTR)addr;
    req.Size      = 0;              // 0 = release entire region
    req.FreeType  = MEM_RELEASE;
    return DrvIoctl(MS_MAGIC_FREE_MEM,
                    &req, (DWORD)sizeof(req),
                    nullptr, 0);
}

// ─────────────────────────────────────────────────────────────
// DrvProtectMem
//
// Changes the page protection of a VA range inside the target
// process via the driver's Ring-0 kernel handle.  Replaces the
// PAGE_EXECUTE_READWRITE single-protection model with per-section
// protections that match what a normal Windows loader would set:
//
//   .text / code  ->  PAGE_EXECUTE_READ
//   .rdata        ->  PAGE_READONLY
//   .data / .bss  ->  PAGE_READWRITE
//
// This eliminates the RWX "red flag" that EAC, Vanguard, and other
// ACs detect by walking the VAD tree looking for MEM_PRIVATE regions
// with simultaneous Write and Execute permissions.
// ─────────────────────────────────────────────────────────────
static bool DrvProtectMem(uint64_t pid,
                           uint64_t addr,
                           size_t   size,
                           ULONG    newProtect)
{
    if (g_hDev == INVALID_HANDLE_VALUE || !addr || !size) return false;
    PROTECT_MEMORY_REQUEST req{};
    req.ProcessId  = (ULONG_PTR)pid;
    req.Address    = (ULONG_PTR)addr;
    req.Size       = size;
    req.NewProtect = newProtect;
    return DrvIoctl(MS_MAGIC_PROTECT_MEM,
                    &req, (DWORD)sizeof(req),
                    nullptr, 0);
}

// ─────────────────────────────────────────────────────────────
// SectionCharsToProtect
//
// Converts IMAGE_SCN_MEM_* characteristic flags to the
// minimal PAGE_* protection that preserves the section's
// intended access rights without granting unnecessary permissions.
//
// Mapping (mirrors what ntdll LdrpMapViewOfSection uses):
//   E+R       ->  PAGE_EXECUTE_READ      (typical .text)
//   E+R+W     ->  PAGE_EXECUTE_READWRITE (rare; JIT stubs)
//   R only    ->  PAGE_READONLY          (.rdata, resources)
//   R+W       ->  PAGE_READWRITE         (.data, .bss)
//   (none)    ->  PAGE_NOACCESS
// ─────────────────────────────────────────────────────────────
static ULONG SectionCharsToProtect(DWORD chars)
{
    bool exec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool write = (chars & IMAGE_SCN_MEM_WRITE)   != 0;
    bool read  = (chars & IMAGE_SCN_MEM_READ)    != 0;
    if (exec  && write) return PAGE_EXECUTE_READWRITE;
    if (exec  && read)  return PAGE_EXECUTE_READ;
    if (exec)           return PAGE_EXECUTE_READ;  // no read flag but still code
    if (write && read)  return PAGE_READWRITE;
    if (read)           return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// ─────────────────────────────────────────────────────────────
// DrvEnumMods
//
// Enumerates modules loaded in the target process by walking the
// PEB Ldr list at Ring-0 via the physical CR3 walk.  No process
// handle required – replaces CreateToolhelp32Snapshot(SNAPMODULE).
// ─────────────────────────────────────────────────────────────
static bool DrvEnumMods(uint64_t pid,
                        std::unordered_map<std::string, uint64_t>& outModules)
{
    std::vector<uint8_t> buf(MS_MAX_MODULES * sizeof(MODULE_ENTRY));
    ENUM_MODS_REQUEST req{};
    req.ProcessId = (ULONG_PTR)pid;
    DWORD got = 0;
    if (!DrvIoctl(MS_MAGIC_ENUM_MODS,
                  &req, (DWORD)sizeof(req),
                  buf.data(), (DWORD)buf.size(), &got))
        return false;
    int n = (int)got / (int)sizeof(MODULE_ENTRY);
    const auto* entries = reinterpret_cast<const MODULE_ENTRY*>(buf.data());
    outModules.clear();
    for (int i = 0; i < n; ++i)
    {
        if (!entries[i].BaseAddress) continue;
        std::string name(entries[i].ModuleName);
        for (char& c : name) c = (char)tolower((unsigned char)c);
        outModules[name] = (uint64_t)entries[i].BaseAddress;
    }
    return !outModules.empty();
}

// ─────────────────────────────────────────────────────────────
// PEB Linking
//
// Inserts a fake LDR_DATA_TABLE_ENTRY into the target process's
// PEB->Ldr three doubly-linked lists so that Windows considers
// the manually mapped DLL a legitimate loaded module.
//
// Why this is necessary:
//   When any thread is created in the process, the kernel's
//   LdrpAllocateTls walks InLoadOrderModuleList and allocates a
//   TLS slot block for every entry that has a TLS directory.
//   Our module is absent → no TLS block is created for new threads
//   → std::thread / CRT state (errno, exception buffers, etc.) write
//   through a NULL pointer → heap corruption → random crash
//   (most often inside X3DAudio which hammers the heap hardest).
//
// After linking, all future threads will receive a valid TLS block
// for our DLL and the heap stays intact.
// ─────────────────────────────────────────────────────────────

// x64 layout of the LDR_DATA_TABLE_ENTRY fields we need.
// Mirrored as a flat struct of native types to avoid header conflicts
// (winternl.h exposes only a redacted version of this structure).
//
// Fields through +0xA8 are required on Windows 10 1809+ / Windows 11.
// In particular, DdagNode (+0x98) MUST point to a valid REMOTE_LDR_DDAG_NODE
// because LdrpCallInitRoutines dereferences entry->DdagNode->State BEFORE
// checking LDRP_DONT_CALL_FOR_THREADS.  A NULL DdagNode crashes the process
// at address 0x38 (NULL + offsetof(LDR_DDAG_NODE, State)) on every new thread.
#pragma pack(push, 1)
struct REMOTE_LDR_ENTRY
{
    // ── Linked-list pointers (three lists, 16 bytes each) ────
    uint64_t InLoadOrder_Flink;     // +0x00  InLoadOrderLinks.Flink
    uint64_t InLoadOrder_Blink;     // +0x08  InLoadOrderLinks.Blink
    uint64_t InMemoryOrder_Flink;   // +0x10  InMemoryOrderLinks.Flink
    uint64_t InMemoryOrder_Blink;   // +0x18  InMemoryOrderLinks.Blink
    uint64_t InInitOrder_Flink;     // +0x20  InInitializationOrderLinks.Flink
    uint64_t InInitOrder_Blink;     // +0x28  InInitializationOrderLinks.Blink
    // ── Module info ──────────────────────────────────────────
    uint64_t DllBase;               // +0x30
    uint64_t EntryPoint;            // +0x38
    uint32_t SizeOfImage;           // +0x40
    // ── UNICODE_STRING FullDllName  (x64: 16 bytes) ──────────
    // NOTE: no padding between SizeOfImage and FullDllName — this is how the
    // real LDR_DATA_TABLE_ENTRY is laid out.  The 4-byte gap inside
    // UNICODE_STRING (between MaximumLength and Buffer) is the INTERNAL
    // pointer-align pad; there is NO outer pad before the struct starts.
    uint16_t FullDllName_Length;    // +0x44  bytes, NOT including NUL
    uint16_t FullDllName_MaxLen;    // +0x46  bytes, including NUL
    uint32_t FullDllName_pad;       // +0x48  UNICODE_STRING internal pointer-align pad
    uint64_t FullDllName_Buffer;    // +0x4C  remote VA of wchar_t[]
    // ── UNICODE_STRING BaseDllName  (x64: 16 bytes) ──────────
    uint16_t BaseDllName_Length;    // +0x54
    uint16_t BaseDllName_MaxLen;    // +0x56
    uint32_t BaseDllName_pad;       // +0x58  UNICODE_STRING internal pointer-align pad
    uint64_t BaseDllName_Buffer;    // +0x5C  remote VA of wchar_t[]
    // ── Loader flags ─────────────────────────────────────────
    uint32_t Flags;                 // +0x64  (union FlagGroup[4] / Flags in real struct)
    uint16_t LoadCount;             // +0x68  (ObsoleteLoadCount on Win8+)
    uint16_t TlsIndex;              // +0x6A
    // ── Extended fields (Windows 10 1809+ / Windows 11) ─────
    uint64_t HashLinks_Flink;       // +0x6C  HashLinks.Flink
    uint64_t HashLinks_Blink;       // +0x74  HashLinks.Blink
    uint32_t TimeDateStamp;         // +0x7C
    // NOTE: no padding here – 0x7C+4 = 0x80 is already 8-byte aligned
    uint64_t EntryPointActivCtx;    // +0x80  EntryPointActivationContext (NULL)
    uint64_t Lock;                  // +0x88  (NULL)
    uint64_t DdagNode;              // +0x90  -> REMOTE_LDR_DDAG_NODE  *** must not be NULL ***
    uint64_t NodeModuleLink_Flink;  // +0x98  NodeModuleLink.Flink (linked to DdagNode->Modules)
    uint64_t NodeModuleLink_Blink;  // +0xA0  NodeModuleLink.Blink
    uint64_t _trailing_A8;          // +0xA8  (BaseNameHashValue+LoadReason in real struct; zeroed)
};  // total: 0xB0 bytes
#pragma pack(pop)
static_assert(sizeof(REMOTE_LDR_ENTRY) == 0xB0,
    "REMOTE_LDR_ENTRY size mismatch – check x64 LDR layout");

// ─────────────────────────────────────────────────────────────
// Minimal LDR_DDAG_NODE required by LdrpCallInitRoutines.
//
// Windows' ntdll checks DdagNode->State BEFORE checking any loader flags
// on every new thread.  State must equal LdrModulesReadyToRun (9) so
// that the function proceeds to deliver DLL_THREAD_ATTACH via
// LdrpCallInitRoutines (needed by /MT static-CRT DLLs).
//
// The Modules LIST_ENTRY forms a circular list with the one entry
// (NodeModuleLink inside REMOTE_LDR_ENTRY at +0x98).
// ─────────────────────────────────────────────────────────────
#pragma pack(push, 1)
struct REMOTE_LDR_DDAG_NODE
{
    uint64_t Modules_Flink;               // +0x00  -> &LDR_ENTRY.NodeModuleLink_Flink
    uint64_t Modules_Blink;               // +0x08  -> &LDR_ENTRY.NodeModuleLink_Flink
    uint64_t ServiceTagList;              // +0x10  (NULL)
    uint32_t LoadCount;                   // +0x18
    uint32_t LoadWhileUnloadingCount;     // +0x1C
    uint32_t LowestLink;                  // +0x20
    uint32_t _pad1;                       // +0x24
    uint64_t Dependencies;               // +0x28  LDRP_CSLIST (NULL)
    uint64_t IncomingDependencies;       // +0x30  LDRP_CSLIST (NULL)
    uint32_t State;                       // +0x38  LdrModulesReadyToRun = 9
    uint32_t _pad2;                       // +0x3C
    uint64_t CondenseLink;               // +0x40  (NULL)
    uint32_t PreorderNumber;              // +0x48
    uint32_t _pad3;                       // +0x4C
};  // total: 0x50 bytes
#pragma pack(pop)
static_assert(sizeof(REMOTE_LDR_DDAG_NODE) == 0x50,
    "REMOTE_LDR_DDAG_NODE size mismatch");

// ─────────────────────────────────────────────────────────────
// HashBaseName
//
// Computes the ntdll LdrpHashTable bucket index for a module base name.
// Algorithm: h = ROR32(h, 1) + c  for each lowercase wchar_t   (mod 2^32)
// Result masked to 5 bits → 32 buckets.
// ─────────────────────────────────────────────────────────────
static uint32_t HashBaseName(const wchar_t* name)
{
    uint32_t h = 0;
    for (const wchar_t* p = name; *p; ++p)
    {
        wchar_t c = *p;
        if (c >= L'A' && c <= L'Z') c += 0x20;
        h = _rotr(h, 1) + (uint32_t)(uint16_t)c;
    }
    return h & 0x1F;
}

// ─────────────────────────────────────────────────────────────
// PebHashLinkModule
//
// Inserts the manually-mapped module's HashLinks (at ldrEntryAddr+0x70)
// into the correct LdrpHashTable bucket so that:
//   (a) Module-by-name lookups (LdrGetDllHandle) can find the DLL.
//   (b) EAC/Vanguard don't flag self-referential HashLinks as a
//       manual-map indicator.
//
// Strategy to locate LdrpHashTable:
//   1. Walk PEB InLoadOrder to find ntdll.dll's LDR entry (DllBase match).
//   2. Read its HashLinks.Blink; follow the chain until we reach an
//      address inside ntdll .data – that's the bucket head for ntdll.
//   3. tableBase = bucketHead − hash("ntdll.dll") × 16.
//   4. Validate all 32 bucket addresses fall inside ntdll .data.
//   5. Tail-insert our HashLinks into LdrpHashTable[hash(baseName)].
// ─────────────────────────────────────────────────────────────
static void PebHashLinkModule(
    uint64_t       pid,
    uint64_t       ldrEntryAddr,
    const wchar_t* baseName,
    const std::unordered_map<std::string, uint64_t>& targetModules)
{
    // ── Find ntdll base ───────────────────────────────────────
    auto ntIt = targetModules.find("ntdll.dll");
    if (ntIt == targetModules.end())
    {
        Log("PebHashLinkModule: ntdll not in module map – hash-link skipped");
        return;
    }
    uint64_t ntdllBase = ntIt->second;

    // ── Find ntdll .data VA + size ────────────────────────────
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!DrvReadMem(pid, ntdllBase, &dos, sizeof(dos)) ||
        !DrvReadMem(pid, ntdllBase + dos.e_lfanew, &nt, sizeof(nt)))
    {
        Log("PebHashLinkModule: cannot read ntdll PE headers – hash-link skipped");
        return;
    }
    uint64_t dataVA = 0, dataSize = 0;
    {
        uint64_t secBase = ntdllBase + (uint32_t)dos.e_lfanew
                         + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader)
                         + nt.FileHeader.SizeOfOptionalHeader;
        uint16_t nSec = nt.FileHeader.NumberOfSections;
        if (nSec > 64) nSec = 64;
        std::vector<IMAGE_SECTION_HEADER> secs(nSec);
        DrvReadMem(pid, secBase, secs.data(), nSec * sizeof(IMAGE_SECTION_HEADER));
        for (auto& s : secs)
        {
            if ((s.Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (s.Characteristics & IMAGE_SCN_MEM_READ)  &&
               !(s.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                s.Misc.VirtualSize > 0x1000)
            {
                dataVA   = ntdllBase + s.VirtualAddress;
                dataSize = s.Misc.VirtualSize;
                break;
            }
        }
    }
    if (!dataVA) { Log("PebHashLinkModule: ntdll .data not found – hash-link skipped"); return; }

    auto inData = [&](uint64_t v) -> bool {
        return v >= dataVA && v < dataVA + dataSize;
    };

    // ── Get PEB→Ldr ───────────────────────────────────────────
    uint64_t pebAddr = 0;
    {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
        if (hProc)
        {
            typedef LONG (NTAPI *pfnNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
            auto pNtQIP = reinterpret_cast<pfnNtQIP>(
                GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
            if (pNtQIP)
            {
                PROCESS_BASIC_INFORMATION pbi{};
                ULONG rLen = 0;
                if (((LONG(NTAPI*)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG))pNtQIP)
                    (hProc, ProcessBasicInformation, &pbi, (ULONG)sizeof(pbi), &rLen) >= 0)
                    pebAddr = (uint64_t)(uintptr_t)pbi.PebBaseAddress;
            }
            CloseHandle(hProc);
        }
    }
    if (!pebAddr) { Log("PebHashLinkModule: cannot get PEB – hash-link skipped"); return; }

    uint64_t ldrAddr = 0;
    DrvReadMem(pid, pebAddr + 0x18, &ldrAddr, sizeof(ldrAddr));
    if (!ldrAddr) { Log("PebHashLinkModule: PEB->Ldr is NULL – hash-link skipped"); return; }

    // ── Walk InLoadOrder to find ntdll.dll's LDR entry ────────
    uint64_t inLoadHead   = ldrAddr + 0x10;
    uint64_t ntdllLdrEntry = 0;
    {
        uint64_t cur = 0;
        DrvReadMem(pid, inLoadHead, &cur, 8);
        for (int g = 0; cur != inLoadHead && g < 512; ++g)
        {
            uint64_t dllBase = 0;
            DrvReadMem(pid, cur + 0x30, &dllBase, 8);
            if (dllBase == ntdllBase) { ntdllLdrEntry = cur; break; }
            uint64_t next = 0;
            DrvReadMem(pid, cur, &next, 8);
            if (!next || next == cur) break;
            cur = next;
        }
    }
    if (!ntdllLdrEntry)
    {
        Log("PebHashLinkModule: ntdll LDR entry not found in PEB – hash-link skipped");
        return;
    }

    // ── Follow ntdll's HashLinks.Blink until we reach ntdll .data ─
    uint64_t ntdllHlBlink = 0;
    DrvReadMem(pid, ntdllLdrEntry + 0x78, &ntdllHlBlink, 8);

    uint64_t bucketNtdll = 0;
    {
        // Try Blink direction (towards list head)
        uint64_t walker = ntdllHlBlink;
        for (int steps = 0; steps < 256 && !bucketNtdll; ++steps)
        {
            if (inData(walker)) { bucketNtdll = walker; break; }
            uint64_t prev = 0;
            if (!DrvReadMem(pid, walker + 8, &prev, 8) || !prev || prev == walker) break;
            walker = prev;
        }
        // Try Flink direction if Blink failed
        if (!bucketNtdll)
        {
            uint64_t ntdllHlFlink = 0;
            DrvReadMem(pid, ntdllLdrEntry + 0x70, &ntdllHlFlink, 8);
            walker = ntdllHlFlink;
            for (int steps = 0; steps < 256 && !bucketNtdll; ++steps)
            {
                if (inData(walker)) { bucketNtdll = walker; break; }
                uint64_t next = 0;
                if (!DrvReadMem(pid, walker, &next, 8) || !next || next == walker) break;
                walker = next;
            }
        }
    }
    if (!bucketNtdll)
    {
        Log("PebHashLinkModule: cannot find ntdll hash bucket in ntdll .data – hash-link skipped");
        return;
    }

    // ── Compute and validate LdrpHashTable base ────────────────
    uint32_t ntdllHash = HashBaseName(L"ntdll.dll");
    uint64_t tableBase = bucketNtdll - (uint64_t)ntdllHash * 16;
    if (!inData(tableBase) || !inData(tableBase + 31 * 16 + 15))
    {
        Log("PebHashLinkModule: LdrpHashTable range check failed (base=0x%llX ntdllBucket=0x%llX ntdllHash=%u) – hash-link skipped",
            (unsigned long long)tableBase,
            (unsigned long long)bucketNtdll, ntdllHash);
        return;
    }
    Log("LdrpHashTable         : 0x%llX  (ntdll+0x%llX)",
        (unsigned long long)tableBase,
        (unsigned long long)(tableBase - ntdllBase));

    // ── Tail-insert into our bucket ────────────────────────────
    uint32_t ourHash   = HashBaseName(baseName);
    uint64_t ourBucket = tableBase + (uint64_t)ourHash * 16;

    uint64_t bucketBlink = 0;
    DrvReadMem(pid, ourBucket + 8, &bucketBlink, 8);

    // HashLinks field inside our REMOTE_LDR_ENTRY sits at +0x6C
    const uint64_t newHl = ldrEntryAddr + 0x6C;

    DrvWriteMem(pid, newHl + 0, &ourBucket,    sizeof(ourBucket));   // Flink -> bucket head
    DrvWriteMem(pid, newHl + 8, &bucketBlink,  sizeof(bucketBlink)); // Blink -> old tail
    DrvWriteMem(pid, bucketBlink + 0, &newHl,  sizeof(newHl));       // old tail.Flink -> us
    DrvWriteMem(pid, ourBucket   + 8, &newHl,  sizeof(newHl));       // head.Blink -> us

    Log("LdrpHashTable link    : bucket[%u]=0x%llX  oldTail=0x%llX  -> new=0x%llX",
        ourHash,
        (unsigned long long)ourBucket,
        (unsigned long long)bucketBlink,
        (unsigned long long)newHl);
}

// ─────────────────────────────────────────────────────────────
// DrvGetPebAddress
//
// Returns the PEB virtual address in the target process.
// Uses NtQueryInformationProcess(ProcessBasicInformation) which
// only requires PROCESS_QUERY_INFORMATION – a right that anti-cheats
// generally do NOT strip via ObRegisterCallbacks because countless
// legitimate OS components need it.
// ─────────────────────────────────────────────────────────────
static uint64_t DrvGetPebAddress(uint64_t pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hProc)
    {
        Log("DrvGetPebAddress: OpenProcess(QUERY_INFO) failed (err=%lu)",
            GetLastError());
        return 0;
    }

    // Dynamically resolve to avoid linking against the import by address
    typedef NTSTATUS (NTAPI *pfnNtQIP)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto pNtQIP = reinterpret_cast<pfnNtQIP>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"),
                       "NtQueryInformationProcess"));
    if (!pNtQIP) { CloseHandle(hProc); return 0; }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG retLen = 0;
    NTSTATUS st = pNtQIP(hProc, ProcessBasicInformation,
                         &pbi, (ULONG)sizeof(pbi), &retLen);
    CloseHandle(hProc);

    if (!NT_SUCCESS(st))
    {
        Log("DrvGetPebAddress: NtQueryInformationProcess failed (0x%08X)",
            (unsigned)st);
        return 0;
    }
    return (uint64_t)(uintptr_t)pbi.PebBaseAddress;
}

// ─────────────────────────────────────────────────────────────
// PebLinkModule
//
// Allocates a REMOTE_LDR_ENTRY + Unicode name strings in the
// target process and inserts them at the *tail* of all three
// PEB Ldr doubly-linked lists.
//
// Must be called BEFORE the shellcode executes DllMain so that
// any threads spawned by DllMain already find the entry.
//
// imageBase    – remote VA where the DLL was mapped
// entryPoint   – remote VA of DllMain (0 if none)
// imageSize    – SizeOfImage from the PE optional header
// fullPath     – full wide path (e.g. L"C:\\path\\to\\dll.dll")
// baseName     – filename only  (e.g. L"dll.dll")
// ─────────────────────────────────────────────────────────────
// Returns the remote VA of the allocated REMOTE_LDR_ENTRY on success so the
// caller can later patch in the real TlsIndex once TlsAlloc() has run.
// Returns 0 on failure.
static uint64_t PebLinkModule(
    uint64_t       pid,
    uint64_t       imageBase,
    uint64_t       entryPoint,
    uint32_t       imageSize,
    const wchar_t* fullPath,
    const wchar_t* baseName)
{
    // ── 1. Find PEB ───────────────────────────────────────────
    uint64_t pebAddr = DrvGetPebAddress(pid);
    if (!pebAddr)
    {
        Log("PebLinkModule: cannot obtain PEB address – skipping");
        return 0;
    }
    Log("PEB address         : 0x%llX", (unsigned long long)pebAddr);

    // ── 2. Read PEB->Ldr (pointer at PEB+0x18 on x64) ────────
    uint64_t ldrAddr = 0;
    if (!DrvReadMem(pid, pebAddr + 0x18, &ldrAddr, sizeof(ldrAddr)) || !ldrAddr)
    {
        Log("PebLinkModule: failed to read PEB->Ldr – skipping");
        return 0;
    }
    Log("PEB->Ldr            : 0x%llX", (unsigned long long)ldrAddr);

    // ── 3. Read the three list-head Flink/Blink pairs ─────────
    //
    //  PEB_LDR_DATA layout (x64, offsets from ldrAddr):
    //    +0x00  Length                       ULONG
    //    +0x04  Initialized                  BOOLEAN
    //    +0x08  SsHandle                     PVOID
    //    +0x10  InLoadOrderModuleList         LIST_ENTRY  ← head
    //    +0x20  InMemoryOrderModuleList       LIST_ENTRY  ← head
    //    +0x30  InInitializationOrderModuleList LIST_ENTRY ← head
    struct ListPair { uint64_t Flink, Blink; };
    ListPair loHead{}, moHead{}, ioHead{};
    if (!DrvReadMem(pid, ldrAddr + 0x10, &loHead, sizeof(loHead)) ||
        !DrvReadMem(pid, ldrAddr + 0x20, &moHead, sizeof(moHead)) ||
        !DrvReadMem(pid, ldrAddr + 0x30, &ioHead, sizeof(ioHead)))
    {
        Log("PebLinkModule: failed to read LDR list heads – skipping");
        return 0;
    }

    // ── 4. Compute string sizes and allocation layout ─────────
    size_t fullLen   = wcslen(fullPath);
    size_t baseLen   = wcslen(baseName);
    size_t fullBytes = (fullLen + 1) * sizeof(wchar_t);  // +1 for NUL
    size_t baseBytes = (baseLen + 1) * sizeof(wchar_t);
    // Layout: [REMOTE_LDR_ENTRY][REMOTE_LDR_DDAG_NODE][fullPath][baseName]
    size_t totalSize = sizeof(REMOTE_LDR_ENTRY) + sizeof(REMOTE_LDR_DDAG_NODE)
                     + fullBytes + baseBytes;

    // ── 5. Allocate the entry + DDAG node + string buffers ────
    uint64_t remoteAlloc = DrvAllocMem(pid, 0, totalSize, PAGE_READWRITE);
    if (!remoteAlloc)
    {
        Err("PebLinkModule: DrvAllocMem failed");
        return 0;
    }
    uint64_t remoteDdag    = remoteAlloc + sizeof(REMOTE_LDR_ENTRY);
    uint64_t remoteFullBuf = remoteDdag  + sizeof(REMOTE_LDR_DDAG_NODE);
    uint64_t remoteBaseBuf = remoteFullBuf + fullBytes;
    Log("LDR entry alloc     : 0x%llX  (%zu bytes)",
        (unsigned long long)remoteAlloc, totalSize);

    // ── 6. Build the entry ────────────────────────────────────
    //
    // Tail-insertion: for each list L
    //   newEntry.L.Flink = &headNode
    //   newEntry.L.Blink = headNode.Blink  (current tail)
    //   currentTail.L.Flink  = &newEntry.L
    //   headNode.L.Blink     = &newEntry.L
    //
    // Offsets of each link within REMOTE_LDR_ENTRY:
    //   InLoadOrderLinks          → entry + 0x00
    //   InMemoryOrderLinks        → entry + 0x10
    //   InInitializationOrderLinks→ entry + 0x20
    REMOTE_LDR_ENTRY e{};

    e.InLoadOrder_Flink   = ldrAddr + 0x10;        // points back to LO head
    e.InLoadOrder_Blink   = loHead.Blink;           // old tail
    e.InMemoryOrder_Flink = ldrAddr + 0x20;         // points back to MO head
    e.InMemoryOrder_Blink = moHead.Blink;           // old tail
    e.InInitOrder_Flink   = ldrAddr + 0x30;         // points back to IO head
    e.InInitOrder_Blink   = ioHead.Blink;           // old tail

    e.DllBase     = imageBase;
    e.EntryPoint  = entryPoint;
    e.SizeOfImage = imageSize;

    e.FullDllName_Length = static_cast<uint16_t>(fullLen * sizeof(wchar_t));
    e.FullDllName_MaxLen = static_cast<uint16_t>(fullBytes);
    e.FullDllName_Buffer = remoteFullBuf;

    e.BaseDllName_Length = static_cast<uint16_t>(baseLen * sizeof(wchar_t));
    e.BaseDllName_MaxLen = static_cast<uint16_t>(baseBytes);
    e.BaseDllName_Buffer = remoteBaseBuf;

    // LDRP_IMAGE_DLL (0x4) | LDRP_ENTRY_PROCESSED (0x4000)
    // | LDRP_PROCESS_ATTACH_CALLED (0x80000)
    // | LDRP_DONT_CALL_FOR_THREADS (0x40000)
    //
    // LDRP_PROCESS_ATTACH_CALLED: prevents DLL_PROCESS_ATTACH from being
    //   re-delivered.  LdrpInitializeNode checks this bit first and returns
    //   immediately if set.
    //
    // LDRP_DONT_CALL_FOR_THREADS: prevents LdrpCallInitRoutines from
    //   delivering DLL_THREAD_ATTACH / DLL_THREAD_DETACH to our fake entry
    //   on every new thread the process creates.  We set this unconditionally
    //   because:
    //     (a) DLLs that call DisableThreadLibraryCalls (most DLLs, including
    //         this one) expect it.  DisableThreadLibraryCalls internally uses
    //         LdrpModuleBaseAddressIndex (an AVL tree) which we do NOT insert
    //         into, so it fails silently → flag is never set → DLL_THREAD_ATTACH
    //         is delivered to DllMain on every new thread → crash/detection.
    //     (b) For /MT TLS DLLs, per-thread CRT state is allocated by
    //         LdrpAllocateTls walking LdrpTlsList (set up by LinkTlsEntry) and
    //         by TLS callbacks (AddressOfCallBacks in the REMOTE_TLS_ENTRY),
    //         NOT by DLL_THREAD_ATTACH to DllMain.  Setting this flag is safe.
    //     (c) For /MD DLLs, VCRUNTIME140/ucrtbase manage per-thread state via
    //         their own real LDR entries and TLS callbacks — our entry's
    //         DLL_THREAD_ATTACH would be a no-op anyway and is never needed.
    e.Flags     = 0x000C4004;  // IMAGE_DLL | ENTRY_PROCESSED | PROCESS_ATTACH_CALLED | DONT_CALL_FOR_THREADS
    e.LoadCount = 1;
    e.TlsIndex  = 0xFFFF;  // sentinel: no structured TLS (patched by LinkTlsEntry when TLS dir present)

    // ── HashLinks: self-referential (not inserted into the hash table;
    //   safe because no public API iterates the hash table for us) ──────────
    e.HashLinks_Flink = remoteAlloc + 0x6C;  // patched to real bucket head by PebHashLinkModule
    e.HashLinks_Blink = remoteAlloc + 0x6C;

    // ── DdagNode: pointer to our REMOTE_LDR_DDAG_NODE ────────────────────────
    // CRITICAL: ntdll's LdrpCallInitRoutines dereferences DdagNode->State
    // (at DdagNode+0x38) on EVERY new thread before checking any loader flags.
    // Leaving this NULL causes an AV at 0x38 on the first thread the game
    // creates after injection.
    e.DdagNode = remoteDdag;

    // ── NodeModuleLink: circular list with one element ─────────────────────
    // DdagNode->Modules is a LIST_ENTRY whose elements are the NodeModuleLink
    // fields of each LDR_DATA_TABLE_ENTRY in this load group.  For a single
    // manually-mapped module, the list has exactly one entry: our own.
    //   NodeModuleLink.Flink -> DdagNode->Modules (back to head)
    //   NodeModuleLink.Blink -> DdagNode->Modules (only entry, points to head)
    // DdagNode->Modules.Flink/Blink -> NodeModuleLink (our entry)
    // (wired below after the DdagNode write)
    e.NodeModuleLink_Flink = remoteDdag + 0x00;  // -> DdagNode->Modules (head)
    e.NodeModuleLink_Blink = remoteDdag + 0x00;  // same (only element, circular)

    // ── Build and write REMOTE_LDR_DDAG_NODE ─────────────────────────────────
    REMOTE_LDR_DDAG_NODE ddag{};
    //   Modules list head: Flink/Blink point to NodeModuleLink in our LDR entry
    ddag.Modules_Flink = remoteAlloc + 0x98;  // &LDR_ENTRY.NodeModuleLink_Flink
    ddag.Modules_Blink = remoteAlloc + 0x98;
    ddag.LoadCount     = 1;
    ddag.State         = 9;  // LdrModulesReadyToRun
    // All other fields remain zero (NULL pointers, zero counts)

    // ── 7. Write entry, DDAG node, and name strings ──────────
    if (!DrvWriteMem(pid, remoteAlloc, &e, sizeof(e)))
    {
        Err("PebLinkModule: DrvWriteMem (LDR entry) failed");
        DrvFreeMem(pid, remoteAlloc);
        return 0;
    }
    if (!DrvWriteMem(pid, remoteDdag, &ddag, sizeof(ddag)))
    {
        Err("PebLinkModule: DrvWriteMem (DDAG node) failed");
        DrvFreeMem(pid, remoteAlloc);
        return 0;
    }
    DrvWriteMem(pid, remoteFullBuf, fullPath, fullBytes);
    DrvWriteMem(pid, remoteBaseBuf, baseName, baseBytes);

    // ── 8. Patch the lists: splice new entry at the tail ──────
    //
    // Remote VAs of the three link fields inside our new entry:
    const uint64_t newLo = remoteAlloc + 0x00;  // &InLoadOrderLinks
    const uint64_t newMo = remoteAlloc + 0x10;  // &InMemoryOrderLinks
    const uint64_t newIo = remoteAlloc + 0x20;  // &InInitializationOrderLinks

    // old tail.Flink = &newEntry.Link  (close the tail forward-pointer)
    DrvWriteMem(pid, loHead.Blink + 0, &newLo, sizeof(newLo));
    DrvWriteMem(pid, moHead.Blink + 0, &newMo, sizeof(newMo));
    DrvWriteMem(pid, ioHead.Blink + 0, &newIo, sizeof(newIo));

    // list head.Blink = &newEntry.Link  (close the head back-pointer)
    DrvWriteMem(pid, ldrAddr + 0x10 + 8, &newLo, sizeof(newLo));
    DrvWriteMem(pid, ldrAddr + 0x20 + 8, &newMo, sizeof(newMo));
    DrvWriteMem(pid, ldrAddr + 0x30 + 8, &newIo, sizeof(newIo));

    Log("PEB link: OK");
    Log("  InLoadOrder   : head=0x%llX  oldTail=0x%llX  -> new=0x%llX",
        (unsigned long long)(ldrAddr + 0x10),
        (unsigned long long)loHead.Blink,
        (unsigned long long)newLo);
    Log("  InMemoryOrder : head=0x%llX  oldTail=0x%llX  -> new=0x%llX",
        (unsigned long long)(ldrAddr + 0x20),
        (unsigned long long)moHead.Blink,
        (unsigned long long)newMo);
    Log("  InInitOrder   : head=0x%llX  oldTail=0x%llX  -> new=0x%llX",
        (unsigned long long)(ldrAddr + 0x30),
        (unsigned long long)ioHead.Blink,
        (unsigned long long)newIo);
    return remoteAlloc;
}

// ─────────────────────────────────────────────────────────────
// Structured TLS Linking (LdrpTlsList)
//
// Windows new-thread path (LdrpInitializeThread) calls
// LdrpAllocateTls, which iterates ntdll's internal LdrpTlsList
// and for each entry allocates a copy of the TLS raw-data template,
// stores the pointer into TEB.ThreadLocalStoragePointer[index], and
// records the correct index in *AddressOfIndex.
//
// Manual mapping bypasses LdrpAllocateTlsEntry, so the injected
// module is absent from LdrpTlsList.  Consequence:
//   Any __declspec(thread) variable accessed on a newly created thread
//   reads TEB.ThreadLocalStoragePointer[_tls_index], finds NULL
//   (slot never allocated), and crashes at NULL+offset.
//
// Our shellcode called TlsAlloc() to get a Win32 TLS slot and wrote
// that into _tls_index.  Win32 TLS uses TEB.TlsSlots[0..63] and
// TEB.TlsExpansionSlots[64..1087], completely separate arrays from
// TEB.ThreadLocalStoragePointer.  Structured TLS uses only
// ThreadLocalStoragePointer, so a Win32 slot number (e.g. 159) is
// meaningless there and causes an out-of-bounds read/write on every
// new thread.
//
// This function:
//   1. Scans ntdll's .data section to locate LdrpTlsList
//   2. Counts entries to determine the next available structured index
//   3. Overwrites _tls_index with the correct structured index (NOT
//      the Win32 slot from TlsAlloc)
//   4. Finds and increments LdrpNumberOfTlsEntries so that
//      LdrpAllocateTls allocates an array large enough for our slot
//   5. Allocates a remote TLS_ENTRY and tail-inserts it
// ─────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct REMOTE_TLS_ENTRY
{
    // +0x00  LIST_ENTRY  TlsEntryLinks
    uint64_t Links_Flink;
    uint64_t Links_Blink;
    // +0x10  IMAGE_TLS_DIRECTORY64 (0x28 bytes)
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;         // = remote &_tls_index
    uint64_t AddressOfCallBacks;     // patched VA of callback array (DLL_THREAD_ATTACH for new threads)
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
    // +0x38  PLDR_DATA_TABLE_ENTRY ModuleAddress
    uint64_t ModuleAddress;
};  // total 0x40 bytes
#pragma pack(pop)
static_assert(sizeof(REMOTE_TLS_ENTRY) == 0x40,
    "REMOTE_TLS_ENTRY size mismatch");

static void LinkTlsEntry(
    uint64_t pid,
    const std::unordered_map<std::string, uint64_t>& targetModules,
    uint64_t ldrEntryAddr,
    uint64_t tlsIndexAddr,           // remote VA of IMAGE_TLS_DIRECTORY64::AddressOfIndex
    uint64_t tlsStartRawData,        // remote VA (patched) of raw TLS data start
    uint64_t tlsEndRawData,          // remote VA (patched) of raw TLS data end
    uint64_t tlsAddressOfCallBacks,  // remote VA (patched) of null-terminated callback array
    uint32_t tlsSizeOfZeroFill,
    uint32_t tlsCharacteristics)
{
    // ── 1. Find ntdll base ────────────────────────────────────
    auto ntIt = targetModules.find("ntdll.dll");
    if (ntIt == targetModules.end())
    {
        Log("LinkTls: ntdll not in module map – structured TLS skipped");
        return;
    }
    uint64_t ntdllBase = ntIt->second;

    // ── 2. Find ntdll .data section ──────────────────────────
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!DrvReadMem(pid, ntdllBase, &dos, sizeof(dos)) ||
        !DrvReadMem(pid, ntdllBase + dos.e_lfanew, &nt, sizeof(nt)))
    {
        Log("LinkTls: cannot read ntdll PE headers"); return;
    }

    uint64_t dataVA = 0, dataSize = 0;
    {
        uint64_t secBase = ntdllBase + (uint32_t)dos.e_lfanew
                         + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader)
                         + nt.FileHeader.SizeOfOptionalHeader;
        uint16_t nSec = nt.FileHeader.NumberOfSections;
        if (nSec > 64) nSec = 64;
        std::vector<IMAGE_SECTION_HEADER> secs(nSec);
        DrvReadMem(pid, secBase, secs.data(), nSec * sizeof(IMAGE_SECTION_HEADER));
        for (auto& s : secs)
        {
            bool w = (s.Characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
            bool x = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool r = (s.Characteristics & IMAGE_SCN_MEM_READ)    != 0;
            if (w && r && !x && s.Misc.VirtualSize > 0x1000)
            {
                dataVA   = ntdllBase + s.VirtualAddress;
                dataSize = s.Misc.VirtualSize;
                break;
            }
        }
    }
    if (!dataVA) { Log("LinkTls: ntdll .data not found"); return; }
    Log("ntdll .data           : 0x%llX  size=0x%llX",
        (unsigned long long)dataVA, (unsigned long long)dataSize);
    // Log ntdll build identity for exact version matching during debugging.
    Log("ntdll build           : TimeDateStamp=0x%08X  SizeOfImage=0x%X  base=0x%llX  (ntdll+0x%llX = .data start)",
        nt.FileHeader.TimeDateStamp,
        nt.OptionalHeader.SizeOfImage,
        (unsigned long long)ntdllBase,
        (unsigned long long)(dataVA - ntdllBase));

    // Helper: is address inside ntdll .data?
    auto inData = [&](uint64_t v) -> bool {
        return v >= dataVA && v < dataVA + dataSize;
    };

    // Is address a plausible user-mode pointer?
    auto plausiblePtr = [](uint64_t v) -> bool {
        return v >= 0x10000ULL && v < 0x00007FFFFFFFFFFULL;
    };

    // ── 3a. Collect TLS reference modules ────────────────────────────────
    //
    // We locate LdrpTlsList by anchoring to modules with a known AddressOfIndex.
    // We collect refs from two passes:
    //   Pass 1: well-known CRT DLLs (most reliable, loaded in nearly all processes)
    //   Pass 2: full module list (catches engine-specific runtimes like gmesdk.dll)
    //
    // For each ref we validate that AddressOfIndex falls within the module's
    // own image [modBase, modBase+SizeOfImage) to catch garbage reads early.
    // A ref with AddressOfIndex outside its module image is logged as SUSPICIOUS
    // and excluded from chain confirmation (it will not match a real TLS_ENTRY).
    struct TlsRef { std::string name; uint64_t modBase; uint64_t addrOfIndex; uint32_t slot; bool valid; };
    std::vector<TlsRef> tlsRefs;

    auto tryAddTlsRef = [&](const std::string& name, uint64_t mb) -> bool
    {
        if (!mb || !plausiblePtr(mb)) return false;
        IMAGE_DOS_HEADER rdos{};
        if (!DrvReadMem(pid, mb, &rdos, sizeof(rdos)) || rdos.e_magic != IMAGE_DOS_SIGNATURE) return false;
        IMAGE_NT_HEADERS64 rnt{};
        if (!DrvReadMem(pid, mb + rdos.e_lfanew, &rnt, sizeof(rnt))) return false;
        auto& tEntry = rnt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (!tEntry.VirtualAddress) return false;
        IMAGE_TLS_DIRECTORY64 rtls{};
        if (!DrvReadMem(pid, mb + tEntry.VirtualAddress, &rtls, sizeof(rtls))) return false;
        if (!rtls.AddressOfIndex) return false;
        uint32_t slotVal = 0xFFFFFFFF;
        if (!DrvReadMem(pid, rtls.AddressOfIndex, &slotVal, 4)) return false;
        if (slotVal == 0xFFFFFFFF || slotVal > 1023) return false;

        uint32_t imgSz = rnt.OptionalHeader.SizeOfImage;
        // AddressOfIndex must lie within the module's own mapped image.
        // A pointer outside [modBase, modBase+SizeOfImage) means the TLS directory
        // or the read is corrupt – using it for chain confirmation would cause the
        // scan to never match any real TLS_ENTRY, failing silently.
        bool addrInImage = (rtls.AddressOfIndex >= mb &&
                            rtls.AddressOfIndex < mb + (uint64_t)imgSz);
        Log("TLS ref            : %-28s  base=0x%llX  imgSz=0x%X  addrOfIdx=0x%llX [%s]  slot=%u",
            name.c_str(),
            (unsigned long long)mb,
            imgSz,
            (unsigned long long)rtls.AddressOfIndex,
            addrInImage ? "in-image" : "OUTSIDE image – SUSPICIOUS",
            slotVal);

        tlsRefs.push_back({ name, mb, rtls.AddressOfIndex, slotVal, addrInImage });
        return true;
    };

    // Pass 1: well-known CRT/runtime DLLs
    static const char* kCandidates[] = {
        "vcruntime140.dll",   "vcruntime140_1.dll",
        "ucrtbase.dll",       "msvcp140.dll",
        "msvcp_win.dll",      "concrt140.dll",
        nullptr
    };
    for (int ci = 0; kCandidates[ci]; ++ci)
    {
        auto it = targetModules.find(kCandidates[ci]);
        if (it != targetModules.end())
            tryAddTlsRef(it->first, it->second);
    }

    // Pass 2: scan all modules for up to 8 valid refs (stops early if we have 3+ valid ones)
    {
        int validCount = 0;
        for (auto& ref : tlsRefs) if (ref.valid) ++validCount;
        if (validCount < 3)
        {
            for (auto& kv : targetModules)
            {
                // Skip already-added names
                bool already = false;
                for (auto& r : tlsRefs) if (r.name == kv.first) { already = true; break; }
                if (already) continue;
                if (tryAddTlsRef(kv.first, kv.second))
                {
                    if (tlsRefs.back().valid) ++validCount;
                    if (validCount >= 8) break;
                }
            }
        }
    }

    // Build a set of confirmed-valid addrOfIndex values for fast lookup during scan.
    // Only refs where addrOfIndex is inside the module image are used for confirmation.
    std::vector<uint64_t> validRefAddrs;
    for (auto& r : tlsRefs)
        if (r.valid) validRefAddrs.push_back(r.addrOfIndex);

    // Compute expected LdrpNumberOfTlsEntries from the max known slot.
    // Used for adjacency-based fallback scan.
    uint32_t maxRefSlot = 0;
    for (auto& r : tlsRefs) if (r.valid && r.slot > maxRefSlot) maxRefSlot = r.slot;
    // The count is >= maxRefSlot + 1 (at least that many structured TLS modules loaded).
    uint32_t expectedMinCount = maxRefSlot + 1;

    const bool hasValidRefs = !validRefAddrs.empty();
    Log("TLS ref summary       : %zu total refs, %zu valid (in-image), minExpectedEntries=%u",
        tlsRefs.size(), validRefAddrs.size(), expectedMinCount);

    // ── 3b. Scan .data for LdrpTlsList ────────────────────────────────────
    //
    // Strategy A (primary, used when hasValidRefs):
    //   Find a LIST_ENTRY head A in ntdll .data such that:
    //     (1) A.Flink points to a candidate TLS_ENTRY whose Links.Blink == A
    //     (2) Walking the full chain finds at least one entry whose
    //         AddressOfIndex matches a valid reference module's addrOfIndex
    //   This eliminates false positives completely.
    //
    // Strategy B (fallback, used when strategy A fails):
    //   Scan ntdll .data for a DWORD equal to expectedMinCount immediately
    //   adjacent to a self-referential or non-empty LIST_ENTRY.  This is the
    //   LdrpNumberOfTlsEntries + LdrpTlsList layout found in all known ntdll builds.
    //   Using the actual known count avoids false matches with coincidental zeros.
    //
    // Strategy C (last resort, when no valid refs):
    //   Original self-referential + adjacent-zero heuristic.
    //   Gated behind !hasValidRefs to prevent false-positive slot-0 collisions
    //   in large processes.

    // Rejection diagnostics
    uint32_t dbg_checked       = 0; // candidate LIST_ENTRYs examined (Flink/Blink plausible)
    uint32_t dbg_blink_mismatch = 0; // first entry's Blink != A
    uint32_t dbg_flink_bad     = 0; // first entry's Flink not plausible
    uint32_t dbg_badAddrIdx    = 0; // AddressOfIndex unreadable or slot > 1023
    uint32_t dbg_noRefMatch    = 0; // chain walked but no ref matched

    // Best near-miss: the candidate with the most chain entries (most likely the real list)
    struct NearMiss { uint64_t headAddr; uint32_t chainLen; std::vector<uint64_t> chainAddrOfIdx; } bestNearMiss{};

    uint64_t ldrpTlsListAddr = 0;
    {
        const size_t CHUNK = 8192;
        std::vector<uint8_t> buf(CHUNK);

        for (uint64_t off = 0; off < dataSize && !ldrpTlsListAddr; off += CHUNK - 16)
        {
            size_t rdSz = std::min<size_t>(CHUNK, dataSize - off);
            if (!DrvReadMem(pid, dataVA + off, buf.data(), rdSz)) continue;

            for (size_t i = 0; i + 16 <= rdSz; i += 8)
            {
                uint64_t A = dataVA + off + i;
                uint64_t Flink, Blink;
                memcpy(&Flink, buf.data() + i,     8);
                memcpy(&Blink, buf.data() + i + 8, 8);

                // ── Strategy A: non-empty list ──────────────────────────
                if (plausiblePtr(Flink) && plausiblePtr(Blink) &&
                    Flink != A && Blink != A)
                {
                    ++dbg_checked;

                    uint8_t te[0x40]{};
                    if (!DrvReadMem(pid, Flink, te, sizeof(te))) goto tryFallback;

                    // First entry's Blink must point back to A
                    uint64_t te_Blink;
                    memcpy(&te_Blink, te + 8, 8);
                    if (te_Blink != A) { ++dbg_blink_mismatch; goto tryFallback; }

                    {
                        uint64_t te_Flink;
                        memcpy(&te_Flink, te + 0, 8);
                        if (!plausiblePtr(te_Flink)) { ++dbg_flink_bad; goto tryFallback; }
                    }

                    // First entry AddressOfIndex + slot sanity
                    {
                        uint64_t addrOfIdx;
                        memcpy(&addrOfIdx, te + 0x20, 8);
                        if (!addrOfIdx || !plausiblePtr(addrOfIdx)) { ++dbg_badAddrIdx; goto tryFallback; }
                        uint32_t s = 0xFFFFFFFF;
                        if (!DrvReadMem(pid, addrOfIdx, &s, 4)) { ++dbg_badAddrIdx; goto tryFallback; }
                        if (s > 1023) { ++dbg_badAddrIdx; goto tryFallback; }
                    }

                    // Walk entire chain for ref confirmation + collect diagnostics
                    if (hasValidRefs)
                    {
                        bool confirmed = false;
                        std::vector<uint64_t> chainAddrs;
                        uint64_t cur = Flink;
                        for (int g = 0; cur != A && g < 512; ++g)
                        {
                            uint8_t ce[0x40]{};
                            if (!DrvReadMem(pid, cur, ce, sizeof(ce))) break;
                            uint64_t ceAddrOfIdx;
                            memcpy(&ceAddrOfIdx, ce + 0x20, 8);
                            chainAddrs.push_back(ceAddrOfIdx);
                            for (uint64_t rv : validRefAddrs)
                                if (ceAddrOfIdx == rv) { confirmed = true; }
                            uint64_t next;
                            memcpy(&next, ce + 0, 8);
                            if (!plausiblePtr(next) || next == cur) break;
                            cur = next;
                        }
                        if (!confirmed)
                        {
                            ++dbg_noRefMatch;
                            // Track the longest chain as "best near-miss" for diagnostics
                            if (chainAddrs.size() > bestNearMiss.chainLen)
                            {
                                bestNearMiss.headAddr       = A;
                                bestNearMiss.chainLen       = (uint32_t)chainAddrs.size();
                                bestNearMiss.chainAddrOfIdx = chainAddrs;
                            }
                            goto tryFallback;
                        }
                    }

                    ldrpTlsListAddr = A;
                    Log("LdrpTlsList           : 0x%llX  (ntdll+0x%llX)  [non-empty, ref-confirmed]",
                        (unsigned long long)A,
                        (unsigned long long)(A - ntdllBase));
                    break;
                }

                // ── Strategy B/C: self-referential (empty or skip) ──────
                tryFallback:
                if (Flink == A && Blink == A)
                {
                    // Strategy B: empty list confirmed by LdrpNumberOfTlsEntries == expectedMinCount
                    if (hasValidRefs && expectedMinCount > 0)
                    {
                        uint64_t probes[] = { A + 0x10, A + 0x18, A - 0x04, A - 0x08 };
                        for (uint64_t p : probes)
                        {
                            if (!inData(p)) continue;
                            uint32_t v = 0xFFFFFFFF;
                            if (!DrvReadMem(pid, p, &v, 4)) continue;
                            if (v == expectedMinCount)
                            {
                                ldrpTlsListAddr = A;
                                Log("LdrpTlsList           : 0x%llX  (ntdll+0x%llX)  [self-ref, adjacent count=%u matches expectedMin=%u]",
                                    (unsigned long long)A, (unsigned long long)(A - ntdllBase),
                                    v, expectedMinCount);
                                break;
                            }
                        }
                        if (ldrpTlsListAddr) break;
                    }
                    // Strategy C: no valid refs →  only accept adjacent zero
                    else if (!hasValidRefs)
                    {
                        uint64_t probes[] = { A + 0x10, A + 0x18, A - 0x04, A - 0x08 };
                        for (uint64_t p : probes)
                        {
                            if (!inData(p)) continue;
                            uint32_t v = 0xFFFFFFFF;
                            if (!DrvReadMem(pid, p, &v, 4)) continue;
                            if (v == 0)
                            {
                                ldrpTlsListAddr = A;
                                Log("LdrpTlsList           : 0x%llX  (ntdll+0x%llX)  [empty list, no-TLS process]",
                                    (unsigned long long)A, (unsigned long long)(A - ntdllBase));
                                break;
                            }
                        }
                        if (ldrpTlsListAddr) break;
                    }
                }
            }
        }
    }

    // ── Scan diagnostic summary ─────────────────────────────────
    Log("TlsList scan stats    : checked=%u  blink_mismatch=%u  flink_bad=%u"
        "  badAddrIdx=%u  no_ref_match=%u",
        dbg_checked, dbg_blink_mismatch, dbg_flink_bad,
        dbg_badAddrIdx, dbg_noRefMatch);

    if (!ldrpTlsListAddr && bestNearMiss.chainLen > 0)
    {
        // ── Near-miss quality filter ──────────────────────────────────────────
        // A genuine LdrpTlsList has an AddressOfIndex != 0 for EVERY entry because
        // every TLS_ENTRY was created by LdrpAllocateTlsEntry which always writes
        // a valid _tls_index slot.  A chain where almost all entries have
        // addrOfIdx==0 is a different ntdll internal list (e.g. the LdrpHashTable
        // chain, work queue, or other linked structure) whose +0x20 offset happens
        // to look like zero-filled AddressOfIndex values.
        //
        // Compute the fraction of entries with non-null addrOfIdx.
        // Real TLS list: fraction should be 1.0 (all non-null).
        // Bad false-positive list: fraction << 1.0 (mostly null).
        uint32_t nonNullCount = 0;
        for (uint64_t ai : bestNearMiss.chainAddrOfIdx) if (ai != 0) ++nonNullCount;
        float nonNullFrac = bestNearMiss.chainLen > 0
            ? (float)nonNullCount / (float)bestNearMiss.chainLen : 0.f;

        // Print the best near-miss for diagnostics.
        Log("Best near-miss        : head=0x%llX  (ntdll+0x%llX)  chainLen=%u"
            "  nonNull=%u (%.0f%%)  quality=%s",
            (unsigned long long)bestNearMiss.headAddr,
            (unsigned long long)(bestNearMiss.headAddr - ntdllBase),
            bestNearMiss.chainLen, nonNullCount, nonNullFrac * 100.f,
            nonNullFrac >= 0.9f ? "GOOD (likely real TLS list)" :
            nonNullFrac >= 0.5f ? "FAIR" : "POOR (likely wrong list)");

        for (size_t k = 0; k < bestNearMiss.chainAddrOfIdx.size() && k < 16; ++k)
        {
            uint64_t ai = bestNearMiss.chainAddrOfIdx[k];
            uint32_t s = 0xFFFFFFFF;
            if (ai) DrvReadMem(pid, ai, &s, 4);
            std::string owner = "unknown";
            for (auto& kv : targetModules)
            {
                IMAGE_DOS_HEADER d2{};
                IMAGE_NT_HEADERS64 n2{};
                if (!DrvReadMem(pid, kv.second, &d2, sizeof(d2)) || d2.e_magic != IMAGE_DOS_SIGNATURE) continue;
                if (!DrvReadMem(pid, kv.second + d2.e_lfanew, &n2, sizeof(n2))) continue;
                if (ai >= kv.second && ai < kv.second + n2.OptionalHeader.SizeOfImage)
                    { owner = kv.first; break; }
            }
            Log("  chain[%2zu]  addrOfIdx=0x%llX  slot=%u  owner=%s",
                k, (unsigned long long)ai, s, owner.c_str());
        }

        // Auto-accept near-miss only if:
        //  (a) chain quality is GOOD (>=90% non-null addrOfIdx entries)   AND
        //  (b) chainLen is within [expectedMinCount, expectedMinCount+4]
        // Both conditions are required to prevent false-positive auto-acceptance
        // of other ntdll lists (like the 160-entry work queue / hash chain) that
        // happen to be the "longest" candidate found.
        if (nonNullFrac >= 0.9f &&
            bestNearMiss.chainLen >= expectedMinCount &&
            bestNearMiss.chainLen <= expectedMinCount + 4)
        {
            ldrpTlsListAddr = bestNearMiss.headAddr;
            Log("LdrpTlsList           : 0x%llX  [auto-accepted near-miss,"
                " chainLen=%u nonNull=%.0f%% matches expected=%u]",
                (unsigned long long)ldrpTlsListAddr,
                bestNearMiss.chainLen, nonNullFrac * 100.f, expectedMinCount);
        }
        else
        {
            Log("Near-miss rejected    : quality=%.0f%%  chainLen=%u  expected=%u"
                " — not a real TLS list",
                nonNullFrac * 100.f, bestNearMiss.chainLen, expectedMinCount);
        }
    }

    // ── Strategy D: unconditional empty-list fallback ─────────────────────
    //
    // This runs after the ref-confirmed scan FAILS regardless of hasValidRefs.
    //
    // Rationale:
    //   Some processes load DLLs (e.g. gmesdk.dll) whose IMAGE_TLS_DIRECTORY64
    //   has a non-FFFFFFFF _tls_index value that came from a Win32 TlsAlloc call
    //   inside the DLL (or from a non-standard loader path), NOT from
    //   LdrpAllocateTlsEntry.  Such modules have a TLS directory + a valid slot
    //   but they are NOT in LdrpTlsList.  Consequently:
    //     - Strategy A finds no candidate whose chain contains the ref's addrOfIndex
    //     - hasValidRefs is true (the ref appears valid) and expectedMinCount > 0
    //     - The old Strategy B/C gating (!hasValidRefs) prevents the empty-list
    //       heuristic → scan returns failure → crash on new threads
    //
    //   After Strategy A completely fails (bestNearMiss was rejected OR not found),
    //   we unconditionally scan for a self-referential LIST_ENTRY adjacent to a
    //   DWORD == 0.  If found, it is accepted as an empty LdrpTlsList.  We log
    //   a clear warning explaining why ref modules may have TLS dirs but the list
    //   is empty (Win32 TlsAlloc vs structured loader TLS).
    if (!ldrpTlsListAddr)
    {
        Log("Fallback D            : scanning for empty LdrpTlsList"
            " (ref modules may use Win32 TlsAlloc, not loader structured TLS)");
        const size_t CHUNK = 8192;
        std::vector<uint8_t> buf2(CHUNK);
        for (uint64_t off = 0; off < dataSize && !ldrpTlsListAddr; off += CHUNK - 16)
        {
            size_t rdSz = std::min<size_t>(CHUNK, dataSize - off);
            if (!DrvReadMem(pid, dataVA + off, buf2.data(), rdSz)) continue;
            for (size_t i = 0; i + 16 <= rdSz; i += 8)
            {
                uint64_t A = dataVA + off + i;
                uint64_t Flink, Blink;
                memcpy(&Flink, buf2.data() + i,     8);
                memcpy(&Blink, buf2.data() + i + 8, 8);
                if (Flink != A || Blink != A) continue;
                // Require at least one of the four adjacent DWORD positions to hold 0
                uint64_t probes[] = { A + 0x10, A + 0x18, A - 0x04, A - 0x08 };
                for (uint64_t p : probes)
                {
                    if (!inData(p)) continue;
                    uint32_t v = 0xFFFFFFFF;
                    if (!DrvReadMem(pid, p, &v, 4)) continue;
                    if (v == 0)
                    {
                        ldrpTlsListAddr = A;
                        Log("LdrpTlsList           : 0x%llX  (ntdll+0x%llX)"
                            "  [empty — fallback D, adjacent count=0]",
                            (unsigned long long)A, (unsigned long long)(A - ntdllBase));
                        if (hasValidRefs)
                            Log("  NOTE: %zu ref module(s) have TLS dirs but are absent"
                                " from LdrpTlsList — they used Win32 TlsAlloc (non-loader path)."
                                " Assigning slot 0 for the injected DLL.",
                                tlsRefs.size());
                        break;
                    }
                }
                if (ldrpTlsListAddr) break;
            }
        }
    }

    if (!ldrpTlsListAddr)
    {
        Log("LinkTls: LdrpTlsList not found after all strategies"
            " – structured TLS for new threads broken");
        Log("LinkTls: valid refs=%zu  expectedMin=%u  checked=%u  noRefMatch=%u"
            " ntdll TimeDateStamp=0x%08X",
            validRefAddrs.size(), expectedMinCount, dbg_checked, dbg_noRefMatch,
            nt.FileHeader.TimeDateStamp);
        return;
    }

    // ── 4. Count entries, determine new structured TLS index ──
    //
    // In Windows, each TLS_ENTRY's AddressOfIndex slot number is
    // assigned sequentially from 0 by LdrpAllocateTlsEntry.  The
    // number of entries equals LdrpNumberOfTlsEntries.  We assign
    // the next available index = max_existing_slot + 1.
    uint32_t maxSlot   = 0;
    uint32_t numEntries = 0;
    {
        uint64_t headFlink = 0;
        DrvReadMem(pid, ldrpTlsListAddr, &headFlink, 8);
        uint64_t cur = headFlink;
        for (int guard = 0; cur != ldrpTlsListAddr && guard < 512; ++guard)
        {
            uint64_t addrOfIdx = 0;
            DrvReadMem(pid, cur + 0x20, &addrOfIdx, 8);
            uint32_t s = 0;
            if (addrOfIdx) DrvReadMem(pid, addrOfIdx, &s, 4);
            if (s != 0xFFFFFFFF && s > maxSlot) maxSlot = s;
            uint64_t next = 0;
            DrvReadMem(pid, cur, &next, 8);
            cur = next;
            ++numEntries;
        }
    }
    // New structured index = max existing + 1
    // (for a compact 0-based assignment this equals numEntries,
    //  but using max+1 is correct even if any slots were freed)
    uint32_t newIndex = (numEntries > 0) ? maxSlot + 1 : 0;
    Log("LdrpTlsList entries   : %u  max_slot=%u  -> assigning slot %u",
        numEntries, maxSlot, newIndex);

    // Overwrite _tls_index in the mapped DLL with the correct structured index.
    // This replaces the incorrect Win32 TLS slot previously written by TlsAlloc.
    DrvWriteMem(pid, tlsIndexAddr, &newIndex, 4);
    // Also update LDR_DATA_TABLE_ENTRY.TlsIndex
    uint16_t idx16 = (uint16_t)newIndex;
    DrvWriteMem(pid, ldrEntryAddr + 0x6A, &idx16, sizeof(idx16));
    Log("_tls_index corrected  : %u written to 0x%llX + LDR TlsIndex",
        newIndex, (unsigned long long)tlsIndexAddr);

    // ── 5. Find and increment LdrpNumberOfTlsEntries ──────────
    //
    // LdrpAllocateTls allocates ThreadLocalStoragePointer with
    // LdrpNumberOfTlsEntries slots.  If we don't increment it,
    // our slot is off the end of the array and LdrpAllocateTls
    // will write out of bounds → heap corruption on EVERY new thread.
    //
    // On Windows 10/11 x64 this ULONG is typically at
    // ldrpTlsListAddr + 0x10 (immediately after the LIST_ENTRY head),
    // but we also scan ±64 bytes to handle layout variation.
    {
        uint32_t expected = numEntries;   // current count before we add ours
        uint32_t newCount = numEntries + 1;
        bool     found    = false;

        // Priority check at the canonical offset (+0x10)
        uint64_t candidates[] = {
            ldrpTlsListAddr + 0x10,   // immediately after LIST_ENTRY head
            ldrpTlsListAddr + 0x18,
            ldrpTlsListAddr - 0x04,
            ldrpTlsListAddr - 0x08,
        };
        for (uint64_t candAddr : candidates)
        {
            if (!inData(candAddr)) continue;
            uint32_t val = 0;
            if (!DrvReadMem(pid, candAddr, &val, 4)) continue;
            if (val == expected)
            {
                DrvWriteMem(pid, candAddr, &newCount, 4);
                Log("LdrpNumberOfTlsEntries: 0x%llX  %u -> %u",
                    (unsigned long long)candAddr, expected, newCount);
                found = true;
                break;
            }
        }
        if (!found)
        {
            // Broader scan ±64 bytes as fallback
            uint64_t scanBase = (ldrpTlsListAddr > 64)
                                ? ldrpTlsListAddr - 64
                                : ldrpTlsListAddr;
            uint8_t scanBuf[160]{};
            if (DrvReadMem(pid, scanBase, scanBuf, sizeof(scanBuf)))
            {
                for (int k = 0; k + 4 <= (int)sizeof(scanBuf); k += 4)
                {
                    uint32_t v;
                    memcpy(&v, scanBuf + k, 4);
                    if (v == expected)
                    {
                        uint64_t patchAddr = scanBase + (uint64_t)k;
                        DrvWriteMem(pid, patchAddr, &newCount, 4);
                        Log("LdrpNumberOfTlsEntries: 0x%llX (scan)  %u -> %u",
                            (unsigned long long)patchAddr, expected, newCount);
                        found = true;
                        break;
                    }
                }
            }
            if (!found)
                Log("LdrpNumberOfTlsEntries not found near LdrpTlsList (non-fatal if count matches)");
        }
    }

    // ── 6. Allocate and tail-insert REMOTE_TLS_ENTRY ──────────
    //
    // AddressOfCallBacks is preserved from the DLL's TLS directory so that
    // LdrpCallTlsInitializers invokes the TLS callbacks with DLL_THREAD_ATTACH
    // for every new thread the injected DLL spawns.  The MSVC static CRT
    // registers callbacks that run _initptd / __acrt_thread_attach to allocate
    // per-thread CRT state (_ptiddata).  Without them, _getptd() returns NULL
    // → crash on the first CRT call from any newly created thread.
    // The shellcode already called the callbacks with DLL_PROCESS_ATTACH once;
    // the loader only calls them with DLL_THREAD_ATTACH going forward.
    REMOTE_TLS_ENTRY e{};
    e.StartAddressOfRawData = tlsStartRawData;
    e.EndAddressOfRawData   = tlsEndRawData;
    e.AddressOfIndex        = tlsIndexAddr;
    e.AddressOfCallBacks    = tlsAddressOfCallBacks;  // DLL_THREAD_ATTACH init for new threads
    e.SizeOfZeroFill        = tlsSizeOfZeroFill;
    e.Characteristics       = tlsCharacteristics;
    e.ModuleAddress         = ldrEntryAddr;

    uint64_t remEntry = DrvAllocMem(pid, 0, sizeof(REMOTE_TLS_ENTRY), PAGE_READWRITE);
    if (!remEntry) { Log("LinkTls: DrvAllocMem(TLS_ENTRY) failed"); return; }

    // Read current tail (Blink of list head)
    uint64_t headBlink = 0;
    DrvReadMem(pid, ldrpTlsListAddr + 8, &headBlink, 8);

    e.Links_Flink = ldrpTlsListAddr;   // new -> head
    e.Links_Blink = headBlink;          // new -> old tail
    DrvWriteMem(pid, remEntry, &e, sizeof(e));

    // old tail.Flink = new entry
    DrvWriteMem(pid, headBlink + 0, &remEntry, sizeof(remEntry));
    // head.Blink = new entry
    DrvWriteMem(pid, ldrpTlsListAddr + 8, &remEntry, sizeof(remEntry));

    Log("TLS_ENTRY linked      : 0x%llX  slot=%u  start=0x%llX  end=0x%llX",
        (unsigned long long)remEntry, newIndex,
        (unsigned long long)tlsStartRawData,
        (unsigned long long)tlsEndRawData);
}

// ─────────────────────────────────────────────────────────────
// PE helpers
// ─────────────────────────────────────────────────────────────
static IMAGE_NT_HEADERS64* GetNtHeaders(uint8_t* base)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        Err("DLL is not x64 (Machine=0x%X)", nt->FileHeader.Machine);
        return nullptr;
    }
    return nt;
}

template<typename T>
static T* RvaToVa(uint8_t* base, uint32_t rva)
{
    return reinterpret_cast<T*>(base + rva);
}

static IMAGE_DATA_DIRECTORY* GetDirectory(IMAGE_NT_HEADERS64* nt, int idx)
{
    return &nt->OptionalHeader.DataDirectory[idx];
}

// ─────────────────────────────────────────────────────────────
// Step 1 – Read DLL from disk
// ─────────────────────────────────────────────────────────────
static std::vector<uint8_t> LoadDllFile(const char* path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        Err("Cannot open DLL '%s' (err=%lu)", path, GetLastError());
        return {};
    }
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    std::vector<uint8_t> buf((size_t)sz.QuadPart);
    DWORD rd = 0;
    ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr);
    CloseHandle(h);
    if (rd != (DWORD)buf.size()) { Err("Short read on DLL file"); return {}; }
    return buf;
}

// ─────────────────────────────────────────────────────────────
// Step 2 – Build a flat mapped image (copy headers + sections)
//           into a local buffer as if loaded at codeBase / rwBase.
//
// Split-allocation model (Fix 4):
//   Executable sections  (.text, etc.)  → codeBase + sectionRVA   (MEM_IMAGE)
//   Non-executable sections (.data/.rdata/.bss) → rwBase + sectionRVA (MEM_PRIVATE RW)
//   When rwBase == 0, all sections land at codeBase (single-base fallback).
//
//   The relocation loop distinguishes targets by checking which section RVA
//   range a pointer falls in, then applies deltaCode or deltaData.
//
// Remote IAT (Fix 1):
//   GetRemoteProcAddress reads the target module's EAT via DrvReadMem.
//   No local GetProcAddress/LoadLibrary – correct for ALL DLLs under ASLR.
// ─────────────────────────────────────────────────────────────
static std::vector<uint8_t> BuildMappedImage(
    uint8_t*            rawFile,
    IMAGE_NT_HEADERS64* nt,
    uint64_t            pid,
    uint64_t            codeBase,
    uint64_t            rwBase,
    uint8_t**           outEntryPoint,
    std::vector<uint64_t>& tlsCallbacks,
    const std::unordered_map<std::string, uint64_t>& targetModules,
    uint64_t*           outTlsIndexAddr  = nullptr,
    std::vector<uint8_t>* outTlsTemplate = nullptr, // TLS raw-data template bytes
    uint32_t*           outTlsZeroFill   = nullptr) // IMAGE_TLS_DIRECTORY64::SizeOfZeroFill
{
    uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    std::vector<uint8_t> img(imageSize, 0);

    // Copy PE header
    memcpy(img.data(), rawFile, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    auto* sec  = IMAGE_FIRST_SECTION(nt);
    WORD  nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; ++i)
    {
        if (sec[i].SizeOfRawData == 0) continue;
        uint32_t rawOff = sec[i].PointerToRawData;
        uint32_t rawSz  = sec[i].SizeOfRawData;
        uint32_t vOff   = sec[i].VirtualAddress;
        memcpy(img.data() + vOff, rawFile + rawOff,
               min(rawSz, imageSize - vOff));
    }

    uint64_t preferredBase = nt->OptionalHeader.ImageBase;
    int64_t  deltaCode     = (int64_t)(codeBase - preferredBase);
    int64_t  deltaData     = rwBase ? (int64_t)(rwBase - preferredBase) : deltaCode;

    // ── Classify section RVA ranges (code vs data) ────────────
    struct SecRange { uint32_t rva, len; bool isCode; };
    std::vector<SecRange> secRanges;
    secRanges.reserve(nSec);
    for (WORD i = 0; i < nSec; ++i)
    {
        uint32_t vlen = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                                : sec[i].SizeOfRawData;
        if (!vlen) continue;
        // Non-writable sections (.text, .rdata, .pdata, .xdata, .reloc, .rsrc) live at
        // codeBase so that RVA-relative lookups (RtlAddFunctionTable unwind info, vtables,
        // IAT stubs, etc.) resolve correctly against imageBase = codeBase.
        // Only truly writable sections (.data, .bss, TLS raw data) live at rwBase.
        secRanges.push_back({ sec[i].VirtualAddress, vlen,
                               !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) });
    }
    auto rvaIsCode = [&](uint32_t rva) -> bool {
        for (auto& r : secRanges)
            if (rva >= r.rva && rva < r.rva + r.len) return r.isCode;
        return true; // headers – treat as non-writable (code region)
    };

    // ── Fix base relocations with split deltas ────────────────
    auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relDir.VirtualAddress && relDir.Size && (deltaCode != 0 || deltaData != 0))
    {
        uint8_t* relEnd = img.data() + relDir.VirtualAddress + relDir.Size;
        auto* relBlk    = RvaToVa<IMAGE_BASE_RELOCATION>(img.data(), relDir.VirtualAddress);
        while (reinterpret_cast<uint8_t*>(relBlk) < relEnd && relBlk->SizeOfBlock >= 8)
        {
            int   count   = (int)((relBlk->SizeOfBlock - 8) / 2);
            auto* entries = reinterpret_cast<uint16_t*>(relBlk + 1);
            for (int k = 0; k < count; ++k)
            {
                uint16_t entry = entries[k];
                int type = entry >> 12;
                int off  = entry & 0x0FFF;
                uint8_t* patch = img.data() + relBlk->VirtualAddress + off;
                if (type == IMAGE_REL_BASED_DIR64)
                {
                    uint64_t v; memcpy(&v, patch, 8);
                    uint64_t pRVA    = v - preferredBase; // wraps on external ptr (handled)
                    int64_t  applyDelta = (pRVA < (uint64_t)imageSize &&
                                           rvaIsCode((uint32_t)pRVA))
                                        ? deltaCode : deltaData;
                    v += (uint64_t)applyDelta;
                    memcpy(patch, &v, 8);
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    uint32_t v; memcpy(&v, patch, 4);
                    v += (uint32_t)(int32_t)deltaCode;
                    memcpy(patch, &v, 4);
                }
            }
            relBlk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(relBlk) + relBlk->SizeOfBlock);
        }
        Log("Relocations applied  deltaCode=0x%llX  deltaData=0x%llX",
            (unsigned long long)deltaCode, (unsigned long long)deltaData);
    }
    else if (deltaCode != 0 && !relDir.VirtualAddress)
    {
        Err("Warning: no reloc directory, base mismatch "
            "(preferred=0x%llX code=0x%llX). DLL may crash.",
            (unsigned long long)preferredBase, (unsigned long long)codeBase);
    }

    // ── Resolve imports via remote EAT (Fix 1) ───────────────
    // GetRemoteProcAddress reads the EAT of each import module directly
    // from the target process's memory.  Correct for all DLLs under ASLR.
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress && impDir.Size)
    {
        auto* desc = RvaToVa<IMAGE_IMPORT_DESCRIPTOR>(img.data(), impDir.VirtualAddress);
        for (; desc->Name; ++desc)
        {
            const char* dllName = RvaToVa<char>(img.data(), desc->Name);

            std::string lower(dllName);
            for (char& c : lower) c = (char)tolower((unsigned char)c);

            // Resolve virtual API set names (api-ms-win-*, ext-ms-win-*) to the
            // physical host DLL before looking up the remote base address.
            std::string lookupName = lower;
            {
                const char* host = ResolveApiSetName(lower.c_str());
                if (host)
                {
                    lookupName = host;
                    Log("  IAT: API set '%s' -> '%s'", dllName, host);
                }
            }

            auto it = targetModules.find(lookupName);
            if (it == targetModules.end())
            {
                Err("IAT: '%s' (lookup '%s') not loaded in target – skip",
                    dllName, lookupName.c_str());
                continue;
            }
            uint64_t remoteModBase = it->second;

            uint32_t oftRva = desc->OriginalFirstThunk
                            ? desc->OriginalFirstThunk : desc->FirstThunk;
            auto* oft = RvaToVa<IMAGE_THUNK_DATA64>(img.data(), oftRva);
            auto* iat = RvaToVa<IMAGE_THUNK_DATA64>(img.data(), desc->FirstThunk);

            int resolved = 0, failed = 0;
            for (; oft->u1.AddressOfData; ++oft, ++iat)
            {
                uint64_t fn = 0;
                if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal))
                {
                    fn = GetRemoteProcAddress(pid, remoteModBase,
                             nullptr, (uint16_t)IMAGE_ORDINAL64(oft->u1.Ordinal), &targetModules);
                    if (!fn) { Err("  Cannot resolve %s!#%llu", dllName,
                        (unsigned long long)IMAGE_ORDINAL64(oft->u1.Ordinal)); ++failed; }
                }
                else
                {
                    auto* ibn = RvaToVa<IMAGE_IMPORT_BY_NAME>(
                        img.data(), (uint32_t)oft->u1.AddressOfData);
                    fn = GetRemoteProcAddress(pid, remoteModBase, ibn->Name, 0, &targetModules);
                    if (!fn) { Err("  Cannot resolve %s!%s", dllName, ibn->Name); ++failed; }
                }
                iat->u1.Function = (ULONGLONG)fn;
                if (fn) ++resolved;
            }
            Log("  IAT: %s  ok=%d  fail=%d  base=0x%llX",
                dllName, resolved, failed, (unsigned long long)remoteModBase);
        }
        Log("Import table resolved");
    }

    // ── Collect TLS callbacks ─────────────────────────────────
    auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress)
    {
        auto* tls = RvaToVa<IMAGE_TLS_DIRECTORY64>(img.data(), tlsDir.VirtualAddress);
        if (tls->AddressOfCallBacks)
        {
            int64_t cbOff = (int64_t)(tls->AddressOfCallBacks - preferredBase);
            if (cbOff >= 0 && (size_t)cbOff + 8 <= imageSize)
            {
                auto* cbArr = reinterpret_cast<uint64_t*>(img.data() + cbOff);
                for (; *cbArr; ++cbArr)
                {
                    uint64_t newVA = *cbArr + (uint64_t)deltaCode;
                    tlsCallbacks.push_back(newVA);
                    *cbArr = newVA;
                }
            }
        }
        // Capture TLS raw-data template BEFORE adjusting absolute VAs.
        // The static CRT stores all per-thread state in TLS; without a valid
        // data pointer for the executing thread the CRT's _getptd() returns
        // NULL and crashes on the first CRT call.  We copy the template here
        // so the shellcode can call TlsSetValue(slot, copy) right after TlsAlloc.
        if (outTlsTemplate && tls->StartAddressOfRawData && tls->EndAddressOfRawData &&
            tls->EndAddressOfRawData > tls->StartAddressOfRawData)
        {
            int64_t  startRva = (int64_t)(tls->StartAddressOfRawData - preferredBase);
            uint64_t rawSize  = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
            if (startRva >= 0 && (size_t)startRva + rawSize <= imageSize)
            {
                outTlsTemplate->assign(img.data() + startRva,
                                       img.data() + startRva + rawSize);
                if (outTlsZeroFill) *outTlsZeroFill = tls->SizeOfZeroFill;
            }
        }
        if (tls->AddressOfCallBacks)
            tls->AddressOfCallBacks    += (uint64_t)deltaCode;
        if (tls->StartAddressOfRawData) tls->StartAddressOfRawData += (uint64_t)deltaCode;
        if (tls->EndAddressOfRawData)   tls->EndAddressOfRawData   += (uint64_t)deltaCode;
        if (tls->AddressOfIndex)        tls->AddressOfIndex        += (uint64_t)deltaData;
        if (outTlsIndexAddr && tls->AddressOfIndex) *outTlsIndexAddr = tls->AddressOfIndex;
        Log("TLS directory patched  callbacks=%zu  indexAddr=0x%llX",
            tlsCallbacks.size(), outTlsIndexAddr ? *outTlsIndexAddr : 0ULL);
    }

    // ── Entry point ───────────────────────────────────────────
    *outEntryPoint = nullptr;
    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        *outEntryPoint = reinterpret_cast<uint8_t*>(
            codeBase + nt->OptionalHeader.AddressOfEntryPoint);
    }

    // Patch ImageBase in the in-memory headers to the actual code base
    auto* patchedNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        img.data() + reinterpret_cast<IMAGE_DOS_HEADER*>(img.data())->e_lfanew);
    patchedNt->OptionalHeader.ImageBase = codeBase;

    // ── PE Header Wipe ────────────────────────────────────────
    // Zero the MZ / PE signature region to defeat AC signature scanning.
    // EAC/Vanguard/BattlEye all scan MEM_PRIVATE regions for MZ/PE
    // signatures; a present header at the DLL base is an instant detection.
    memset(img.data(), 0, nt->OptionalHeader.SizeOfHeaders);

    return img;
}

// ─────────────────────────────────────────────────────────────
// Step 3 – Write exception (.pdata) table
//   In 64-bit Windows, structured exception handling requires that
//   RUNTIME_FUNCTION entries be registered via RtlAddFunctionTable.
//   We add this call to the loader shellcode.
// ─────────────────────────────────────────────────────────────
// (Handled inside the loader shellcode below)

// ─────────────────────────────────────────────────────────────
// Step 4 – Build x64 loader shellcode
//
// Shellcode layout (purely position-independent):
//
//   [Prologue]
//   push rbx / push rsi / push rdi / sub rsp, 0x48  (shadow + align)
//
//   [Optional: RtlAddFunctionTable for .pdata]
//   mov rcx, pdata_ptr
//   mov rdx, count
//   mov r8,  imageBase
//   call RtlAddFunctionTable
//
//   [TLS callbacks loop – one call per callback, hardcoded]
//   foreach cb in tlsCallbacks:
//     mov rcx, imageBase
//     mov edx, 1       (DLL_PROCESS_ATTACH)
//     xor r8d, r8d
//     mov rax, cb_addr
//     call rax
//
//   [DllMain]
//   mov rcx, imageBase
//   mov edx, 1
//   xor r8d, r8d
//   mov rax, dllMain
//   call rax
//
//   [Cleanup]
//   add rsp, 0x48 / pop rdi / pop rsi / pop rbx
//   xor ecx, ecx
//   mov rax, RtlExitUserThread
//   jmp rax
// ─────────────────────────────────────────────────────────────
struct ShellcodeBuilder
{
    std::vector<uint8_t> code;

    void Emit(const void* src, size_t sz)
    {
        const auto* p = static_cast<const uint8_t*>(src);
        code.insert(code.end(), p, p + sz);
    }

    void U8 (uint8_t  v) { code.push_back(v); }
    void U32(uint32_t v) { Emit(&v, 4); }
    void U64(uint64_t v) { Emit(&v, 8); }

    // sub rsp, imm8
    void SubRsp(uint8_t imm)  { U8(0x48); U8(0x83); U8(0xEC); U8(imm); }
    // add rsp, imm8
    void AddRsp(uint8_t imm)  { U8(0x48); U8(0x83); U8(0xC4); U8(imm); }

    // mov rax, imm64
    void MovRaxImm(uint64_t v){ U8(0x48); U8(0xB8); U64(v); }
    // mov rbx, imm64
    void MovRbxImm(uint64_t v){ U8(0x48); U8(0xBB); U64(v); }
    // mov rcx, imm64
    void MovRcxImm(uint64_t v){ U8(0x48); U8(0xB9); U64(v); }
    // mov rdx, imm64
    void MovRdxImm(uint64_t v){ U8(0x48); U8(0xBA); U64(v); }
    // mov r8, imm64
    void MovR8Imm (uint64_t v){ U8(0x49); U8(0xB8); U64(v); }
    // mov r9, imm64
    void MovR9Imm (uint64_t v){ U8(0x49); U8(0xB9); U64(v); }

    // xor r8d, r8d
    void ZeroR8d() { U8(0x45); U8(0x31); U8(0xC0); }
    // xor r9d, r9d
    void ZeroR9d() { U8(0x45); U8(0x31); U8(0xC9); }
    // xor ecx, ecx
    void ZeroEcx() { U8(0x31); U8(0xC9); }
    // xor edx, edx
    void ZeroEdx() { U8(0x31); U8(0xD2); }
    // mov edx, imm32
    void MovEdxImm(uint32_t v){ U8(0xBA); U32(v); }
    // call rax
    void CallRax()  { U8(0xFF); U8(0xD0); }
    // jmp  rax
    void JmpRax()   { U8(0xFF); U8(0xE0); }

    // mov rbp, rsp  – save RSP before forced alignment
    void MovRbpRsp()    { U8(0x48); U8(0x89); U8(0xE5); }
    // and rsp, -16  – force 16-byte alignment required by x64 ABI before any CALL
    void AlignStack()   { U8(0x48); U8(0x83); U8(0xE4); U8(0xF0); }
    // mov rsp, rbp  – restore RSP to value captured by MovRbpRsp
    void RestoreStack() { U8(0x48); U8(0x89); U8(0xEC); }

    // ── Full x64 context save/restore for thread hijacking ────────
    //
    // PushAll saves (bottom→top of stack, i.e. last-pushed at low address):
    //   pushfq, rax, rcx, rdx, rbx, rbp, rsi, rdi, r8–r15  = 15 items × 8 = 120 bytes
    // AddRsp(0x28) + 15 pushes + SubRsp(0x28) = net 160 bytes → 16-byte aligned delta.
    //
    void PushAll()
    {
        U8(0x9C);                         // pushfq
        U8(0x50);                         // push rax
        U8(0x51);                         // push rcx
        U8(0x52);                         // push rdx
        U8(0x53);                         // push rbx
        U8(0x55);                         // push rbp
        U8(0x56);                         // push rsi
        U8(0x57);                         // push rdi
        U8(0x41); U8(0x50);               // push r8
        U8(0x41); U8(0x51);               // push r9
        U8(0x41); U8(0x52);               // push r10
        U8(0x41); U8(0x53);               // push r11
        U8(0x41); U8(0x54);               // push r12
        U8(0x41); U8(0x55);               // push r13
        U8(0x41); U8(0x56);               // push r14
        U8(0x41); U8(0x57);               // push r15
    }

    void PopAll()
    {
        U8(0x41); U8(0x5F);               // pop r15
        U8(0x41); U8(0x5E);               // pop r14
        U8(0x41); U8(0x5D);               // pop r13
        U8(0x41); U8(0x5C);               // pop r12
        U8(0x41); U8(0x5B);               // pop r11
        U8(0x41); U8(0x5A);               // pop r10
        U8(0x41); U8(0x59);               // pop r9
        U8(0x41); U8(0x58);               // pop r8
        U8(0x5F);                         // pop rdi
        U8(0x5E);                         // pop rsi
        U8(0x5D);                         // pop rbp
        U8(0x5B);                         // pop rbx
        U8(0x5A);                         // pop rdx
        U8(0x59);                         // pop rcx
        U8(0x58);                         // pop rax
        U8(0x9D);                         // popfq
    }

    // Epilogue: signal done by writing 1 to a separate PAGE_READWRITE page,
    // then return.
    //
    // Why ret instead of jmp origRip:
    //   When the shellcode is invoked as a user-mode APC NormalRoutine, ntdll's
    //   APC dispatcher calls it as a regular function and restores the hijacked
    //   thread's full context on return.  A simple `ret` is correct and clean.
    //   The done_flag still lives in a separate RW page so the write never
    //   touches the RX code cave.
    //
    // Emits (13 bytes):
    //   48 B8 <doneFlagAddr 8B>   mov rax, doneFlagAddr
    //   C6 00 01                  mov byte [rax], 1
    //   C3                        ret
    //
    void WriteSetDoneAndRet(uint64_t doneFlagAddr)
    {
        MovRaxImm(doneFlagAddr);       // mov rax, doneFlagAddr
        U8(0xC6); U8(0x00); U8(0x02); // mov byte [rax], 2  (done = 2, claimed = 1, free = 0)
        U8(0xC3);                      // ret
    }

    // Write a progress byte to the done_flag address without returning.
    // Used to checkpoint shellcode stages for diagnostics:
    //   3 = pdata registered, about to call DllMain
    //   4 = DllMain returned, about to write done
    // 13 bytes: mov rax, addr (10) + mov byte [rax], val (3)
    void WriteFlagByte(uint64_t flagAddr, uint8_t val)
    {
        MovRaxImm(flagAddr);          // mov rax, flagAddr
        U8(0xC6); U8(0x00); U8(val);  // mov byte [rax], val
    }
};

static std::vector<uint8_t> BuildLoaderShellcode(
    uint64_t                       imageBase,
    uint8_t*                       dllMainVA,
    const std::vector<uint64_t>&   tlsCallbacks,
    uint64_t                       pdataVA,
    uint32_t                       pdataCount,
    uint64_t                       pRtlAddFunctionTable,
    uint64_t                       doneFlagAddr, // RW page byte; 0=free,1=claimed,2=done
    uint64_t                       tlsIndexAddr = 0, // remote addr of IMAGE_TLS_DIRECTORY64::AddressOfIndex
    uint64_t                       tlsPtrPage   = 0, // remote PVOID[] array; [0]=tlsDataBuf at slot 0
    uint64_t                       tlsDataBuf   = 0) // remote RW page: copy of TLS raw-data template
{
    ShellcodeBuilder b;

    // ── Standard x64 function prologue ──────────────────────────────────────
    //
    // ntdll's KiUserApcDispatcher calls our NormalRoutine as a normal C
    // function: it saves/restores the full thread CONTEXT itself via
    // NtContinue when we return.  We must NOT push/pop extra registers or
    // realign the stack with AND, as that corrupts the dispatcher's frame.
    //
    // On entry: RSP is 16-byte aligned − 8 (return addr pushed by CALL).
    // sub rsp, 0x28 = 0x20 shadow space + 8-byte alignment pad → RSP
    // is now 16-byte aligned for every CALL inside the shellcode.
    b.SubRsp(0x28);

    // ── Atomic single-fire guard ─────────────────────────────────────────────
    // doneFlagAddr byte: 0=free, 1=claimed/running, 2=done.
    // lock cmpxchg byte [rbx], cl  (al=0 expected → cl=1 new)
    // If cmpxchg succeeds (al==0): ZF=1, jnz falls through → run DllMain.
    // If cmpxchg fails  (al!=0): ZF=0, jnz jumps → skip to loser epilogue.
    // RBX, RAX, RCX are all caller-saved in x64 Windows ABI – no callee save needed.
    b.MovRbxImm(doneFlagAddr);  // mov rbx, doneFlagAddr
    b.U8(0x31); b.U8(0xC0);    // xor eax, eax  (al = 0 = expected "free")
    b.U8(0xB1); b.U8(0x01);    // mov cl, 1     (new value = "claimed")
    b.U8(0xF0); b.U8(0x0F);    // lock cmpxchg byte [rbx], cl
    b.U8(0xB0); b.U8(0x0B);    //   ^ F0 0F B0 0B
    size_t jnzPatchPos = b.code.size();
    b.U8(0x0F); b.U8(0x85);    // jnz rel32  →  loser epilogue
    b.U32(0);                   //   placeholder; patched below

    // ── Register .pdata for structured exception handling ────────────────────
    if (pdataVA && pdataCount && pRtlAddFunctionTable)
    {
        b.MovRcxImm(pdataVA);
        b.MovRdxImm((uint64_t)pdataCount);
        b.MovR8Imm (imageBase);
        b.MovRaxImm(pRtlAddFunctionTable);
        b.CallRax();
    }

    // ── Set up structured TLS for the APC thread ───────────────────────────
    //
    // MSVC __declspec(thread) code reads TEB.ThreadLocalStoragePointer[_tls_index]
    // (gs:[0x58][_tls_index*8]).  Win32 TlsAlloc/TlsSetValue writes to
    // TEB.TlsSlots which is a DIFFERENT array — using them here was wrong.
    //
    // Correct fix:
    //   1. Write structured slot 0 directly to _tls_index (LdrpTlsList is empty
    //      so slot 0 is always available).
    //   2. If ThreadLocalStoragePointer (gs:[0x58]) is NULL (normal when
    //      LdrpNumberOfTlsEntries was 0), install our pre-populated tlsPtrPage
    //      whose element [0] already points to tlsDataBuf.
    //   3. If already non-NULL (unexpected but safe), just set element [0].
    // After this, any __declspec(thread) access in TLS callbacks or DllMain
    // reads ThreadLocalStoragePointer[0] = tlsDataBuf — no crash.
    if (tlsIndexAddr)
    {
        // mov rcx, tlsIndexAddr;  mov dword [rcx], 0
        b.MovRcxImm(tlsIndexAddr);
        b.U8(0xC7); b.U8(0x01); b.U32(0);     // slot 0
    }
    if (tlsPtrPage && tlsDataBuf)
    {
        // rax = gs:[0x58]  (ThreadLocalStoragePointer)
        b.U8(0x65); b.U8(0x48); b.U8(0x8B); b.U8(0x04); b.U8(0x25); b.U32(0x58);
        // test rax, rax
        b.U8(0x48); b.U8(0x85); b.U8(0xC0);
        // jnz .has_tlsp  (skip install if already non-NULL)
        size_t jnzTlsp = b.code.size();
        b.U8(0x75); b.U8(0);                   // jnz rel8 placeholder
        // mov rax, tlsPtrPage
        b.MovRaxImm(tlsPtrPage);
        // mov gs:[0x58], rax
        b.U8(0x65); b.U8(0x48); b.U8(0x89); b.U8(0x04); b.U8(0x25); b.U32(0x58);
        // .has_tlsp:  rax = ThreadLocalStoragePointer
        b.code[jnzTlsp + 1] = (uint8_t)(b.code.size() - (jnzTlsp + 2));
        // mov rcx, tlsDataBuf;  mov [rax], rcx  -> ThreadLocalStoragePointer[0] = tlsDataBuf
        b.MovRcxImm(tlsDataBuf);
        b.U8(0x48); b.U8(0x89); b.U8(0x08);   // mov [rax], rcx
    }

    // Stage 3: pdata registered, TLS index allocated, about to call DllMain
    if (doneFlagAddr) b.WriteFlagByte(doneFlagAddr, 3);

    // ── TLS callbacks: fn(imageBase, DLL_PROCESS_ATTACH=1, NULL) ─────────────
    for (uint64_t cb : tlsCallbacks)
    {
        b.MovRcxImm(imageBase);
        b.MovEdxImm(1);
        b.ZeroR8d();
        b.ZeroR9d();
        b.MovRaxImm(cb);
        b.CallRax();
    }

    // ── DllMain: fn(imageBase, DLL_PROCESS_ATTACH=1, NULL) ───────────────────
    if (dllMainVA)
    {
        b.MovRcxImm(imageBase);
        b.MovEdxImm(1);
        b.ZeroR8d();
        b.ZeroR9d();
        b.MovRaxImm((uint64_t)(uintptr_t)dllMainVA);
        b.CallRax();
    }
    // Stage 4: DllMain returned
    if (doneFlagAddr) b.WriteFlagByte(doneFlagAddr, 4);

    // ── Winner epilogue: undo prologue, signal done=2, return ────────────────
    // ntdll KiUserApcDispatcher restores full thread context via NtContinue
    // after we return, so a plain `ret` here is all that is needed.
    b.AddRsp(0x28);
    b.WriteSetDoneAndRet(doneFlagAddr); // mov rax, addr; mov byte [rax], 2; ret

    // ── Loser epilogue: undo prologue, return ────────────────────────────────
    // Patch the jnz rel32 to land here.
    {
        size_t skipTarget = b.code.size();
        int32_t rel = (int32_t)((ptrdiff_t)skipTarget - (ptrdiff_t)(jnzPatchPos + 6));
        memcpy(b.code.data() + jnzPatchPos + 2, &rel, sizeof(rel));
    }
    b.AddRsp(0x28);
    b.U8(0xC3); // ret

    return b.code;
}

// ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    printf("MidnightSoftware Manual Mapper  (x64, driver-only, kernel APC injection)\n");
    printf("─────────────────────────────────────────────────────────────\n\n");

    if (argc < 3)
    {
        printf("Usage: %s <ProcessName.exe> <dll_path.dll> [--threads=start|end|mid|shuffle]\n", argv[0]);
        printf("  --threads=start    iterate TIDs ascending  (lowest first)\n");
        printf("  --threads=end      iterate TIDs descending (highest first) [default]\n");
        printf("  --threads=mid      iterate TIDs from the middle outward\n");
        printf("  --threads=shuffle  iterate TIDs in random order\n");
        return 1;
    }

    const char* targetName = argv[1];
    const char* dllPath    = argv[2];

    // ── Optional --threads=<mode> flag ────────────────────────
    enum class ThreadOrder { START, END, MID, SHUFFLE };
    ThreadOrder threadOrder = ThreadOrder::END;  // default: descending
    for (int i = 3; i < argc; ++i)
    {
        const char* arg = argv[i];
        const char* prefix = "--threads=";
        if (strncmp(arg, prefix, strlen(prefix)) == 0)
        {
            const char* mode = arg + strlen(prefix);
            if      (strcmp(mode, "start")   == 0) threadOrder = ThreadOrder::START;
            else if (strcmp(mode, "end")     == 0) threadOrder = ThreadOrder::END;
            else if (strcmp(mode, "mid")     == 0) threadOrder = ThreadOrder::MID;
            else if (strcmp(mode, "shuffle") == 0) threadOrder = ThreadOrder::SHUFFLE;
            else
            {
                fprintf(stderr, "[!] Unknown --threads mode '%s'. Use start|end|mid|shuffle.\n", mode);
                return 1;
            }
        }
    }

    // ── 1. Read DLL from disk ─────────────────────────────────
    Log("Loading DLL from disk: %s", dllPath);
    auto rawFile = LoadDllFile(dllPath);
    if (rawFile.empty()) return 1;
    Log("DLL file size: %zu bytes", rawFile.size());

    // ── 2. Parse PE headers ───────────────────────────────────
    auto* nt = GetNtHeaders(rawFile.data());
    if (!nt) { Err("Not a valid x64 PE file"); return 1; }

    uint64_t preferredBase = nt->OptionalHeader.ImageBase;
    uint32_t imageSize     = nt->OptionalHeader.SizeOfImage;
    Log("DLL preferred base : 0x%llX", (unsigned long long)preferredBase);
    Log("DLL image size     : 0x%X", imageSize);
    Log("DLL entry point RVA: 0x%X", nt->OptionalHeader.AddressOfEntryPoint);

    // ── 3. Open MidnightSoftware driver and find PID ─────────────────────
    Log("Opening MidnightSoftware driver...");
    if (!DrvOpen())
    {
        Err("Cannot open \\\\.\\DXGKrnl (err=%lu). Is the driver loaded?",
            GetLastError());
        return 1;
    }
    Log("Driver: OK");

    Log("Searching for process: %s", targetName);
    uint64_t pid = DrvFindPid(targetName);
    if (!pid)
    {
        Err("Process '%s' not found", targetName);
        CloseHandle(g_hDev);
        return 1;
    }
    Log("Found PID: %llu", (unsigned long long)pid);

    // ── 4. Allocate payload region in the target process (Ring-0) ───────────
    //
    // All memory allocation is performed through DrvAllocMem, which uses a
    // kernel-mode handle (OBJ_KERNEL_HANDLE + KernelMode) opened inside the
    // driver.  ObRegisterCallbacks AC callbacks are NOT invoked for kernel-mode
    // handle operations, so PROCESS_VM_OPERATION / PROCESS_VM_WRITE stripping
    // is completely bypassed.
    //
    // MEM_IMAGE module stomping is explicitly abandoned (Requirement 3):
    //   Anti-cheats periodically hash the physical pages backing MEM_IMAGE
    //   regions and compare against the on-disk signature.  Any modification
    //   to DLL padding/code caves triggers a hash mismatch -> ban.
    //
    // CFG (SetProcessValidCallTargets) sourced from this process is NOT called
    // (Requirement 5): calling SPVCT on a protected process from an external,
    // unsigned user-mode process is itself a high-confidence detection signal.
    //
    // RWX is deliberately avoided (UC consensus / EAC+Vanguard detection):
    //   MEM_PRIVATE pages with simultaneous Write+Execute (PAGE_EXECUTE_READWRITE)
    //   are the #1 AC heuristic for manual mappers.  We allocate as PAGE_READWRITE,
    //   write all sections, then call DrvProtectMem once per section to apply the
    //   correct per-section protection (RX / RO / RW).  The resulting VAD layout
    //   is indistinguishable from a normally loaded module.

    // ldrEntryAddr: remote VA of the REMOTE_LDR_ENTRY inserted into PEB Ldr
    // (step 8.5).  Used after DllMain completes to patch in the real TLS slot.
    uint64_t ldrEntryAddr = 0;

    uint64_t targetBase = DrvAllocMem(pid, preferredBase, imageSize,
                                      PAGE_READWRITE);
    if (!targetBase)
    {
        Log("Preferred base 0x%llX busy - allocating anywhere",
            (unsigned long long)preferredBase);
        targetBase = DrvAllocMem(pid, 0, imageSize, PAGE_READWRITE);
    }
    if (!targetBase)
    {
        Err("DrvAllocMem (DLL image) failed");
        CloseHandle(g_hDev);
        return 1;
    }
    Log("DLL image allocated in target via driver: 0x%llX  size=0x%X",
        (unsigned long long)targetBase, imageSize);

    // rwBase = 0 -> BuildMappedImage uses a single delta for all sections.
    uint64_t rwBase = 0;

    Log("imageBase = 0x%llX  imageSize = 0x%X",
        (unsigned long long)targetBase,
        imageSize);

    // ── 5. Capture section layout BEFORE BuildMappedImage wipes headers ──
    struct SecInfo {
        uint32_t rva;
        uint32_t vlen;
        DWORD    chars;
    };
    std::vector<SecInfo> sectionInfo;
    {
        auto* s = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            uint32_t vlen = s[i].Misc.VirtualSize
                          ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
            if (!vlen) continue;
            sectionInfo.push_back({ s[i].VirtualAddress, vlen, s[i].Characteristics });
        }
    }

    // ── 6. Build target module map name -> remote base ────────────────────
    // Populated via DrvEnumMods (PEB Ldr walk at Ring-0 - no process handle).
    // Replaces CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) which requires
    // PROCESS_VM_READ on the target to read its module list from user-mode.
    std::unordered_map<std::string, uint64_t> targetModules;
    if (!DrvEnumMods(pid, targetModules))
    {
        Err("DrvEnumMods failed - IAT resolution may be incomplete");
        // Non-fatal: proceed with whatever modules were enumerated.
    }
    Log("Target modules indexed: %zu", targetModules.size());

    // ── 7. Build mapped image (relocs + remote IAT + TLS) ────────────────
    uint8_t*              entryPointVA = nullptr;
    uint64_t              tlsIndexAddr = 0;     // remote VA of _tls_index DWORD
    std::vector<uint64_t> tlsCallbacks;
    std::vector<uint8_t>  tlsTemplate;           // local copy of TLS raw-data template
    uint32_t              tlsZeroFill  = 0;      // IMAGE_TLS_DIRECTORY64::SizeOfZeroFill
    auto mapped = BuildMappedImage(rawFile.data(), nt,
                                   pid, targetBase, rwBase,
                                   &entryPointVA, tlsCallbacks,
                                   targetModules, &tlsIndexAddr,
                                   &tlsTemplate, &tlsZeroFill);
    if (tlsIndexAddr)
        Log("TLS index remote VA    : 0x%llX", (unsigned long long)tlsIndexAddr);
    if (!tlsTemplate.empty())
        Log("TLS template size      : %zu bytes + %u zero-fill",
            tlsTemplate.size(), tlsZeroFill);
    if (mapped.empty()) { Err("BuildMappedImage failed"); goto cleanup; }

    // ── 8. Write image sections to target ─────────────────────────────────
    //
    // The pages were committed by DrvAllocMem with MEM_COMMIT|MEM_RESERVE and
    // PAGE_READWRITE.  WriteMemoryCr3 in the driver walks the physical page
    // tables directly, so the PTE protection bits do not block writes here.
    Log("Writing image sections via MidnightSoftware driver...");
    for (auto& s : sectionInfo)
    {
        uint64_t writeVA      = targetBase + s.rva;
        bool     ok           = true;
        size_t   bytesWritten = 0;
        while (bytesWritten < s.vlen)
        {
            size_t chunk = std::min<size_t>(4096, s.vlen - bytesWritten);
            if (!DrvWriteMem(pid, writeVA + bytesWritten,
                             mapped.data() + s.rva + bytesWritten, chunk))
            {
                Err("DrvWriteMem section RVA=0x%X failed at offset %zu - aborting",
                    s.rva, bytesWritten);
                ok = false;
                break;
            }
            bytesWritten += chunk;
        }
        if (!ok) goto cleanup;
    }
    Log("Image sections written: %zu sections OK", sectionInfo.size());

    // ── 8a. Re-protect sections to per-section PAGE_* (eliminate RWX) ─────────
    //
    // All bytes are written.  Now change each section's protection from the
    // initial PAGE_READWRITE to the value dictated by its PE characteristics.
    // The resulting VAD layout mirrors a normally loaded module:
    //   .text / code  ->  PAGE_EXECUTE_READ
    //   .rdata        ->  PAGE_READONLY
    //   .data / .bss  ->  PAGE_READWRITE
    //
    // This eliminates the RWX red flag that EAC/Vanguard detect by walking
    // the VAD tree for MEM_PRIVATE pages with simultaneous W+X permissions.
    Log("Re-protecting sections (RWX elimination)...");
    {
        size_t protOk = 0;
        for (auto& s : sectionInfo)
        {
            ULONG prot = SectionCharsToProtect(s.chars);
            if (prot == PAGE_NOACCESS) continue;
            uint64_t secVA   = targetBase + s.rva;
            size_t   secSize = (s.vlen + 0xFFFu) & ~(size_t)0xFFFu;
            if (DrvProtectMem(pid, secVA, secSize, prot))
                ++protOk;
            else
                Err("DrvProtectMem RVA=0x%X prot=0x%X failed (non-fatal)",
                    s.rva, prot);
        }
        Log("Section re-protection: %zu/%zu sections OK",
            protOk, sectionInfo.size());
    }

    // ── 8.5  PEB Linking ───────────────────────────────────────────────────────
    //
    // Insert a fake LDR_DATA_TABLE_ENTRY into the target process's PEB Ldr
    // lists BEFORE executing the shellcode / DllMain.  This ensures that any
    // new threads spawned by the injected DLL (e.g. std::thread inside DllMain)
    // have their TLS block allocated by the Windows thread-creation path
    // (LdrpAllocateTls), preventing heap corruption that causes crashes in
    // unrelated modules such as X3DAudio1_7.dll.
    {
        // Convert dllPath (narrow) to wide strings for UNICODE_STRING fields.
        wchar_t wFullPath[MAX_PATH] = {};
        MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wFullPath, MAX_PATH);

        // Extract just the filename portion.
        wchar_t wBaseName[MAX_PATH] = {};
        const wchar_t* slash = wcsrchr(wFullPath, L'\\');
        if (!slash) slash = wcsrchr(wFullPath, L'/');
        wcscpy_s(wBaseName, slash ? slash + 1 : wFullPath);

        // entryPointVA stores the remote VA as a pointer (see BuildMappedImage).
        uint64_t epVA = (uint64_t)(uintptr_t)entryPointVA;

        ldrEntryAddr = PebLinkModule(pid, targetBase, epVA, imageSize, wFullPath, wBaseName);
        if (!ldrEntryAddr)
            Log("PebLinkModule failed or was skipped – TLS may not be allocated"
                " for threads created by the injected DLL");
        else
            PebHashLinkModule(pid, ldrEntryAddr, wBaseName, targetModules);
    }

    // CFG registration (SetProcessValidCallTargets) REMOVED - Requirement 5.
    // Calling SPVCT from an external unsigned process is a high-confidence IoC.
    // The kernel-allocated MEM_PRIVATE RWX region is CFG-exempt on
    // FORCE_INTEGRITY-free processes (the documented threat-model target).

    // ── 9. .pdata location ────────────────────────────────────────────────
    // ldrEntryAddr: remote VA of the REMOTE_LDR_ENTRY we inserted into PEB Ldr.
    // Set in step 8.5; used post-DllMain to patch in the real TLS slot index.
    // ldrEntryAddr is declared above (before targetBase) so step 8.5 can use it.

    uint64_t pdataVA    = 0;
    uint32_t pdataCount = 0;
    {
        auto& exDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exDir.VirtualAddress && exDir.Size)
        {
            pdataVA    = targetBase + exDir.VirtualAddress;
            pdataCount = exDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
            Log(".pdata: VA=0x%llX  count=%u",
                (unsigned long long)pdataVA, pdataCount);
        }
    }

    // ── 10. Kernel APC injection ──────────────────────────────────────────
    //
    // Requirements 1, 2, 4, 5:
    //   Shellcode + done_flag: allocated via DrvAllocMem (kernel OBJ_KERNEL_HANDLE,
    //   no ring-3 OpenProcess or VirtualAllocEx).
    //   Thread alerting: driver QUEUE_APC handler calls KeAlertThread(UserMode)
    //   after KeInsertQueueApc - no OpenThread/NtAlertThread from ring-3.
    //   CFG: SetProcessValidCallTargets NOT called.
    {
        uint64_t pRtlAddFunctionTable = (uint64_t)(uintptr_t)
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddFunctionTable");

        // ── Allocate structured TLS data buffer + ThreadLocalStoragePointer page ──
        //
        // MSVC __declspec(thread) accesses TEB.ThreadLocalStoragePointer[_tls_index],
        // NOT TEB.TlsSlots (Win32 TlsAlloc target).  For existing threads when
        // LdrpTlsList was empty, ThreadLocalStoragePointer is NULL because
        // LdrpAllocateTls skips allocation when LdrpNumberOfTlsEntries == 0.
        //
        // Fix:
        //   tlsDataBuf  = copy of the TLS raw-data template (per-thread state)
        //   tlsPtrPage  = remote PVOID[16] array, element[0] = tlsDataBuf
        // The shellcode installs tlsPtrPage as gs:[0x58] (ThreadLocalStoragePointer)
        // before running TLS callbacks / DllMain, so every __declspec(thread)
        // dereference gets a valid non-NULL pointer.
        // Both pages must remain alive for the process lifetime (never freed).
        uint64_t tlsDataBuf = 0;
        uint64_t tlsPtrPage = 0;
        if (!tlsTemplate.empty())
        {
            size_t bufSize = tlsTemplate.size() + (size_t)tlsZeroFill;
            tlsDataBuf = DrvAllocMem(pid, 0, (bufSize < 16 ? 16 : bufSize), PAGE_READWRITE);
            if (tlsDataBuf)
            {
                DrvWriteMem(pid, tlsDataBuf, tlsTemplate.data(), tlsTemplate.size());
                // Zero-fill bytes are already zeroed by MEM_COMMIT.
                Log("TLS data buffer        : 0x%llX  size=%zu+%u",
                    (unsigned long long)tlsDataBuf,
                    tlsTemplate.size(), tlsZeroFill);
                // Allocate the ThreadLocalStoragePointer array (16 slots, zero-filled).
                // Pre-set slot 0 = tlsDataBuf so the shellcode can just write the page
                // address into gs:[0x58] without needing any runtime calculation.
                tlsPtrPage = DrvAllocMem(pid, 0, 16 * sizeof(uint64_t), PAGE_READWRITE);
                if (tlsPtrPage)
                {
                    DrvWriteMem(pid, tlsPtrPage, &tlsDataBuf, sizeof(tlsDataBuf));
                    Log("TLS ptr page           : 0x%llX  [0]=0x%llX",
                        (unsigned long long)tlsPtrPage, (unsigned long long)tlsDataBuf);
                }
            }
        }

        // ── Pre-injection TLS linking ───────────────────────────────────────
        // CRITICAL ORDER: LinkTlsEntry MUST run before the APC shellcode fires.
        //
        // DllMain often creates threads (e.g. Dumper-7 scanner threads).
        // Each new thread calls LdrpAllocateTls which allocates a
        // ThreadLocalStoragePointer array of LdrpNumberOfTlsEntries slots.
        // If LinkTlsEntry has not run yet, LdrpNumberOfTlsEntries == 0, so
        // LdrpAllocateTls skips allocation entirely and leaves
        // ThreadLocalStoragePointer NULL.  The first __declspec(thread)
        // access from any DllMain-spawned thread then crashes.
        //
        // By linking TLS first:
        //  - LdrpNumberOfTlsEntries = 1
        //  - LdrpTlsList has our REMOTE_TLS_ENTRY (template + slot 0)
        //  - New threads get ThreadLocalStoragePointer[0] = fresh template copy
        if (ldrEntryAddr && tlsIndexAddr)
        {
            auto& tlsDirEntry =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            uint64_t tlsStart = 0, tlsEnd = 0, tlsCallbacksVA = 0;
            uint32_t tlsZFill = 0, tlsChars = 0;
            if (tlsDirEntry.VirtualAddress)
            {
                IMAGE_TLS_DIRECTORY64 rTls{};
                if (DrvReadMem(pid,
                               targetBase + tlsDirEntry.VirtualAddress,
                               &rTls, sizeof(rTls)))
                {
                    tlsStart       = rTls.StartAddressOfRawData;
                    tlsEnd         = rTls.EndAddressOfRawData;
                    tlsZFill       = rTls.SizeOfZeroFill;
                    tlsChars       = rTls.Characteristics;
                    tlsCallbacksVA = rTls.AddressOfCallBacks;
                }
            }
            LinkTlsEntry(pid, targetModules, ldrEntryAddr, tlsIndexAddr,
                         tlsStart, tlsEnd, tlsCallbacksVA, tlsZFill, tlsChars);
        }

        // Probe shellcode size
        auto sizeProbe = BuildLoaderShellcode(
            targetBase, entryPointVA, tlsCallbacks,
            pdataVA, pdataCount,
            pRtlAddFunctionTable, 1,
            tlsIndexAddr, tlsPtrPage, tlsDataBuf);
        size_t scSize = sizeProbe.size();
        Log("Shellcode size: %zu bytes", scSize);

        // ── a. Allocate shellcode page via driver (Ring-0, no process handle) ─
        // Allocate as PAGE_READWRITE so the driver can write bytes into it,
        // then re-protect to PAGE_EXECUTE_READ before queueing the APC.
        // A PAGE_EXECUTE_READWRITE shellcode page is a standalone bannable
        // signal (W+X MEM_PRIVATE); PAGE_EXECUTE_READ is the norm for code.
        uint64_t scRemoteAddr = DrvAllocMem(pid, 0, scSize, PAGE_READWRITE);
        if (!scRemoteAddr)
        {
            Err("DrvAllocMem (shellcode) failed - aborting");
            if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
            if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
            goto cleanup;
        }
        Log("Shellcode page (RW, Ring-0 alloc): 0x%llX", (unsigned long long)scRemoteAddr);

        // ── b. Allocate done_flag page via driver (Ring-0, no process handle) ─
        uint64_t doneFlagAddr = DrvAllocMem(pid, 0, 8, PAGE_READWRITE);
        if (!doneFlagAddr)
        {
            Err("DrvAllocMem (done_flag) failed - aborting");
            DrvFreeMem(pid, scRemoteAddr);
            if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
            if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
            goto cleanup;
        }
        Log("done_flag page (RW, Ring-0 alloc): 0x%llX", (unsigned long long)doneFlagAddr);

        // ── c. Build + write shellcode directly via driver ────────────────────
        auto shellcode = BuildLoaderShellcode(
            targetBase, entryPointVA, tlsCallbacks,
            pdataVA, pdataCount,
            pRtlAddFunctionTable, doneFlagAddr,
            tlsIndexAddr, tlsPtrPage, tlsDataBuf);

        if (!DrvWriteMem(pid, scRemoteAddr, shellcode.data(), shellcode.size()))
        {
            Err("DrvWriteMem (shellcode) failed - aborting");
            DrvFreeMem(pid, scRemoteAddr);
            DrvFreeMem(pid, doneFlagAddr);
            if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
            if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
            goto cleanup;
        }
        Log("Shellcode written via driver: OK");

        // Re-protect shellcode page from PAGE_READWRITE to PAGE_EXECUTE_READ.
        // Must happen BEFORE APC delivery so the executed code is never W+X.
        if (!DrvProtectMem(pid, scRemoteAddr,
                           (scSize + 0xFFFu) & ~(size_t)0xFFFu,
                           PAGE_EXECUTE_READ))
            Err("DrvProtectMem (shellcode -> RX) failed (non-fatal, page is still callable)");
        else
            Log("Shellcode page re-protected: PAGE_READWRITE -> PAGE_EXECUTE_READ");

        // ── d. Smart sequential APC spray ────────────────────────────────────
        //
        // Broadcast APC to every thread simultaneously causes audio/XAudio
        // threads to crash when force-woken (EXCEPTION_ACCESS_VIOLATION inside
        // X3DAudio1_7.dll).  Instead we iterate through threads in ascending
        // TID order (lower TIDs = older, generally PoolThreads that sleep in
        // an alertable wait) and stop as soon as any thread picks up the APC.
        //
        // Per-thread mini-wait: 200 ms.  The shellcode writes done_flag=1 the
        // instant it starts, so we detect uptake long before DllMain finishes.
        // The cmpxchg guard in the shellcode prevents double-execution even if
        // a stray APC from an earlier attempt fires late.
        {
            // Collect TIDs.
            HANDLE hTSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hTSnap == INVALID_HANDLE_VALUE)
            {
                Err("CreateToolhelp32Snapshot failed (err=%lu)", GetLastError());
                DrvFreeMem(pid, scRemoteAddr);
                DrvFreeMem(pid, doneFlagAddr);
                if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
                if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
                goto cleanup;
            }
            std::vector<DWORD> tids;
            {
                THREADENTRY32 te{}; te.dwSize = sizeof(te);
                if (Thread32First(hTSnap, &te))
                    do {
                        if (te.th32OwnerProcessID == (DWORD)pid &&
                            te.th32ThreadID != GetCurrentThreadId())
                            tids.push_back(te.th32ThreadID);
                    } while (Thread32Next(hTSnap, &te));
            }
            CloseHandle(hTSnap);

            if (tids.empty())
            {
                Err("No threads found in PID %llu", (unsigned long long)pid);
                DrvFreeMem(pid, scRemoteAddr);
                DrvFreeMem(pid, doneFlagAddr);
                if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
                if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
                goto cleanup;
            }

            // Order threads according to --threads mode.
            const char* orderLabel = "descending (end)";
            switch (threadOrder)
            {
            case ThreadOrder::START:
                std::sort(tids.begin(), tids.end());  // ascending
                orderLabel = "ascending (start)";
                break;
            case ThreadOrder::END:
                std::sort(tids.begin(), tids.end(), std::greater<DWORD>());  // descending
                orderLabel = "descending (end)";
                break;
            case ThreadOrder::MID:
            {
                // Sort ascending first, then reorder: mid, mid-1, mid+1, mid-2, mid+2 ...
                std::sort(tids.begin(), tids.end());
                std::vector<DWORD> reordered;
                reordered.reserve(tids.size());
                int lo = (int)tids.size() / 2;
                int hi = lo;
                // include the center element once
                reordered.push_back(tids[lo]);
                --lo; ++hi;
                while (lo >= 0 || hi < (int)tids.size())
                {
                    if (hi < (int)tids.size()) reordered.push_back(tids[hi++]);
                    if (lo >= 0)               reordered.push_back(tids[lo--]);
                }
                tids = std::move(reordered);
                orderLabel = "from middle outward (mid)";
                break;
            }
            case ThreadOrder::SHUFFLE:
            {
                std::mt19937 rng(std::random_device{}());
                std::shuffle(tids.begin(), tids.end(), rng);
                orderLabel = "random (shuffle)";
                break;
            }
            }
            Log("Smart APC spray: %zu threads, order: %s", tids.size(), orderLabel);

            // ── Spray loop ───────────────────────────────────────────────────
            uint8_t flag    = 0;
            bool    claimed = false;
            for (DWORD t : tids)
            {
                if (!DrvQueueApc(pid, t, scRemoteAddr))
                {
                    Log("  TID %lu: DrvQueueApc failed - skipping", t);
                    continue;
                }
                Log("  TID %lu: APC queued, waiting up to 200 ms...", t);

                // Mini-wait: poll every 5 ms for up to 200 ms.
                DWORD miniDeadline = GetTickCount() + 200;
                while (GetTickCount() < miniDeadline)
                {
                    flag = 0;
                    if (DrvReadMem(pid, doneFlagAddr, &flag, 1) && flag >= 1)
                        break;
                    Sleep(5);
                }

                if (flag >= 1)
                {
                    Log("  TID %lu: shellcode started (flag=%u) - stopping spray", t, flag);
                    claimed = true;
                    break;
                }
                // Thread did not enter alertable state in time; try next one.
                Log("  TID %lu: no response - trying next thread", t);
            }

            if (!claimed)
            {
                Err("Timeout: no thread entered an alertable state to execute the APC");
                DrvFreeMem(pid, scRemoteAddr);
                DrvFreeMem(pid, doneFlagAddr);
                if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
                if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
                goto cleanup;
            }

            // ── e. Full completion wait (30 s) ───────────────────────────────
            Log("Polling done_flag at 0x%llX for DllMain completion (timeout 30 s)...",
                (unsigned long long)doneFlagAddr);
            bool    done     = false;
            uint8_t lastFlag = flag; // already >= 1 from spray loop
            DWORD   deadline = GetTickCount() + 30000;
            while (GetTickCount() < deadline)
            {
                uint8_t cur = 0;
                if (DrvReadMem(pid, doneFlagAddr, &cur, 1))
                {
                    if (cur != lastFlag)
                    {
                        const char* stageName =
                            cur == 1 ? "shellcode claimed" :
                            cur == 3 ? "pdata registered, calling DllMain" :
                            cur == 4 ? "DllMain returned, writing done" :
                            cur == 2 ? "done" : "unknown";
                        Log("done_flag progress: %u (%s)", cur, stageName);
                        lastFlag = cur;
                    }
                    if (cur == 2) { done = true; break; }
                }
                Sleep(10);
            }

            if (done)
                Log("DllMain completed - done_flag set");
            else
            {
                Err("Timeout: DllMain did not complete within 30 s (last flag=%u)", lastFlag);
                DrvFreeMem(pid, scRemoteAddr);
                DrvFreeMem(pid, doneFlagAddr);
                if (tlsDataBuf) DrvFreeMem(pid, tlsDataBuf);
                if (tlsPtrPage) DrvFreeMem(pid, tlsPtrPage);
                goto cleanup;
            }

            // TLS was linked before injection; nothing to do here.
        }

        // ── Shellcode / done_flag pages: kept alive intentionally ──────────────
        //
        // The APC spray queues APCs to every thread it tries before one claims
        // the shellcode.  Threads that showed "no response" still have the APC
        // pending in the kernel; they will fire it when they next enter an
        // alertable wait (SleepEx, WaitForSingleObjectEx, etc.).
        //
        // If we free scRemoteAddr or doneFlagAddr here, those late-firing APCs
        // land on decommitted pages.  The very first instruction of the shellcode
        // is  lock cmpxchg byte [doneFlagAddr], cl  which access-violates on the
        // freed page → unhandled exception in the game thread → process crash.
        //
        // Fix: leave both pages mapped.  The shellcode's atomic guard handles
        // the repeated-fire case correctly:
        //   cmpxchg sees done_flag == 2 ≠ 0  →  ZF=0  →  jnz loser_epilogue
        //   loser epilogue: add rsp, 0x28 ; ret   (returns safely, no work done)
        // No crash, no double-DllMain, no resource leak beyond two permanent pages.
        //
        // The shellcode page (PAGE_EXECUTE_READ) and done_flag page (PAGE_READWRITE)
        // are both committed for the process lifetime.
        Log("Shellcode page kept    : 0x%llX  (pending-APC loser-epilogue safety)",
            (unsigned long long)scRemoteAddr);
        Log("done_flag page kept    : 0x%llX  (pending-APC loser-epilogue safety)",
            (unsigned long long)doneFlagAddr);

        if (tlsDataBuf)
            Log("TLS data buffer kept   : 0x%llX  (ThreadLocalStoragePointer[0])",
                (unsigned long long)tlsDataBuf);
        if (tlsPtrPage)
            Log("TLS ptr page kept      : 0x%llX  (gs:[0x58] for APC thread)",
                (unsigned long long)tlsPtrPage);
    }

    printf("\n[+] ======================================\n");
    printf("[+]  DLL mapped successfully into PID %llu\n", (unsigned long long)pid);
    printf("[+]  Image base: 0x%llX\n",  (unsigned long long)targetBase);
    printf("[+]  Entry pt  : 0x%llX\n",  (unsigned long long)(uintptr_t)entryPointVA);
    printf("[+] ======================================\n\n");

    CloseHandle(g_hDev);
    return 0;

cleanup:
    // Only free the DLL image allocation if injection was not completed.
    // Shellcode and done_flag allocations are left alive (loser APC safety).
    if (targetBase) DrvFreeMem(pid, targetBase);
    CloseHandle(g_hDev);
    return 1;
}
