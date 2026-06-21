#pragma once
#include "includes.hpp"
#include "kvc_session.hpp"
#include "dse_bypass.hpp"
#include "log.hpp"
#include "VMProtectSDK.h"   // VMProtect 3.x SDK

//=============================================================================
//  driver_mgr.hpp  –  Full kvc-integrated kernel driver load / unload
//
//  Mirrors kvc-main ControllerDriverLoader.cpp exactly:
//    • load_driver()             ≙  LoadExternalDriver()
//    • reload_driver()           ≙  ReloadExternalDriver()
//    • stop_driver()             ≙  StopExternalDriver()
//    • unload_driver()           ≙  RemoveExternalDriver()
//    • normalize_driver_path()   ≙  NormalizeDriverPath()
//    • check_hvci()              ≙  CheckAndHandleHVCI() (detection only)
//
//  Default DSE bypass method: Method::Safe (SeCiCallbacks / PDB-based)
//    STEP 1 – DSE disable:  kvc BeginSession → dse.Disable(Safe) → EndSession
//    STEP 2 – SCM load:     CreateService / StartService
//    STEP 3 – DSE restore:  kvc BeginSession → dse.Restore(Safe) → EndSession
//
//  NOTE: Requires Administrator privileges.
//=============================================================================

namespace driver_mgr {

//─────────────────────────────────────────────── result codes ─────────────────
enum class Result : uint32_t {
    OK,
    ERR_FILE_NOT_FOUND,   // .sys path does not exist
    ERR_SC_CONNECT,       // OpenSCManagerW failed
    ERR_SVC_CREATE,       // CreateServiceW failed
    ERR_SVC_OPEN,         // OpenServiceW failed (during stop/delete)
    ERR_SVC_START,        // StartServiceW failed
    ERR_SVC_STOP,         // ControlService STOP failed
    ERR_SVC_DELETE,       // DeleteService failed
    ERR_KVC_SESSION,      // kvc.sys BeginSession failed
    ERR_DSE_DISABLE,      // dse_bypass::Disable() failed
    ERR_DSE_RESTORE,      // dse_bypass::Restore() failed
};

struct OpResult {
    Result   code    = Result::OK;
    DWORD    win_err = 0;            // GetLastError() at point of failure
    std::wstring message;            // human-readable description
};

//─────────────────────────────────────────────── helpers ──────────────────────

// Derive a short service name from the .sys filename stem.
// e.g. L"C:\\path\\to\\MidnightSoftwareDriver.sys" → L"MidnightSoftwareDriver"
inline std::wstring svc_name_from_path( const std::wstring& sys_path )
{
    return std::filesystem::path( sys_path ).stem().wstring();
}

// Format a Win32 error code as a UTF-16 string.
inline std::wstring format_win_error( DWORD code )
{
    wchar_t* buf = nullptr;
    if ( !FormatMessageW( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                          FORMAT_MESSAGE_IGNORE_INSERTS,
                          nullptr, code,
                          MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                          reinterpret_cast<LPWSTR>( &buf ), 0, nullptr ) )
        return std::format( L"error 0x{:08X}", code );
    std::wstring s( buf );
    LocalFree( buf );
    // trim trailing \r\n
    while ( !s.empty() && ( s.back() == L'\n' || s.back() == L'\r' ) )
        s.pop_back();
    return s;
}

//─────────────────────────────────────────────── DSE note ───────────────────
//
//  kvc uses a two-step sequence BEFORE calling SCM:
//    1. Opens its own kvc.sys kernel device (CreateFileW on device path)
//    2. m_dseBypass->Disable(Safe) → patches g_CiOptions in kernel via IOCTL
//       (RTC_MEMORY_READ / RTC_MEMORY_WRITE structs sent to kvc.sys)
//    3. EndDriverSession() → closes kvc.sys handle BEFORE any SCM call
//    4. SCM load (below)
//    5. RAII guard → m_dseBypass->Restore(Safe) → repatch g_CiOptions back
//
//  This is ONLY needed for UNSIGNED drivers.
//  When skip_dse=true (test-signed driver / bcdedit /set testsigning on),
//  kvc_session is never touched.
//
//─────────────────────────────────────────────── helpers ─────────────────────

// ── normalize_driver_path ─────────────────────────────────────────────────────
//  Mirrors kvc ControllerDriverLoader::NormalizeDriverPath() exactly.
//  If input contains a backslash or colon (absolute/relative path):
//    - Appends ".sys" if missing, then returns as-is.
//  If input is a bare filename (no slash or colon):
//    - Appends ".sys" if missing, prepends %SystemRoot%\System32\drivers
inline std::wstring normalize_driver_path( const std::wstring& input )
{
    auto to_lower = []( std::wstring s ) -> std::wstring {
        for ( auto& c : s ) c = static_cast<wchar_t>( ::towlower( c ) );
        return s;
    };

    auto ensure_sys = [&]( std::wstring p ) -> std::wstring {
        if ( p.size() < 4 ||
             to_lower( p.substr( p.size() - 4 ) ) != L".sys" )
            p += L".sys";
        return p;
    };

    // Absolute/relative path: leave as-is, just fix extension
    if ( input.find( L'\\' ) != std::wstring::npos ||
         input.find( L':'  ) != std::wstring::npos )
        return ensure_sys( input );

    // Bare name: expand to "%SystemRoot%\system32\drivers"
    wchar_t sysDir[MAX_PATH]{};
    ::GetSystemDirectoryW( sysDir, MAX_PATH );
    return std::wstring( sysDir ) + L"\\drivers\\" + ensure_sys( input );
}

// ── check_hvci ────────────────────────────────────────────────────────────────
//  Mirrors kvc CheckAndHandleHVCI() detection side only (no reboot prompt).
//  BeginSession → GetStatus → HVCI flag → EndSession.
//  Returns true when Memory Integrity is DISABLED (safe to use Method::Standard).
//  Returns false when HVCI enabled OR kvc session failed.
//  NOTE: When using Method::Safe (default), HVCI state does NOT block loading.
inline bool check_hvci( const std::wstring& kvc_sys_path = L"" ) noexcept
{
    std::wstring kvc_path = kvc_sys_path.empty()
                          ? kvc_session::FindKvcSys()
                          : kvc_sys_path;
    if ( kvc_path.empty() ) return false;

    kvc_session::Session ses{};
    if ( !kvc_session::BeginSession( ses, kvc_path ) ) return false;

    dse_bypass::Status st;
    const bool got = ses.dse.GetStatus( st );
    kvc_session::EndSession( ses, true );

    if ( !got ) return false;
    return !st.hvciEnabled;   // true = HVCI off = safe for Standard method
}

//─────────────────────────────────────────────── stop_driver ─────────────────
//
//  Mirrors kvc StopExternalDriver() exactly.
//  Stops the service if running, does NOT delete it.
//
__declspec(noinline) inline OpResult stop_driver( const std::wstring& svc_name )
{
    VMProtectBeginUltra( "stop_driver" );
    if ( !kvc_session::g_pOpenSCManagerW ) {
        if ( !kvc_session::InitDynamicAPIs() ) {
            VMProtectEnd();
            return { Result::ERR_SC_CONNECT, ERROR_PROC_NOT_FOUND,
                     L"InitDynamicAPIs failed" };
        }
    }

    SC_HANDLE hScm = kvc_session::g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );
    if ( !hScm ) {
        DWORD e = ::GetLastError();
        return { Result::ERR_SC_CONNECT, e,
                 std::format( L"OpenSCManagerW failed: {}", format_win_error( e ) ) };
    }

    SC_HANDLE hSvc = kvc_session::g_pOpenServiceW(
        hScm, svc_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS );
    if ( !hSvc ) {
        DWORD e = ::GetLastError();
        kvc_session::g_pCloseServiceHandle( hScm );
        // mirror kvc: "does not exist" is not an error for stop
        if ( e == ERROR_SERVICE_DOES_NOT_EXIST )
            return { Result::OK, 0,
                     std::format( L"Service '{}' does not exist.", svc_name ) };
        return { Result::ERR_SVC_OPEN, e,
                 std::format( L"OpenServiceW('{}') failed: {}", svc_name, format_win_error(e) ) };
    }

    SERVICE_STATUS ss{};
    kvc_session::g_pQueryServiceStatus( hSvc, &ss );
    if ( ss.dwCurrentState != SERVICE_STOPPED &&
         ss.dwCurrentState != SERVICE_STOP_PENDING )
    {
        if ( !kvc_session::g_pControlService( hSvc, SERVICE_CONTROL_STOP, &ss ) ) {
            DWORD e = ::GetLastError();
            kvc_session::g_pCloseServiceHandle( hSvc );
            kvc_session::g_pCloseServiceHandle( hScm );
            return { Result::ERR_SVC_STOP, e,
                     std::format( L"ControlService STOP failed: {}", format_win_error(e) ) };
        }
        // spin up to 3 s
        for ( int i = 0; i < 30; ++i ) {
            ::Sleep( 100 );
            if ( kvc_session::g_pQueryServiceStatus( hSvc, &ss ) &&
                 ss.dwCurrentState == SERVICE_STOPPED )
                break;
        }
    }

    kvc_session::g_pCloseServiceHandle( hSvc );
    kvc_session::g_pCloseServiceHandle( hScm );
    return { Result::OK, 0, std::format( L"Service '{}' stopped.", svc_name ) };
}

//─────────────────────────────────────────────── unload_driver ────────────────
//
//  Mirrors kvc RemoveExternalDriver() exactly.
//  Stops (if running) then marks service for deletion.
//
__declspec(noinline) inline OpResult unload_driver( const std::wstring& svc_name )
{
    VMProtectBeginUltra( "unload_driver" );
    if ( !kvc_session::g_pOpenSCManagerW ) {
        if ( !kvc_session::InitDynamicAPIs() ) {
            VMProtectEnd();
            return { Result::ERR_SC_CONNECT, ERROR_PROC_NOT_FOUND,
                     L"InitDynamicAPIs failed" };
        }
    }

    // ── 1. Stop first ────────────────────────────────────────────────────────
    {
        auto r = stop_driver( svc_name );
        if ( r.code != Result::OK )
            return r;
    }

    // ── 2. Open SCM ──────────────────────────────────────────────────────────
    SC_HANDLE hScm = kvc_session::g_pOpenSCManagerW( nullptr, nullptr, SC_MANAGER_CONNECT );
    if ( !hScm ) {
        DWORD e = ::GetLastError();
        return { Result::ERR_SC_CONNECT, e,
                 std::format( L"OpenSCManagerW failed: {}", format_win_error(e) ) };
    }

    // ── 3. Open service ──────────────────────────────────────────────────────
    SC_HANDLE hSvc = kvc_session::g_pOpenServiceW( hScm, svc_name.c_str(), DELETE );
    if ( !hSvc ) {
        DWORD e = ::GetLastError();
        kvc_session::g_pCloseServiceHandle( hScm );
        // mirror kvc: does not exist → already removed
        if ( e == ERROR_SERVICE_DOES_NOT_EXIST )
            return { Result::OK, 0,
                     std::format( L"Service '{}' already removed.", svc_name ) };
        return { Result::ERR_SVC_OPEN, e,
                 std::format( L"OpenServiceW('{}') failed: {}", svc_name, format_win_error(e) ) };
    }

    // ── 4. Delete ────────────────────────────────────────────────────────────
    BOOL  ok  = kvc_session::g_pDeleteService( hSvc );
    DWORD e   = ::GetLastError();

    kvc_session::g_pCloseServiceHandle( hSvc );
    kvc_session::g_pCloseServiceHandle( hScm );

    if ( !ok ) {
        // mirror kvc: marked-for-delete → treat as success
        if ( e == ERROR_SERVICE_MARKED_FOR_DELETE )
            return { Result::OK, 0,
                     std::format( L"Service '{}' already marked for deletion.", svc_name ) };
        return { Result::ERR_SVC_DELETE, e,
                 std::format( L"DeleteService failed: {}", format_win_error(e) ) };
    }

    return { Result::OK, 0, std::format( L"Service '{}' unloaded.", svc_name ) };
}

//─────────────────────────────────────────────── load_driver ─────────────────
//
//  Full 3-step kvc flow mirroring LoadExternalDriver() exactly.
//
//  sys_path     – absolute path to the .sys file
//  svc_name     – service name; empty → derived from filename stem
//  start_type   – SERVICE_DEMAND_START by default
//  skip_dse     – true when driver is test-signed (bcdedit /set testsigning on)
//  kvc_sys_path – path to kvc.sys; empty → auto-searched by FindKvcSys()
//
__declspec(noinline) inline OpResult load_driver( const std::wstring& sys_path,
                              std::wstring        svc_name     = L"",
                              DWORD               start_type   = SERVICE_DEMAND_START,
                              bool                skip_dse     = false,
                              const std::wstring& kvc_sys_path = L"" )
{
    VMP_GUARD();
    VMProtectBeginUltra( "load_driver" );
    if ( !kvc_session::g_pOpenSCManagerW ) {
        if ( !kvc_session::InitDynamicAPIs() ) {
            VMProtectEnd();
            return { Result::ERR_SC_CONNECT, ERROR_PROC_NOT_FOUND,
                     L"InitDynamicAPIs failed" };
        }
    }

    // ── 0. Validate .sys ─────────────────────────────────────────────────────
    if ( !std::filesystem::exists( sys_path ) )
        return { Result::ERR_FILE_NOT_FOUND, 0,
                 std::format( L"File not found: {}", sys_path ) };

    if ( svc_name.empty() )
        svc_name = svc_name_from_path( sys_path );

    // ── STEP 1 – DSE disable (kvc BeginSession → Disable → EndSession) ────────
    // Which method succeeded – keeps Restore symmetric with Disable.
    dse_bypass::Method   succeededMethod = dse_bypass::Method::Safe;
    dse_bypass::RestoreHints dseHints;   // captured after Disable, replayed in restore_dse
    if ( !skip_dse ) {
        std::wstring kvc_path = kvc_sys_path.empty()
                              ? kvc_session::FindKvcSys()
                              : kvc_sys_path;
        dlog::write( std::format( L"[driver_mgr::load] STEP1 DSE-disable – kvc_path: {}",
                                  kvc_path.empty() ? L"(not found)" : kvc_path ) );
        if ( kvc_path.empty() )
            return { Result::ERR_KVC_SESSION, 0,
                     std::format( L"kvc.sys not found – place it next to driver_loader.exe.\n"
                                  L"Log: {}", dlog::g_log_path ) };

        kvc_session::Session ses{};
        if ( !kvc_session::BeginSession( ses, kvc_path ) ) {
            DWORD e = ::GetLastError();
            dlog::write( std::format( L"[driver_mgr::load] FAIL STEP1 BeginSession error {}", e ) );
            return { Result::ERR_KVC_SESSION, e,
                     std::format( L"BeginSession failed (error {}: {})\n\n"
                                  L"Common causes:\n"
                                  L"  \u2022 Windows Defender / Vulnerable Driver Blocklist\n"
                                  L"    blocks RTCore64.sys (run: sc query RTCore64)\n"
                                  L"  \u2022 kvc.sys corrupt or wrong version\n"
                                  L"Log: {}",
                                  e, format_win_error( e ), dlog::g_log_path ) };
        }

        // ── Build-gated method selection ──────────────────────────────────────
        //  build >= 26100  (Win11 24H2 / 25H2)  → Safe (PDB) is reliable
        //  build <  26100  (Win10, Win11 22H2)   → Standard (disk g_CiOptions)
        //    The Safe PE-scan gives wrong SeCiCallbacks RVA on Win10 without PDB,
        //    causing it to silently patch the wrong address and report success.
        const DWORD wBuild = detail_dse::GetWindowsBuildNumber();
        const bool  useStdFirst = ( wBuild > 0 && wBuild < 26100 );
        dlog::write( std::format( L"[driver_mgr::load] Windows build {} – {} method first",
                                  wBuild, useStdFirst ? L"Standard" : L"Safe" ) );

        const dse_bypass::Method primary  = useStdFirst ? dse_bypass::Method::Standard
                                                        : dse_bypass::Method::Safe;
        const dse_bypass::Method fallback = useStdFirst ? dse_bypass::Method::Safe
                                                        : dse_bypass::Method::Standard;

        const bool primaryOk = ses.dse.Disable( primary );
        if ( primaryOk ) {
            succeededMethod = primary;
            dseHints = ses.dse.CaptureRestoreHints();   // snapshot patch location
            dlog::write( std::format( L"[driver_mgr::load] DSE Disable via {} method OK",
                                      useStdFirst ? L"Standard" : L"Safe" ) );
        } else {
            DWORD ePrimary = ::GetLastError();
            dlog::write( std::format( L"[driver_mgr::load] {} method failed (error {}), trying {}",
                                      useStdFirst ? L"Standard" : L"Safe",
                                      ePrimary,
                                      useStdFirst ? L"Safe" : L"Standard" ) );
            if ( !ses.dse.Disable( fallback ) ) {
                DWORD eFallback = ::GetLastError();
                dlog::write( std::format( L"[driver_mgr::load] FAIL both methods failed ({} / {})",
                                          ePrimary, eFallback ) );
                kvc_session::EndSession( ses, true );
                return { Result::ERR_DSE_DISABLE, ePrimary,
                         std::format( L"DSE Disable failed.\n"
                                      L"  {} error {}: {}\n"
                                      L"  {} error {}: {}\n\n"
                                      L"Log: {}",
                                      useStdFirst ? L"Standard" : L"Safe",
                                      ePrimary,   format_win_error( ePrimary ),
                                      useStdFirst ? L"Safe" : L"Standard",
                                      eFallback,  format_win_error( eFallback ),
                                      dlog::g_log_path ) };
            }
            succeededMethod = fallback;
            dseHints = ses.dse.CaptureRestoreHints();   // snapshot patch location
            dlog::write( std::format( L"[driver_mgr::load] DSE Disable via {} method OK (fallback)",
                                      useStdFirst ? L"Safe" : L"Standard" ) );
        }

        // Close kvc.sys handle BEFORE SCM – mirrors kvc exactly
        kvc_session::EndSession( ses, false );   // false = keep SCM service alive for STEP 3
    }

    // ── STEP 2 – SCM load ─────────────────────────────────────────────────────
    SC_HANDLE hScm = kvc_session::g_pOpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT );
    if ( !hScm ) {
        DWORD e = ::GetLastError();
        // Best-effort DSE restore on failure
        if ( !skip_dse ) {
            std::wstring kvc_path = kvc_sys_path.empty()
                                  ? kvc_session::FindKvcSys()
                                  : kvc_sys_path;
            if ( !kvc_path.empty() ) {
                kvc_session::Session ses2{};
                if ( kvc_session::BeginSession( ses2, kvc_path ) ) {
                    ses2.dse.ApplyRestoreHints( dseHints );   // replay disable-session state
                    if ( !ses2.dse.Restore( succeededMethod ) )
                        dlog::write( L"[driver_mgr::load] WARN early-exit DSE restore returned false" );
                    kvc_session::EndSession( ses2, true );
                } else {
                    dlog::write( std::format( L"[driver_mgr::load] WARN early-exit DSE restore skipped – BeginSession failed (GLE {})",
                                              ::GetLastError() ) );
                }
            }
        }
        return { Result::ERR_SC_CONNECT, e,
                 std::format( L"OpenSCManagerW failed: {}", format_win_error(e) ) };
    }

    // RAII guard so DSE is always restored on any early exit from here on
    auto restore_dse = [&]() {
        if ( skip_dse ) return;
        std::wstring kvc_path = kvc_sys_path.empty()
                              ? kvc_session::FindKvcSys()
                              : kvc_sys_path;
        if ( kvc_path.empty() ) {
            dlog::write( L"[driver_mgr::load] WARN restore_dse – kvc.sys path not found; DSE may remain disabled" );
            return;
        }
        kvc_session::Session ses{};
        if ( kvc_session::BeginSession( ses, kvc_path ) ) {
            ses.dse.ApplyRestoreHints( dseHints );   // replay the exact patch location from STEP 1
            if ( !ses.dse.Restore( succeededMethod ) )
                dlog::write( L"[driver_mgr::load] WARN DSE restore returned false after driver load" );
            else
                dlog::write( L"[driver_mgr::load] STEP3 DSE restore OK" );
            kvc_session::EndSession( ses, true );
        } else {
            dlog::write( std::format( L"[driver_mgr::load] WARN STEP3 DSE restore skipped – BeginSession failed (GLE {})"
                                      L" – DSE remains disabled, Windows may report test-signing mode!",
                                      ::GetLastError() ) );
        }
    };
    // wrap SCM cleanup + DSE restore in one lambda called on every exit path
    auto scm_cleanup = [&]( SC_HANDLE sv, bool restore ) {
        if ( sv )  kvc_session::g_pCloseServiceHandle( sv );
        kvc_session::g_pCloseServiceHandle( hScm );
        if ( restore ) restore_dse();
    };

    // ── Purge any stale service entry (error 183 / wrong binary path) ──────────
    //  If a previous session left the service registered (running OR stopped),
    //  forcibly stop and delete it so we always create a fresh entry below.
    //  This mirrors kvc PerformAtomicCleanup() before every load.
    {
        SC_HANDLE hExist = kvc_session::g_pOpenServiceW(
            hScm, svc_name.c_str(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE );
        if ( hExist ) {
            dlog::write( std::format(
                L"[driver_mgr::load] stale service '{}' found – purging before reload",
                svc_name ) );

            // Stop if still running
            SERVICE_STATUS ss{};
            if ( kvc_session::g_pQueryServiceStatus( hExist, &ss ) &&
                 ss.dwCurrentState != SERVICE_STOPPED &&
                 ss.dwCurrentState != SERVICE_STOP_PENDING )
            {
                kvc_session::g_pControlService( hExist, SERVICE_CONTROL_STOP, &ss );
                // spin up to 3 s for clean stop
                for ( int i = 0; i < 30; ++i ) {
                    ::Sleep( 100 );
                    if ( kvc_session::g_pQueryServiceStatus( hExist, &ss ) &&
                         ss.dwCurrentState == SERVICE_STOPPED )
                        break;
                }
            }

            // Mark for deletion (may be deferred until handles are closed)
            kvc_session::g_pDeleteService( hExist );
            kvc_session::g_pCloseServiceHandle( hExist );

            // Give SCM time to fully remove the entry
            ::Sleep( 400 );
        }
    }

    // Create the service entry fresh with the current binary path
    SC_HANDLE hSvc = kvc_session::g_pCreateServiceW(
        hScm,
        svc_name.c_str(),
        svc_name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        start_type,
        SERVICE_ERROR_NORMAL,
        sys_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr );
    if ( !hSvc ) {
        DWORD ce = ::GetLastError();
        // If it still exists (marked-for-delete race), open and start it
        if ( ce == ERROR_SERVICE_EXISTS || ce == ERROR_ALREADY_EXISTS ) {
            hSvc = kvc_session::g_pOpenServiceW(
                hScm, svc_name.c_str(), SERVICE_ALL_ACCESS );
        }
        if ( !hSvc ) {
            scm_cleanup( nullptr, true );
            return { Result::ERR_SVC_CREATE, ce,
                     std::format( L"CreateServiceW failed: {}", format_win_error(ce) ) };
        }
    }

    // Start the service
    BOOL  ok  = kvc_session::g_pStartServiceW( hSvc, 0, nullptr );
    DWORD se  = ::GetLastError();
    scm_cleanup( hSvc, true );   // STEP 3 – always restore DSE

    if ( !ok && se != ERROR_SERVICE_ALREADY_RUNNING
             && se != ERROR_ALREADY_EXISTS ) {       // 183: driver image already in kernel
        dlog::write( std::format( L"[driver_mgr::load] FAIL StartServiceW error {} ({})",
                                  se, format_win_error( se ) ) );
        return { Result::ERR_SVC_START, se,
                 std::format( L"StartServiceW('{}') failed (error {}: {})"
                              L"\nLog: {}",
                              svc_name, se, format_win_error( se ), dlog::g_log_path ) };
    }

    dlog::write( std::format( L"[driver_mgr::load] OK – driver '{}' running", svc_name ) );
    return { Result::OK, 0, std::format( L"Driver '{}' loaded.", svc_name ) };
}

//─────────────────────────────────────────────── reload_driver ────────────────
//
//  Mirrors kvc ReloadExternalDriver() exactly.
//  Stops the driver service (if running) then re-loads it using load_driver().
//
//  sys_path     – absolute path to the .sys file (required; used for path normalization)
//  svc_name     – empty → derived from filename stem
//  start_type   – SERVICE_DEMAND_START by default
//  skip_dse     – true when driver is test-signed
//  kvc_sys_path – path to kvc.sys; empty → auto-searched by FindKvcSys()
//
inline OpResult reload_driver( const std::wstring& sys_path,
                                std::wstring        svc_name     = L"",
                                DWORD               start_type   = SERVICE_DEMAND_START,
                                bool                skip_dse     = false,
                                const std::wstring& kvc_sys_path = L"" )
{
    const std::wstring normalized = normalize_driver_path( sys_path );

    if ( svc_name.empty() )
        svc_name = svc_name_from_path( normalized );

    // ── Stop existing service if running ─────────────────────────────────────
    {
        auto r = stop_driver( svc_name );
        // ERR_SVC_OPEN with "does not exist" is OK; anything else is a real error
        if ( r.code != Result::OK )
            return r;
    }

    // ── Re-load via the standard load flow ───────────────────────────────────
    return load_driver( normalized, svc_name, start_type, skip_dse, kvc_sys_path );
}

} // namespace driver_mgr
