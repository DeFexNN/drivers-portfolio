#pragma once
#include "includes.hpp"
#include "embedded.hpp"
#include "driver_mgr.hpp"
#include "log.hpp"
#include "firebase_auth.hpp"  // Firebase REST key validator
#include "session_manager.hpp"    // key_store: persistent key save/load
#include "VMProtectSDK.h"
#include "handshake.hpp"          // loader → SDK session token (shared memory)

//=============================================================================
//  auth.hpp  -  Firebase key auth + driver load + payload launch UI
//
//  State machine
//  -------------
//   IDLE
//    ? (user submits key)
//    V
//   VALIDATING  -> Firebase REST check in background thread
//    ? (key valid, HWID OK)     ? (invalid / banned / expired / HWID mismatch)
//    V                          V
//   LOADING  ? load_driver()  FAILED (shows reason, allows retry)
//    ? (success)
//    V
//   LAUNCHING  ->  CreateProcessW(payload)
//    ?
//    V
//   DONE  -> main loop exits
//
//  Key format: MIDNIGHT-GAME-XXXXXXXXXX
//  Validated against Firebase Firestore REST API.
//=============================================================================

namespace auth {

//----------------------------------- state ------------------------------------
enum class State : uint8_t {
    IDLE,         // waiting for key input
    VALIDATING,   // Firebase HTTP check (background thread)
    LOADING,      // driver being loaded (background thread, in same thread after validate)
    LAUNCHING,    // driver OK, launching payload
    DONE,         // payload launched - exit loop
    FAILED,       // something went wrong - show error + retry
};

inline State        g_state           = State::IDLE;
inline bool         g_done            = false;
inline bool         g_close_requested = false;

// Background thread signals:
//   0 = busy, 1 = validate OK, -1 = validate FAIL,
//   2 = driver load OK, -2 = driver load FAIL
inline LONG         g_thread_signal   = 0L;
inline std::wstring g_error_msg;

inline char         g_key_buf[128]    = {};
inline bool         g_show_error      = false;

// Animated dots
inline float        g_dot_timer       = 0.f;
inline int          g_dot_count       = 0;

// Active service name (set after successful load)
inline std::wstring g_loaded_svc_name;

// Sub-label shown during VALIDATING / LOADING
inline const char*  g_status_label    = "Validating key";

// Timer for LAUNCHING -> DONE
inline float        g_launch_close_timer = 0.f;
static constexpr float LAUNCH_CLOSE_DELAY = 8.0f;

// PID of the launched payload (RuntimeBroker.exe / DMA-SDK)
// Set by launch_payload(); read by protect_payload_proc()
inline DWORD        g_payload_pid = 0;

// Handshake: named shared-memory handle – kept open until loader exits so the
// shared-memory segment stays alive while the SDK is running.
inline HANDLE       g_hs_map           = nullptr;
// License expiry from Firebase (Unix seconds); set by auth_load_thread().
// 0 = lifetime key or expiry field absent from Firestore document.
inline uint64_t     g_key_expires_unix  = 0;

// Key persistence: holds the key between start_auth_thread() call and
// the moment the background thread signals validation success.
inline std::string  g_pending_key;

// Prevents auto-auth from firing more than once per process lifetime.
inline bool         g_auto_auth_tried = false;

//------------------------------- resolve rel path -----------------------------
inline std::wstring resolve_relative( const wchar_t* rel )
{
    wchar_t exe_dir[MAX_PATH];
    ::GetModuleFileNameW( nullptr, exe_dir, MAX_PATH );
    ::PathRemoveFileSpecW( exe_dir );
    wchar_t out[MAX_PATH];
    ::PathCombineW( out, exe_dir, rel );
    wchar_t canonical[MAX_PATH];
    ::GetFullPathNameW( out, MAX_PATH, canonical, nullptr );
    return canonical;
}

//------------------------------- launch payload -------------------------------
__declspec(noinline) inline bool launch_payload( const std::wstring& exe_path )
{
    VMProtectBeginMutation( "launch_payload" );
    dlog::write( wfmt( WOBFS( L"[auth] launch_payload: {}" ), exe_path ) );
    if ( exe_path.empty() ) {
        dlog::write( WOBF( L"[auth] launch_payload FAIL - path is empty" ) );
        return false;
    }
    if ( ::GetFileAttributesW( exe_path.c_str() ) == INVALID_FILE_ATTRIBUTES ) {
        dlog::write( wfmt( WOBFS( L"[auth] launch_payload FAIL - file not found ({})" ),
                                  ::GetLastError() ) );
        return false;
    }

    STARTUPINFOW        si{ sizeof( si ) };
    PROCESS_INFORMATION pi{};
    BOOL ok = lazy::k32::get().CreateProcessW(
        exe_path.c_str(), nullptr,
        nullptr, nullptr, FALSE,
        0, nullptr, nullptr,
        &si, &pi );
    DWORD ce = ::GetLastError();
    if ( ok ) {
        dlog::write( wfmt( WOBFS( L"[auth] launch_payload OK - PID {}" ), pi.dwProcessId ) );
        g_payload_pid = pi.dwProcessId;       // save for protect_payload_proc
        ::CloseHandle( pi.hProcess );
        ::CloseHandle( pi.hThread );
    } else {
        dlog::write( wfmt( WOBFS( L"[auth] launch_payload FAIL - error {}: {}" ),
                                  ce, driver_mgr::format_win_error( ce ) ) );
    }
    VMProtectEnd();
    return ok != FALSE;
}

//----------------------- protect payload via ObRegisterCallbacks IOCTL --------
// Sends MS_MAGIC_PROTECT_PROC to the kernel driver so it installs
// ObRegisterCallbacks stripping PROCESS_VM_READ / TERMINATE / etc. from any
// third-party OpenProcess call targeting our payload (RuntimeBroker.exe).
inline void protect_payload_proc( DWORD pid )
{
    if ( pid == 0 ) return;

    // Open the DXGKrnl device the same way DMA comms do
    HANDLE hDev = ::CreateFileW(
        L"\\\\.\\DXGKrnl",
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING, 0, nullptr );

    if ( hDev == INVALID_HANDLE_VALUE ) {
        dlog::write( wfmt( WOBFS( L"[auth] protect_payload_proc: open DXGKrnl failed ({})" ),
                           ::GetLastError() ) );
        return;
    }

    struct { ULONG_PTR ProcessId; } req{ (ULONG_PTR)pid };
    DWORD transferred = 0;

    // MS_MAGIC_PROTECT_PROC = CTL_CODE(0x23, 0x0DEA, METHOD_BUFFERED, FILE_ANY_ACCESS)
    //   = (0x23 << 16) | (0x0DEA << 2) | 0 = 0x008C0002 | 0x37A8 = 0x008C37A8
    //   Computed: ((0x23u << 16) | (0x0DEAu << 2))
    constexpr DWORD IOCTLCODE_PROTECT_PROC = ( (0x23u << 16) | (0x0DEAu << 2) );

    BOOL ok = ::DeviceIoControl(
        hDev,
        IOCTLCODE_PROTECT_PROC,
        &req, static_cast<DWORD>( sizeof( req ) ),
        nullptr, 0,
        &transferred, nullptr );

    ::CloseHandle( hDev );

    if ( ok )
        dlog::write( wfmt( WOBFS( L"[auth] protect_payload_proc: PID {} protected via kernel ObCallbacks" ), pid ) );
    else
        dlog::write( wfmt( WOBFS( L"[auth] protect_payload_proc: DeviceIoControl failed ({})" ), ::GetLastError() ) );
}

//----------------------- combined validate + load thread ----------------------
struct AuthLoadParams {
    std::string  key;
    std::string  hwid;
    std::wstring sys_path;
};

inline void set_error( const wchar_t* msg )
{
    g_error_msg = msg;
    ::InterlockedExchange( &g_thread_signal, -1L );
}

static DWORD WINAPI auth_load_thread( LPVOID param )
{
    VMProtectBeginMutation( "auth_load_thread" );
    auto* p = static_cast<AuthLoadParams*>( param );

    // -- Phase 1: Firebase key validation ----------------------------------
    dlog::write( wfmt( WOBFS( L"[auth] validating key via Firebase..." ) ) );
    const fb_auth::Result vr = fb_auth::validate( p->key, p->hwid );

    if ( vr.code != fb_auth::Code::OK ) {
        // Convert narrow error to wide
        int n = ::MultiByteToWideChar( CP_UTF8, 0, fb_auth::code_to_str( vr.code ), -1,
                                       nullptr, 0 );
        std::wstring wmsg( static_cast<size_t>( n > 0 ? n - 1 : 0 ), L'\0' );
        ::MultiByteToWideChar( CP_UTF8, 0, fb_auth::code_to_str( vr.code ), -1,
                               wmsg.data(), n );
        g_error_msg = wmsg;
        ::InterlockedExchange( &g_thread_signal, -1L );
        dlog::write( wfmt( WOBFS( L"[auth] key validation FAILED: {}" ),
                           std::wstring( vr.reason.begin(), vr.reason.end() ) ) );
        delete p;
        VMProtectEnd();
        return 0;
    }

    dlog::write( WOBF( L"[auth] key validation OK" ) );
    // Persist expiry so the UI thread can build the handshake token.
    g_key_expires_unix = vr.expires_at_unix;
    // Signal VALIDATING -> LOADING transition
    ::InterlockedExchange( &g_thread_signal, 1L );

    // -- Phase 2: driver load -----------------------------------------------
    g_loaded_svc_name = driver_mgr::svc_name_from_path( p->sys_path );
    auto res = driver_mgr::load_driver( p->sys_path, L"",
                                        SERVICE_DEMAND_START,
                                        /*skip_dse=*/false,
                                        embedded::g_kvc_path );
    if ( res.code == driver_mgr::Result::OK ) {
        ::InterlockedExchange( &g_thread_signal, 2L );   // all good
    } else {
        g_error_msg = res.message;
        ::InterlockedExchange( &g_thread_signal, -2L );  // driver failed
    }

    delete p;
    VMProtectEnd();
    return 0;
}

// Kick off the combined validate + load thread
inline void start_auth_thread( const std::string& key )
{
    ::InterlockedExchange( &g_thread_signal, 0L );
    g_status_label = "Validating key";
    g_pending_key  = key;   // save for key_store::save() on success

    auto* p      = new AuthLoadParams{};
    p->key       = key;
    p->hwid      = fb_auth::get_hwid();
    p->sys_path  = embedded::g_driver_path;

    dlog::write( wfmt( WOBFS( L"[auth] HWID: {}" ),
                       std::wstring( p->hwid.begin(), p->hwid.end() ) ) );

    HANDLE h = ::CreateThread( nullptr, 0, auth_load_thread, p, 0, nullptr );
    if ( h ) ::CloseHandle( h );
}

//----------------------------------- UI ---------------------------------------
inline bool draw_login_ui()
{
    if ( g_state == State::DONE ) { g_done = true; return true; }

    const ImGuiIO& io = ImGui::GetIO();
    const float    dt = io.DeltaTime;

    // animated dots
    g_dot_timer += dt;
    if ( g_dot_timer >= 0.45f ) {
        g_dot_timer = 0.f;
        g_dot_count = ( g_dot_count + 1 ) % 4;
    }

    constexpr float WIN_W = 400.f;
    constexpr float WIN_H = 220.f;

    ImGui::SetNextWindowPos(
        ImVec2( io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f ),
        ImGuiCond_Always, ImVec2( 0.5f, 0.5f ) );
    ImGui::SetNextWindowSize( ImVec2( WIN_W, WIN_H ), ImGuiCond_Always );
    ImGui::SetNextWindowBgAlpha( 0.97f );

    constexpr ImGuiWindowFlags WF =
        ImGuiWindowFlags_NoResize      | ImGuiWindowFlags_NoMove        |
        ImGuiWindowFlags_NoCollapse    | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoScrollbar;

    ImGui::Begin( OBF( "##loader_wnd" ), nullptr, WF );

    // -- Title bar + X button -------------------------------------------------
    {
        const char* title;
        switch ( g_state ) {
            case State::VALIDATING: title = OBF( "  MidnightSoftware Loader  |  Validating..." ); break;
            case State::LOADING:    title = OBF( "  MidnightSoftware Loader  |  Loading..."    ); break;
            default:                title = OBF( "  MidnightSoftware Loader  |  Start"         ); break;
        }

        ImGui::SetCursorPosY( ImGui::GetCursorPosY() + 3.f );
        ImGui::TextUnformatted( title );

        constexpr float CLOSE_W = 26.f;
        const float pad = ImGui::GetStyle().WindowPadding.x;
        ImGui::SameLine( WIN_W - CLOSE_W - pad - 2.f );
        ImGui::PushStyleColor( ImGuiCol_Button,        ImVec4{ 0.55f,0.10f,0.10f,1.f } );
        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4{ 0.80f,0.15f,0.15f,1.f } );
        ImGui::PushStyleColor( ImGuiCol_ButtonActive,  ImVec4{ 1.00f,0.20f,0.20f,1.f } );
        if ( ImGui::Button( OBF( "X##close" ), ImVec2( CLOSE_W, 0.f ) ) )
            g_close_requested = true;
        ImGui::PopStyleColor( 3 );
    }
    ImGui::Separator();
    ImGui::Spacing();

    // ==================================== IDLE ================================
    if ( g_state == State::IDLE )
    {
        // ── Auto-auth: load saved key once per process lifetime ────────────
        if ( !g_auto_auth_tried ) {
            g_auto_auth_tried = true;
            std::string saved = key_store::load();
            if ( !saved.empty() ) {
                dlog::write( WOBF( L"[auth] found saved key – auto-submitting" ) );
                g_show_error = false;
                start_auth_thread( saved );
                g_state = State::VALIDATING;
                ::SecureZeroMemory( saved.data(), saved.size() );
            }
        }

        ImGui::TextDisabled( OBF( " Version: 1.0.0     Driver: MidnightSoftware" ) );
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        constexpr float LBL_W = 40.f;
        constexpr float INP_W = 280.f;
        ImGui::SetCursorPosX( ( WIN_W - LBL_W - INP_W - 8.f ) * 0.5f );
        ImGui::TextUnformatted( OBF( "Key" ) );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( INP_W );
        const bool enter = ImGui::InputText(
            OBF( "##key_input" ), g_key_buf, sizeof( g_key_buf ),
            ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue );

        // Placeholder hint below input
        {
            const char* hint = OBF( "MIDNIGHT-GAME-XXXXXXXXXX" );
            ImGui::SetCursorPosX( ( WIN_W - ImGui::CalcTextSize( hint ).x ) * 0.5f );
            ImGui::TextDisabled( hint );
        }

        ImGui::Spacing();

        constexpr float BTN_W = 160.f;
        ImGui::SetCursorPosX( ( WIN_W - BTN_W ) * 0.5f );
        ImGui::PushStyleColor( ImGuiCol_Button,        ImVec4{ 0.18f,0.44f,0.18f,1.f } );
        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4{ 0.24f,0.60f,0.24f,1.f } );
        ImGui::PushStyleColor( ImGuiCol_ButtonActive,  ImVec4{ 0.30f,0.75f,0.30f,1.f } );
        const bool btn = ImGui::Button( OBF( "Activate" ), ImVec2( BTN_W, 28.f ) );
        ImGui::PopStyleColor( 3 );

        if ( ( enter || btn ) && g_key_buf[0] != '\0' ) {
            g_show_error = false;
            std::string key( g_key_buf );
            ::SecureZeroMemory( g_key_buf, sizeof( g_key_buf ) );
            start_auth_thread( key );
            g_state = State::VALIDATING;
        }

        if ( g_show_error ) {
            ImGui::Spacing();
            ImGui::PushTextWrapPos( WIN_W - 20.f );
            ImGui::SetCursorPosX( 10.f );
            // g_error_msg already in wide - convert for ImGui
            int n = ::WideCharToMultiByte( CP_UTF8, 0, g_error_msg.c_str(), -1,
                                           nullptr, 0, nullptr, nullptr );
            std::string eu( n > 0 ? n - 1 : 0, '\0' );
            ::WideCharToMultiByte( CP_UTF8, 0, g_error_msg.c_str(), -1,
                                   eu.data(), n, nullptr, nullptr );
            ImGui::TextColored( ImVec4( 1.f, 0.30f, 0.30f, 1.f ), "%s", eu.c_str() );
            ImGui::PopTextWrapPos();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::SetCursorPosX(
            ( WIN_W - ImGui::CalcTextSize( OBF("Requires Administrator") ).x ) * 0.5f );
        ImGui::TextDisabled( OBF( "Requires Administrator" ) );
    }

    // ============================ VALIDATING / LOADING ========================
    else if ( g_state == State::VALIDATING || g_state == State::LOADING )
    {
        const LONG sig = ::InterlockedCompareExchange( &g_thread_signal, 0L, 0L );

        if ( g_state == State::VALIDATING ) {
            if ( sig == 1L ) {
                // Validation passed -> persist key, transition to LOADING phase
                key_store::save( g_pending_key );
                ::InterlockedExchange( &g_thread_signal, 0L );
                g_state = State::LOADING;
                g_status_label = "Loading MidnightSoftware";
            } else if ( sig == -1L ) {
                // Validation failed -> wipe any cached key so user must re-enter
                key_store::clear();
                ::InterlockedExchange( &g_thread_signal, 0L );
                g_show_error = true;
                g_state = State::IDLE;
                // g_error_msg already set by thread
            }
        } else { // LOADING
            if ( sig == 2L ) {
                // driver loaded OK -> write handshake token then launch payload
                ::InterlockedExchange( &g_thread_signal, 0L );
                dlog::write( L"[auth] MidnightSoftware loaded, writing handshake and launching payload..." );

                // Write the session token into named shared memory.
                // The SDK opens this segment on startup and aborts if it is
                // absent, stale, or the MAC does not verify.
                g_hs_map = handshake::write(
                    fb_auth::get_hwid(),
                    g_pending_key,
                    g_key_expires_unix );
                if ( !g_hs_map )
                    dlog::write( WOBF( L"[auth] WARNING: handshake failed – MidnightSoftware will refuse to run" ) );

                if ( launch_payload( embedded::g_payload_path ) ) {
                    // Immediately register kernel-level process protection
                    // so Task Manager / x64dbg / Cheat Engine cannot dump the payload
                    protect_payload_proc( g_payload_pid );
                    g_launch_close_timer = 0.f;
                    g_state = State::LAUNCHING;
                } else {
                    DWORD ce = ::GetLastError();
                    g_error_msg = std::format( L"Failed to launch MidnightSoftware"
                                               L" (error {}: {})\nPath: {}\nLog: {}",
                        ce, driver_mgr::format_win_error( ce ),
                        embedded::g_payload_path, dlog::g_log_path );
                    g_state = State::FAILED;
                }
            } else if ( sig == -2L ) {
                ::InterlockedExchange( &g_thread_signal, 0L );
                g_state = State::FAILED;
            }
        }

        // Animated spinner label
        char dots[5]{}; for ( int i = 0; i < g_dot_count; ++i ) dots[i] = '.';
        char buf[128];
        snprintf( buf, sizeof( buf ), "%s%s", g_status_label, dots );
        ImGui::SetCursorPosY( ImGui::GetCursorPosY() + 30.f );
        ImGui::SetCursorPosX( ( WIN_W - ImGui::CalcTextSize( buf ).x ) * 0.5f );
        ImGui::TextColored( ImVec4( 0.9f, 0.8f, 0.2f, 1.f ), "%s", buf );

        ImGui::Spacing();
        ImGui::Spacing();
        {
            const char* sub = ( g_state == State::VALIDATING )
                ? OBF( "Connecting to auth server..." )
                : OBF( "Do not close this window." );
            ImGui::SetCursorPosX(
                ( WIN_W - ImGui::CalcTextSize( sub ).x ) * 0.5f );
            ImGui::TextDisabled( sub );
        }

        // Indeterminate progress bar
        static float s_prog_t = 0.f;
        s_prog_t += dt * 0.8f;
        if ( s_prog_t > 1.f ) s_prog_t -= 1.f;
        const float lo = s_prog_t;
        const float hi = lo + 0.25f > 1.f ? 1.f : lo + 0.25f;
        ImGui::Spacing();
        const ImVec4 bar_col = ( g_state == State::VALIDATING )
            ? ImVec4{ 0.55f, 0.20f, 0.95f, 1.f }   // purple for validating
            : ImVec4{ 0.20f, 0.60f, 1.00f, 1.f };   // blue for loading
        ImGui::PushStyleColor( ImGuiCol_PlotHistogram, bar_col );
        ImGui::ProgressBar( hi, ImVec2( -1.f, 12.f ), OBF( "" ) );
        ImGui::PopStyleColor();
    }

    // ==================================== LAUNCHING ===========================
    else if ( g_state == State::LAUNCHING )
    {
        g_launch_close_timer += dt;
        const float remaining = LAUNCH_CLOSE_DELAY - g_launch_close_timer;
        if ( remaining <= 0.f ) {
            g_state = State::DONE;
        } else {
            ImGui::SetCursorPosY( ImGui::GetCursorPosY() + 28.f );
            const char* ok1 = OBF( "MidnightSoftware loaded successfully!" );
            ImGui::SetCursorPosX( ( WIN_W - ImGui::CalcTextSize( ok1 ).x ) * 0.5f );
            ImGui::TextColored( ImVec4( 0.2f, 0.95f, 0.2f, 1.f ), ok1 );

            ImGui::Spacing();
            const char* ok2 = OBF( "Launching MidnightSoftware..." );
            ImGui::SetCursorPosX( ( WIN_W - ImGui::CalcTextSize( ok2 ).x ) * 0.5f );
            ImGui::TextColored( ImVec4( 0.6f, 0.9f, 0.6f, 1.f ), ok2 );

            ImGui::Spacing();
            ImGui::Spacing();
            char closebuf[32];
            snprintf( closebuf, sizeof(closebuf), OBF( "Closing in %.0fs..." ),
                      remaining + 0.99f );
            ImGui::SetCursorPosX(
                ( WIN_W - ImGui::CalcTextSize( closebuf ).x ) * 0.5f );
            ImGui::TextDisabled( closebuf );

            ImGui::Spacing();
            const float fill = 1.f - ( g_launch_close_timer / LAUNCH_CLOSE_DELAY );
            ImGui::PushStyleColor( ImGuiCol_PlotHistogram,
                                   ImVec4{ 0.20f, 0.75f, 0.20f, 1.f } );
            ImGui::ProgressBar( fill, ImVec2( -1.f, 8.f ), OBF( "" ) );
            ImGui::PopStyleColor();
        }
    }

    // ==================================== FAILED ==============================
    else if ( g_state == State::FAILED )
    {
        ImGui::SetCursorPosY( ImGui::GetCursorPosY() + 10.f );

        int len = ::WideCharToMultiByte( CP_UTF8, 0, g_error_msg.c_str(), -1,
                                         nullptr, 0, nullptr, nullptr );
        std::string err_utf8( len > 0 ? len - 1 : 0, '\0' );
        if ( len > 0 )
            ::WideCharToMultiByte( CP_UTF8, 0, g_error_msg.c_str(), -1,
                                   err_utf8.data(), len, nullptr, nullptr );

        ImGui::PushTextWrapPos( WIN_W - 20.f );
        ImGui::SetCursorPosX( 10.f );
        ImGui::TextColored( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), OBF( "Error:" ) );
        ImGui::SetCursorPosX( 10.f );
        ImGui::TextColored( ImVec4( 1.f, 0.6f, 0.6f, 1.f ),
                            "%s", err_utf8.c_str() );
        ImGui::PopTextWrapPos();

        ImGui::Spacing();
        ImGui::Spacing();

        constexpr float BTN_W = 100.f;
        ImGui::SetCursorPosX( ( WIN_W - BTN_W * 2.f - 12.f ) * 0.5f );
        if ( ImGui::Button( OBF( "Retry" ), ImVec2( BTN_W, 26.f ) ) ) {
            g_error_msg.clear();
            g_state = State::IDLE;
        }
        ImGui::SameLine( 0.f, 12.f );
        ImGui::PushStyleColor( ImGuiCol_Button,        ImVec4{ 0.55f,0.10f,0.10f,1.f } );
        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4{ 0.80f,0.15f,0.15f,1.f } );
        ImGui::PushStyleColor( ImGuiCol_ButtonActive,  ImVec4{ 1.00f,0.20f,0.20f,1.f } );
        if ( ImGui::Button( OBF( "Close" ), ImVec2( BTN_W, 26.f ) ) )
            g_close_requested = true;
        ImGui::PopStyleColor( 3 );

        if ( !dlog::g_log_path.empty() ) {
            ImGui::Spacing();
            int plen = ::WideCharToMultiByte( CP_UTF8, 0, dlog::g_log_path.c_str(),
                                              -1, nullptr, 0, nullptr, nullptr );
            std::string lp( plen > 0 ? plen - 1 : 0, '\0' );
            ::WideCharToMultiByte( CP_UTF8, 0, dlog::g_log_path.c_str(), -1,
                                   lp.data(), plen, nullptr, nullptr );
            ImGui::SetCursorPosX( 10.f );
            ImGui::TextDisabled( "Log: %s", lp.c_str() );
            ImGui::SetCursorPosX( ( WIN_W - BTN_W ) * 0.5f );
            if ( ImGui::Button( OBF( "View Log" ), ImVec2( BTN_W, 22.f ) ) ) {
                dlog::close();
                ::ShellExecuteW( nullptr, L"open", dlog::g_log_path.c_str(),
                                 nullptr, nullptr, SW_SHOW );
            }
        }
    } // end FAILED

    ImGui::End();
    return ( g_state == State::DONE );
}

} // namespace auth

