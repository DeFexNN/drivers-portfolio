//=============================================================================
//  main.cpp  -  MidnightSoftware Loader
//
//  Flow:
//    1. If not in %%TEMP%%: copy self there with a random name, relaunch, exit.
//    2. Create a fixed 400x220 D3D11 window (standard opaque, centered)
//    3. Run the ImGui auth/load/launch UI (auth.hpp draw_login_ui)
//    4. On success: driver loaded -> payload launched -> window closes
//=============================================================================

#include "src/includes.hpp"
#include "src/log.hpp"
#include "src/embedded.hpp"
#include "src/auth.hpp"
#include "src/VMProtectSDK.h"   // VMProtect 3.x SDK

// ---------------------------------------------------------------------------
// Self-relocate: copy the loader to %%TEMP%%\<random>.exe and relaunch it.
// This makes the file name in Explorer and Task Manager change every time.
// The copy detects it is already in %%TEMP%% and skips the step.
// ---------------------------------------------------------------------------
static bool SelfRelocate() noexcept
{
    wchar_t own_path[MAX_PATH];
    if (!::GetModuleFileNameW(nullptr, own_path, MAX_PATH)) return false;

    wchar_t tmp_dir[MAX_PATH];
    if (!::GetTempPathW(MAX_PATH, tmp_dir)) return false;

    // Compare own path prefix against %TEMP% (case-insensitive)
    std::wstring own_str = own_path;
    std::wstring tmp_str = tmp_dir;
    auto lower = [](std::wstring s) {
        for (auto& c : s) c = (wchar_t)::towlower(c); return s;
    };
    if (lower(own_str).find(lower(tmp_str)) != std::wstring::npos)
        return false; // already running from %TEMP%, skip

    // Build random destination: %TEMP%\<10hex>.exe
    std::wstring rnd  = embedded::rand_stem();
    std::wstring dest = std::wstring(tmp_dir) + rnd + L".exe";

    if (!::CopyFileW(own_path, dest.c_str(), FALSE)) return false;

    // Hide the temp copy so it does not show in Explorer easily
    ::SetFileAttributesW(dest.c_str(),
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);

    STARTUPINFOW        si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    BOOL launched = ::CreateProcessW(
        dest.c_str(), nullptr, nullptr, nullptr,
        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (launched) {
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
    } else {
        // Relaunch failed: clean up copy and fall through to running in place
        ::SetFileAttributesW(dest.c_str(), FILE_ATTRIBUTE_NORMAL);
        ::DeleteFileW(dest.c_str());
        return false;
    }
    return true; // original should exit
}

//─────────────────────────────── D3D11 globals ────────────────────────────────
static ID3D11Device*           g_pd3dDevice          = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext    = nullptr;
static IDXGISwapChain*         g_pSwapChain           = nullptr;
static bool                    g_SwapChainOccluded    = false;
static UINT                    g_ResizeWidth          = 0;
static UINT                    g_ResizeHeight         = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static constexpr int WND_W = 400;
static constexpr int WND_H = 220;

//─────────────────────────────── prototypes ───────────────────────────────────
__declspec(noinline) bool   CreateDeviceD3D( HWND );
void   CleanupDeviceD3D();
void   CreateRenderTarget();
void   CleanupRenderTarget();
LRESULT WINAPI WndProc( HWND, UINT, WPARAM, LPARAM );
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler( HWND, UINT, WPARAM, LPARAM );

//─────────────────────────────── centre window ────────────────────────────────
static void CenterWindow( HWND hwnd )
{
    RECT rc; ::GetWindowRect( hwnd, &rc );
    const int w = rc.right  - rc.left;
    const int h = rc.bottom - rc.top;
    const int sw = ::GetSystemMetrics( SM_CXSCREEN );
    const int sh = ::GetSystemMetrics( SM_CYSCREEN );
    ::SetWindowPos( hwnd, nullptr, ( sw - w ) / 2, ( sh - h ) / 2, 0, 0,
                    SWP_NOSIZE | SWP_NOZORDER );
}

//─────────────────────────────── apply style ──────────────────────────────────
static void ApplyLoaderStyle()
{
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding   = 6.f;
    s.FrameRounding    = 4.f;
    s.GrabRounding     = 4.f;
    s.PopupRounding    = 4.f;
    s.ScrollbarRounding = 4.f;
    s.WindowBorderSize = 1.f;
    s.FramePadding     = ImVec2( 8.f, 5.f );
    s.ItemSpacing      = ImVec2( 8.f, 6.f );

    // Dark theme with slight green tint for active elements
    ImGui::StyleColorsDark();
    ImVec4* c = s.Colors;
    c[ ImGuiCol_WindowBg ]            = ImVec4{ 0.10f, 0.10f, 0.12f, 1.00f };
    c[ ImGuiCol_Header ]              = ImVec4{ 0.18f, 0.44f, 0.18f, 1.00f };
    c[ ImGuiCol_HeaderHovered ]       = ImVec4{ 0.24f, 0.60f, 0.24f, 1.00f };
    c[ ImGuiCol_HeaderActive ]        = ImVec4{ 0.30f, 0.75f, 0.30f, 1.00f };
    c[ ImGuiCol_FrameBg ]             = ImVec4{ 0.16f, 0.16f, 0.20f, 1.00f };
    c[ ImGuiCol_FrameBgHovered ]      = ImVec4{ 0.22f, 0.22f, 0.28f, 1.00f };
    c[ ImGuiCol_FrameBgActive ]       = ImVec4{ 0.28f, 0.28f, 0.38f, 1.00f };
    c[ ImGuiCol_TitleBg ]             = ImVec4{ 0.10f, 0.10f, 0.12f, 1.00f };
    c[ ImGuiCol_TitleBgActive ]       = ImVec4{ 0.13f, 0.13f, 0.16f, 1.00f };
    c[ ImGuiCol_Separator ]           = ImVec4{ 0.28f, 0.28f, 0.34f, 1.00f };
    c[ ImGuiCol_Button ]              = ImVec4{ 0.18f, 0.18f, 0.24f, 1.00f };
    c[ ImGuiCol_ButtonHovered ]       = ImVec4{ 0.26f, 0.26f, 0.34f, 1.00f };
    c[ ImGuiCol_ButtonActive ]        = ImVec4{ 0.34f, 0.34f, 0.44f, 1.00f };
    c[ ImGuiCol_CheckMark ]           = ImVec4{ 0.20f, 0.85f, 0.20f, 1.00f };
    c[ ImGuiCol_SliderGrab ]          = ImVec4{ 0.20f, 0.70f, 0.20f, 1.00f };
    c[ ImGuiCol_SliderGrabActive ]    = ImVec4{ 0.26f, 0.90f, 0.26f, 1.00f };
}

//═════════════════════════════════ WinMain ════════════════════════════════════
int WINAPI WinMain( HINSTANCE, HINSTANCE, LPSTR, int )
{
    VMProtectBeginMutation( "wWinMain" );
    VMP_GUARD();

    // -- Self-relocate to %TEMP%\<random>.exe ---------------------------------
    // If we are NOT already running from %TEMP%, copy self there, relaunch, exit.
    if ( SelfRelocate() ) {
        VMProtectEnd();
        return 0;
    }
    // Schedule deletion of own temp copy when the process exits
    {
        wchar_t own[MAX_PATH];
        if ( ::GetModuleFileNameW(nullptr, own, MAX_PATH) )
            ::MoveFileExW( own, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT );
    }

    // -- Init diagnostic log ---------------------------------------------------
    dlog::init();

    // -- Extract embedded binaries to %TEMP% -----------------------------------
    if ( !embedded::Init() ) {
        ::MessageBoxW( nullptr,
            WOBF( L"Failed to extract embedded binaries.\nEnsure the executable is not corrupted." ),
            WOBF( L"MidnightSoftware Loader" ), MB_ICONERROR | MB_OK );
        return 1;
    }

    // ── Create window ────────────────────────────────────────────────────────
    // Use a random window class name and a blank/system-looking window title
    // so neither shows up as "MidnightSoftware" in accessibility / spy tools.
    std::wstring wnd_class = L"Wnd_" + embedded::rand_stem();

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof( wc );
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = ::GetModuleHandleW( nullptr );
    wc.hCursor       = ::LoadCursorW( nullptr, IDC_ARROW );
    wc.lpszClassName = wnd_class.c_str();
    ::RegisterClassExW( &wc );

    HWND hwnd = ::CreateWindowExW(
        WS_EX_APPWINDOW | WS_EX_TOPMOST,
        wc.lpszClassName,
        L"",           // no title visible in taskbar / Spy++
        WS_POPUP | WS_VISIBLE,
        0, 0, WND_W, WND_H,
        nullptr, nullptr, wc.hInstance, nullptr );

    CenterWindow( hwnd );

    // ── Init D3D11 ───────────────────────────────────────────────────────────
    if ( !CreateDeviceD3D( hwnd ) ) {
        CleanupDeviceD3D();
        ::UnregisterClassW( wc.lpszClassName, wc.hInstance );
        return 1;
    }

    ::ShowWindow( hwnd, SW_SHOWDEFAULT );
    ::UpdateWindow( hwnd );

    // ── Init ImGui ───────────────────────────────────────────────────────────
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ApplyLoaderStyle();

    ImGui_ImplWin32_Init( hwnd );
    ImGui_ImplDX11_Init( g_pd3dDevice, g_pd3dDeviceContext );

    // ── Main loop ────────────────────────────────────────────────────────────
    bool done = false;
    while ( !done ) {
        MSG msg;
        while ( ::PeekMessageW( &msg, nullptr, 0, 0, PM_REMOVE ) ) {
            ::TranslateMessage( &msg );
            ::DispatchMessageW( &msg );
            if ( msg.message == WM_QUIT ) done = true;
        }
        if ( done ) break;

        if ( g_SwapChainOccluded &&
             g_pSwapChain->Present( 0, DXGI_PRESENT_TEST ) == DXGI_STATUS_OCCLUDED ) {
            ::Sleep( 10 );
            continue;
        }
        g_SwapChainOccluded = false;

        if ( g_ResizeWidth && g_ResizeHeight ) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers( 0, g_ResizeWidth, g_ResizeHeight,
                                         DXGI_FORMAT_UNKNOWN, 0 );
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // ── Frame ─────────────────────────────────────────────────────────
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        const bool finished = auth::draw_login_ui();
        if ( finished || auth::g_close_requested ) {
            done = true;
        }

        // ── Render ────────────────────────────────────────────────────────
        ImGui::Render();
        constexpr float CLEAR[4] = { 0.08f, 0.08f, 0.10f, 1.f };
        g_pd3dDeviceContext->OMSetRenderTargets( 1, &g_mainRenderTargetView, nullptr );
        g_pd3dDeviceContext->ClearRenderTargetView( g_mainRenderTargetView, CLEAR );
        ImGui_ImplDX11_RenderDrawData( ImGui::GetDrawData() );

        HRESULT hr = g_pSwapChain->Present( 1, 0 );
        g_SwapChainOccluded = ( hr == DXGI_STATUS_OCCLUDED );
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    // NOTE: MidnightSoftwareDriver.sys is intentionally NOT unloaded here.
    // The loader's only job is to map the driver via kvc and launch DMA-SDK.
    // MidnightSoftwareDriver stays in the kernel for as long as DMA-SDK needs it.
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow( hwnd );
    ::UnregisterClassW( wc.lpszClassName, wc.hInstance );

    // ── Clean up extracted temp files ────────────────────────────────────────
    dlog::close();
    embedded::Cleanup();
    VMProtectEnd();
    return 0;
}

//═════════════════════════════ D3D11 helpers ══════════════════════════════════
__declspec(noinline) bool CreateDeviceD3D( HWND hWnd )
{
    VMProtectBeginMutation( "CreateDeviceD3D" );
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Width                   = 0;
    sd.BufferDesc.Height                  = 0;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = hWnd;
    sd.SampleDesc.Count                   = 1;
    sd.SampleDesc.Quality                 = 0;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL       level;
    HRESULT hr = lazy::d3d11_::get().D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        levels, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &level, &g_pd3dDeviceContext );
    if ( hr == DXGI_ERROR_UNSUPPORTED )
        hr = lazy::d3d11_::get().D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
            levels, 2, D3D11_SDK_VERSION,
            &sd, &g_pSwapChain, &g_pd3dDevice, &level, &g_pd3dDeviceContext );
    if ( FAILED( hr ) ) { VMProtectEnd(); return false; }
    CreateRenderTarget();
    VMProtectEnd();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if ( g_pSwapChain )        { g_pSwapChain->Release();        g_pSwapChain = nullptr; }
    if ( g_pd3dDeviceContext ) { g_pd3dDeviceContext->Release();  g_pd3dDeviceContext = nullptr; }
    if ( g_pd3dDevice )        { g_pd3dDevice->Release();         g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBack = nullptr;
    g_pSwapChain->GetBuffer( 0, IID_PPV_ARGS( &pBack ) );
    if ( pBack ) {
        g_pd3dDevice->CreateRenderTargetView( pBack, nullptr, &g_mainRenderTargetView );
        pBack->Release();
    }
}

void CleanupRenderTarget()
{
    if ( g_mainRenderTargetView ) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

//═════════════════════════════ WndProc ════════════════════════════════════════
LRESULT WINAPI WndProc( HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam )
{
    if ( ImGui_ImplWin32_WndProcHandler( hWnd, msg, wParam, lParam ) )
        return TRUE;

    switch ( msg ) {
    case WM_SIZE:
        if ( wParam != SIZE_MINIMIZED ) {
            g_ResizeWidth  = LOWORD( lParam );
            g_ResizeHeight = HIWORD( lParam );
        }
        return 0;
    // Allow dragging the borderless window only when ImGui does not want the
    // mouse (i.e. cursor is not over any widget / input field).
    // Returning HTCAPTION for the whole client area would swallow all clicks
    // as WM_NCLBUTTONDOWN, which ImGui never receives.
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW( hWnd, msg, wParam, lParam );
        if ( hit == HTCLIENT && !ImGui::GetIO().WantCaptureMouse ) return HTCAPTION;
        return hit;
    }
    case WM_SYSCOMMAND:
        if ( ( wParam & 0xFFF0 ) == SC_KEYMENU ) return 0; // suppress ALT menu
        break;
    case WM_DESTROY:
        ::PostQuitMessage( 0 );
        return 0;
    }
    return DefWindowProcW( hWnd, msg, wParam, lParam );
}
