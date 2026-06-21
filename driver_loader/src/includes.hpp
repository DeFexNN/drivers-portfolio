#pragma once

//=============================================================================
//  includes.hpp  –  common headers for driver_loader
//=============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wrl/client.h>
#include <d3d11.h>
// d3d11.lib / dxgi.lib resolved at runtime via lazy::d3d11_::get()
#include <dwmapi.h>
#pragma comment( lib, "dwmapi.lib" )
#include <shlwapi.h>
#pragma comment( lib, "shlwapi.lib" )
#include <shellapi.h>
// shell32.lib resolved at runtime via lazy::shell32_::get()

#include <tlhelp32.h>
#include <psapi.h>      // type declarations only – resolved dynamically via lazy_api.hpp
#include <winreg.h>

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <filesystem>
#include <format>

// ── Dear ImGui ───────────────────────────────────────────────────────────────
#include <imgui.h>
#include <imgui_internal.h>
#include <backends/imgui_impl_win32.h>
#include <backends/imgui_impl_dx11.h>

// ── Compile-time XOR string obfuscation ──────────────────────────────────────
//  OBF(s)   → const char*    WOBF(s)   → const wchar_t*
//  OBFS(s)  → std::string    WOBFS(s)  → std::wstring
#include "string_obf.hpp"

// ── Runtime format helper for obfuscated format strings ──────────────────────
//  std::format() requires a compile-time format-string literal.
//  Use wfmt(WOBFS(L"..."), args...) when the string must be obfuscated at RT.
template<class... Args>
[[nodiscard]] inline std::wstring wfmt( std::wstring fmt_str, Args... args )
{
    return std::vformat( std::wstring_view( fmt_str ),
        std::make_wformat_args( args... ) );
}

// ── Lazy IAT-hiding loaders for Win32 APIs ────────────────────────────────────
//  kernel32 / dbghelp / winhttp / advapi32 / user32 / gdi32 /
//  shell32 / imm32 / d3d11 / d3dcompiler resolved fully at runtime.
#include "lazy_api.hpp"
