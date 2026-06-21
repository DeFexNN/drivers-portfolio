#pragma once
#include "includes.hpp"

//=============================================================================
//  session_manager.hpp  –  DSE original CiCallback registry persistence
//
//  Translated verbatim from kvc-main / SessionManager.cpp
//  (DSE-NG Original Callback Management section)
//
//  Stores the original CiValidateImageHeader callback address in the registry
//  so it survives kvc.sys unload / process exit and enables reliable DSE
//  restore across sessions.
//
//  Registry key : HKCU\Software\kvc\DSE
//  Registry value : OriginalCiCallback  (REG_QWORD)
//=============================================================================

namespace session_manager {

// ── Save original CiCallback address ──────────────────────────────────────────
//  Call BEFORE patching, so address is the true kernel function pointer.
inline void SaveOriginalCiCallback( DWORD64 address ) noexcept
{
    HKEY hKey = nullptr;
    auto& reg = lazy::advapi32_::get();
    if ( reg.RegCreateKeyExW && reg.RegCreateKeyExW(
             HKEY_CURRENT_USER, WOBF( L"Software\\kvc\\DSE" ), 0, nullptr,
             REG_OPTION_NON_VOLATILE, KEY_WRITE,
             nullptr, &hKey, nullptr ) == ERROR_SUCCESS )
    {
        if ( reg.RegSetValueExW )
            reg.RegSetValueExW( hKey, WOBF( L"OriginalCiCallback" ), 0, REG_QWORD,
                                reinterpret_cast<const BYTE*>( &address ),
                                sizeof( DWORD64 ) );
        if ( reg.RegCloseKey ) reg.RegCloseKey( hKey );
    }
}

// ── Load original CiCallback address ──────────────────────────────────────────
//  Returns 0 if no address was saved (first run or was cleared).
inline DWORD64 GetOriginalCiCallback() noexcept
{
    HKEY   hKey  = nullptr;
    DWORD64 value = 0;
    DWORD  sz    = sizeof( DWORD64 );

    auto& reg = lazy::advapi32_::get();
    if ( reg.RegOpenKeyExW && reg.RegOpenKeyExW(
             HKEY_CURRENT_USER, WOBF( L"Software\\kvc\\DSE" ), 0,
             KEY_READ, &hKey ) == ERROR_SUCCESS )
    {
        if ( reg.RegQueryValueExW )
            reg.RegQueryValueExW( hKey, WOBF( L"OriginalCiCallback" ), nullptr, nullptr,
                                  reinterpret_cast<BYTE*>( &value ), &sz );
        if ( reg.RegCloseKey ) reg.RegCloseKey( hKey );
    }
    return value;
}

// ── Erase saved address ────────────────────────────────────────────────────────
//  Call after a successful restore to avoid replaying a stale boot's address.
inline void ClearOriginalCiCallback() noexcept
{
    HKEY hKey = nullptr;
    auto& reg = lazy::advapi32_::get();
    if ( reg.RegOpenKeyExW && reg.RegOpenKeyExW(
             HKEY_CURRENT_USER, WOBF( L"Software\\kvc\\DSE" ), 0,
             KEY_WRITE, &hKey ) == ERROR_SUCCESS )
    {
        if ( reg.RegDeleteValueW ) reg.RegDeleteValueW( hKey, WOBF( L"OriginalCiCallback" ) );
        if ( reg.RegCloseKey    ) reg.RegCloseKey( hKey );
    }
}

} // namespace session_manager

//=============================================================================
//  key_store  –  Persistent auth-key storage
//
//  Saves the validated license key in the registry, XOR-obfuscated so it is
//  not stored as plain text.  On next launch the stored key is loaded and
//  submitted automatically – the user does not need to re-enter it.
//
//  Registry key  : HKCU\Software\kvc\Auth
//  Registry value: Key  (REG_BINARY)  – bytes XOR'd with XOR_MASK
//=============================================================================
namespace key_store {

static constexpr uint8_t XOR_MASK[8] = {
    0xDE, 0xF3, 0x7A, 0xC0, 0x1B, 0x9E, 0x45, 0xF8
};
static constexpr DWORD   MAX_KEY_LEN = 127;

// ── Save a validated key ────────────────────────────────────────────────────
inline void save( const std::string& key ) noexcept
{
    if ( key.empty() ) return;
    uint8_t buf[ MAX_KEY_LEN + 1 ]{};
    const DWORD n = static_cast<DWORD>(
        (std::min)( key.size(), static_cast<size_t>( MAX_KEY_LEN ) ) );
    buf[0] = static_cast<uint8_t>( n );          // first byte = length
    for ( DWORD i = 0; i < n; ++i )
        buf[i + 1] = static_cast<uint8_t>( key[i] ) ^ XOR_MASK[i % 8];

    HKEY hKey = nullptr;
    auto& reg = lazy::advapi32_::get();
    if ( reg.RegCreateKeyExW && reg.RegCreateKeyExW(
             HKEY_CURRENT_USER, L"Software\\kvc\\Auth", 0, nullptr,
             REG_OPTION_NON_VOLATILE, KEY_WRITE,
             nullptr, &hKey, nullptr ) == ERROR_SUCCESS )
    {
        if ( reg.RegSetValueExW )
            reg.RegSetValueExW( hKey, L"Key", 0, REG_BINARY,
                                buf, n + 1 );
        if ( reg.RegCloseKey ) reg.RegCloseKey( hKey );
    }
}

// ── Load the saved key (returns empty string if none) ──────────────────────
inline std::string load() noexcept
{
    HKEY    hKey = nullptr;
    uint8_t buf[ MAX_KEY_LEN + 2 ]{};
    DWORD   sz   = sizeof( buf );
    DWORD   type = 0;

    auto& reg = lazy::advapi32_::get();
    if ( !reg.RegOpenKeyExW || !reg.RegQueryValueExW )
        return {};
    if ( reg.RegOpenKeyExW(
             HKEY_CURRENT_USER, L"Software\\kvc\\Auth",
             0, KEY_READ, &hKey ) != ERROR_SUCCESS )
        return {};

    LONG r = reg.RegQueryValueExW( hKey, L"Key", nullptr, &type, buf, &sz );
    if ( reg.RegCloseKey ) reg.RegCloseKey( hKey );

    if ( r != ERROR_SUCCESS || type != REG_BINARY || sz < 2 )
        return {};

    const DWORD n = (std::min)( static_cast<DWORD>( buf[0] ),
                                 static_cast<DWORD>( sz - 1 ) );
    if ( n == 0 || n > MAX_KEY_LEN ) return {};

    std::string key( n, '\0' );
    for ( DWORD i = 0; i < n; ++i )
        key[i] = static_cast<char>( buf[i + 1] ^ XOR_MASK[i % 8] );
    return key;
}

// ── Erase the saved key (call on validation failure) ───────────────────────
inline void clear() noexcept
{
    HKEY hKey = nullptr;
    auto& reg = lazy::advapi32_::get();
    if ( reg.RegOpenKeyExW && reg.RegOpenKeyExW(
             HKEY_CURRENT_USER, L"Software\\kvc\\Auth",
             0, KEY_WRITE, &hKey ) == ERROR_SUCCESS )
    {
        if ( reg.RegDeleteValueW ) reg.RegDeleteValueW( hKey, L"Key" );
        if ( reg.RegCloseKey )     reg.RegCloseKey( hKey );
    }
}

} // namespace key_store
