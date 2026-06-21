#pragma once
#include "includes.hpp"
#include <cstdio>

//=============================================================================
//  log.hpp  –  minimal file logger for driver_loader diagnostics
//
//  All output goes to %TEMP%\midnight_loader.log (UTF-8, appended each run).
//  Call dlog::init() once at startup; dlog::write() anywhere afterwards.
//=============================================================================

namespace dlog {

inline std::wstring g_log_path;
inline FILE*        g_fp = nullptr;

inline void init() noexcept
{
    wchar_t tmp[MAX_PATH]{};
    ::GetTempPathW( MAX_PATH, tmp );
    g_log_path = std::wstring( tmp ) + WOBFS( L"midnight_loader.log" );

    // Convert path to narrow for fopen_s (UTF-8, plain append – no CRT encoding shenanigans)
    int plen = ::WideCharToMultiByte( CP_UTF8, 0, g_log_path.c_str(), -1,
                                      nullptr, 0, nullptr, nullptr );
    if ( plen <= 0 ) return;
    std::string narrow_path( static_cast<size_t>( plen - 1 ), '\0' );
    ::WideCharToMultiByte( CP_UTF8, 0, g_log_path.c_str(), -1,
                           narrow_path.data(), plen, nullptr, nullptr );

    fopen_s( &g_fp, narrow_path.c_str(), "a" );
    if ( !g_fp ) return;

    // session header
    SYSTEMTIME st{};
    ::GetLocalTime( &st );
    std::fprintf( g_fp,
        "\n=== MidnightSoftware Loader session %04d-%02d-%02d %02d:%02d:%02d ===\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond );
    std::fflush( g_fp );
}

inline void write( const wchar_t* msg ) noexcept
{
    if ( !g_fp ) return;
    // Narrow to UTF-8
    int len = ::WideCharToMultiByte( CP_UTF8, 0, msg, -1,
                                     nullptr, 0, nullptr, nullptr );
    if ( len <= 0 ) return;
    std::string s( static_cast<size_t>( len - 1 ), '\0' );
    ::WideCharToMultiByte( CP_UTF8, 0, msg, -1,
                           s.data(), len, nullptr, nullptr );
    std::fprintf( g_fp, "%s\n", s.c_str() );
    std::fflush( g_fp );
}

inline void write( const std::wstring& msg ) noexcept { write( msg.c_str() ); }

inline void close() noexcept
{
    if ( g_fp ) { std::fclose( g_fp ); g_fp = nullptr; }
}

} // namespace dlog
