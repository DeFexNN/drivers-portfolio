#pragma once
//=============================================================================
//  handshake.hpp  –  MidnightSoftware Loader  →  War Thunder SDK  session token writer
//
//  Writes a cryptographic 128-byte token into named shared memory before
//  the SDK overlay is launched.  The SDK reads and verifies this token at
//  startup; if the segment is absent or the MAC does not match the process
//  terminates immediately.
//
//  Protocol overview
//  -----------------
//    1.  Loader calls handshake::write(hwid, key, expires_at).
//    2.  A random 32-bit nonce is generated (GetTickCount64 ^ PID).
//    3.  Block is filled: magic, version, issued_at, key (XOR-masked), expiry,
//        nonce, and a 32-byte custom MAC over all fields.
//    4.  Block is written to the named file-mapping
//          Global\MidnightSoftware_WT_<HWID8>
//        (first 8 chars of the HWID make the name unique per machine).
//    5.  The HANDLE returned by write() must be kept open until the loader
//        process exits; closing it destroys the shared memory.
//    6.  SDK (core/handshake.hpp) opens the mapping, validates magic,
//        checks freshness (≤120 s), re-derives the MAC, and terminates
//        immediately on any mismatch.
//
//  Custom MAC
//  ----------
//  Two-pass HMAC-like construction using a 4-lane, 64-bit multiply-rotate
//  mixing function (similar to SipHash) over a 32-byte compile-time secret
//  split across two 16-byte arrays to resist simple pattern scans.
//  In the SDK the verify() function is wrapped in VMProtectBeginUltra so
//  the full body is virtualized and cannot be statically reversed.
//=============================================================================
#include "includes.hpp"
#include "string_obf.hpp"

namespace handshake {

// ─────────────────────────────── Block layout ─────────────────────────────────
// 128 bytes – two cache lines.  Must match core/handshake.hpp in the SDK.
#pragma pack(push, 1)
struct Block {
    uint32_t magic;           // 0xDEF3C0DE
    uint32_t version;         // 1
    uint64_t issued_at;       // Unix seconds when loader wrote this block
    uint64_t key_expires_at;  // Unix seconds (0 = lifetime / unknown)
    char     key_str[64];     // license key, XOR-obfuscated in memory
    uint8_t  mac[32];         // custom HMAC-like 256-bit tag
    uint32_t nonce;           // mixed into MAC; prevents replay of stale blocks
    uint8_t  _pad[4];
};
#pragma pack(pop)
static_assert( sizeof(Block) == 128, "handshake::Block size mismatch" );

// ─────────────────────────────── Compile-time secret ──────────────────────────
// 32 bytes split into two 16-byte arrays.  Both driver_loader and
// war_thunder_sdk contain identical values surrounded by different code so
// a pattern scan of one binary cannot locate the full secret in the other.
static constexpr uint8_t SECRET_A[16] = {
    0x7F, 0xC3, 0x9A, 0x14, 0xB6, 0x2D, 0xE8, 0x51,
    0x0A, 0x3F, 0xCC, 0x77, 0x19, 0xD4, 0x8B, 0x60
};
static constexpr uint8_t SECRET_B[16] = {
    0xA1, 0x5E, 0x27, 0xF9, 0x43, 0x8C, 0xB0, 0x6D,
    0xEC, 0x32, 0x74, 0x1A, 0x9F, 0x56, 0xD8, 0x03
};

// In-memory XOR mask applied to key_str stored inside the Block.
// (Separate from the MAC; prevents accidental key exposure in memory dumps.)
static constexpr uint8_t KEY_XOR[8] = {
    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89
};

// ─────────────────────────────── MAC primitives ───────────────────────────────

static inline uint64_t hs_rotl64( uint64_t v, int s ) noexcept
{
    return ( v << s ) | ( v >> ( 64 - s ) );
}

// SipHash-like lane mixing step.
static void hs_mix( uint64_t st[4], uint64_t w ) noexcept
{
    st[0] ^= w;
    st[0]  = hs_rotl64( st[0] * 0x9E3779B185EBCA87ULL, 27 ) ^ st[1];
    st[1]  = hs_rotl64( st[1], 31 ) + st[0];
    st[2] ^= st[1];
    st[2]  = hs_rotl64( st[2] * 0xC949D7C7509E6557ULL, 25 ) ^ st[3];
    st[3]  = hs_rotl64( st[3], 37 ) + st[2];
    // Cross-lane diffusion
    st[0] ^= st[3];
    st[1] ^= st[2];
}

// One pass of the two-pass HMAC-like construction.
// Initialises 4 lanes from (key XOR pad), then mixes in all data bytes.
static void hs_pass( uint64_t        st[4],
                     const uint8_t   key[32],
                     uint8_t         pad,
                     const uint8_t*  data,
                     size_t          len,
                     uint8_t         out[32] ) noexcept
{
    uint8_t k[32];
    for ( int i = 0; i < 32; ++i ) k[i] = key[i] ^ pad;
    memcpy( st, k, 32 );
    // Domain separator primes
    hs_mix( st, 0xDEF3C0DE12345678ULL );
    hs_mix( st, 0xABCDEF0123456789ULL );

    size_t i = 0;
    for ( ; i + 8 <= len; i += 8 ) {
        uint64_t w = 0;
        memcpy( &w, data + i, 8 );
        hs_mix( st, w );
    }
    if ( i < len ) {
        uint64_t tail = 0;
        memcpy( &tail, data + i, len - i );
        // Encode remaining byte count in the high byte of the tail word
        hs_mix( st, tail | ( (uint64_t)( len - i ) << 56 ) );
    }
    // Length finaliser
    hs_mix( st, (uint64_t)len ^ 0xFF01020304050607ULL );
    // Finalisation rounds
    for ( int r = 0; r < 4; ++r )
        hs_mix( st, (uint64_t)r * 0x6C62272E07BB0142ULL );
    memcpy( out, st, 32 );
}

// compute_mac – assemble input buffer and run two-pass HMAC-like MAC.
static void compute_mac( const char*  hwid,
                          uint64_t     issued_at,
                          uint32_t     nonce,
                          const char*  key_plain,
                          uint64_t     key_expires_at,
                          uint8_t      out[32] ) noexcept
{
    uint8_t secret[32];
    memcpy( secret,      SECRET_A, 16 );
    memcpy( secret + 16, SECRET_B, 16 );

    // Build concatenated input buffer: hwid | issued_at | nonce | key | expiry
    char hwid_buf[64]{};
    char key_buf[64]{};
    strncpy_s( hwid_buf, hwid,      63 );
    strncpy_s( key_buf,  key_plain, 63 );

    uint8_t data[200]{};
    size_t  off = 0;
    auto app = [&]( const void* p, size_t n ) noexcept {
        if ( off + n <= sizeof(data) ) { memcpy( data + off, p, n ); off += n; }
    };
    app( hwid_buf,        strnlen( hwid_buf, 63 ) );
    app( &issued_at,      8 );
    app( &nonce,          4 );
    app( key_buf,         strnlen( key_buf,  63 ) );
    app( &key_expires_at, 8 );

    uint64_t st[4];
    uint8_t  inner[32];
    hs_pass( st, secret, 0x36, data, off, inner );   // inner hash

    uint64_t st2[4];
    hs_pass( st2, secret, 0x5C, inner, 32, out );    // outer hash
}

// ─────────────────────────────── Utilities ────────────────────────────────────

static inline uint64_t hs_unix_now() noexcept
{
    FILETIME ft;
    ::GetSystemTimeAsFileTime( &ft );
    uint64_t v = ( (uint64_t)ft.dwHighDateTime << 32 ) | ft.dwLowDateTime;
    return ( v - 116444736000000000ULL ) / 10000000ULL;
}

static inline std::wstring make_shm_name( const std::string& hwid )
{
    wchar_t buf[64];
    wchar_t hw[9]{};
    for ( int i = 0; i < 8 && i < (int)hwid.size(); ++i )
        hw[i] = (wchar_t)(unsigned char)hwid[i];
    swprintf_s( buf, L"Global\\MidnightSoftware_WT_%s", hw );
    return buf;
}

// ─────────────────────────────── write() ──────────────────────────────────────
// Call BEFORE CreateProcess on the SDK payload.
//
// Parameters
//   hwid           : from fb_auth::get_hwid()
//   key_plain      : the validated license key string
//   key_expires_at : Unix seconds from Firebase (0 = lifetime / unknown)
//
// Returns an open HANDLE to the file-mapping object.
// Keep it open until the loader process exits; closing it destroys the
// shared-memory segment and the SDK can no longer find the token.
[[nodiscard]] inline HANDLE write( const std::string& hwid,
                                   const std::string& key_plain,
                                   uint64_t           key_expires_at ) noexcept
{
    // Non-cryptographic nonce; replay protection relies on the timestamp +
    // freshness window, not on nonce secrecy.
    ::srand( (unsigned)( ::GetTickCount64() ^ (uint64_t)::GetCurrentProcessId() ) );
    const uint32_t nonce   = ( (uint32_t)::rand() << 16 ) ^ (uint32_t)::rand();
    const uint64_t issued  = hs_unix_now();

    Block blk{};
    blk.magic          = 0xDEF3C0DE;
    blk.version        = 1;
    blk.issued_at      = issued;
    blk.key_expires_at = key_expires_at;
    blk.nonce          = nonce;

    // XOR-mask key so it doesn't sit plaintext in the shared page.
    const size_t klen = ( std::min )( key_plain.size(), (size_t)63 );
    for ( size_t i = 0; i < 64; ++i )
        blk.key_str[i] = (char)( ( i < klen ? (uint8_t)key_plain[i] : 0u )
                                  ^ KEY_XOR[i % 8] );

    // Sign the block.
    compute_mac( hwid.c_str(), issued, nonce,
                 key_plain.c_str(), key_expires_at, blk.mac );

    // Create named file-mapping (DACL=nullptr → creator-only access).
    const std::wstring name = make_shm_name( hwid );
    HANDLE hMap = ::CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, (DWORD)sizeof(Block),
        name.c_str() );
    if ( !hMap ) return nullptr;

    void* pv = ::MapViewOfFile( hMap, FILE_MAP_WRITE, 0, 0, sizeof(Block) );
    if ( !pv ) { ::CloseHandle( hMap ); return nullptr; }

    memcpy( pv, &blk, sizeof(Block) );
    ::SecureZeroMemory( &blk, sizeof(blk) );  // wipe key from stack
    ::UnmapViewOfFile( pv );

    // Return the mapping handle – caller owns it.
    return hMap;
}

} // namespace handshake
