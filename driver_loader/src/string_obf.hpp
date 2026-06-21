#pragma once

//=============================================================================
//  string_obf.hpp  –  Compile-time XOR string obfuscation  (C++20)
//
//  Strategy
//  ─────────
//  Every string literal wrapped in OBF / WOBF is XOR-encrypted at compile
//  time and stored in the binary only as ciphertext.  Decryption happens at
//  runtime via a forced volatile read path that defeats constant-folding in
//  both MSVC and Clang/GCC.
//
//  Key derivation
//  ──────────────
//  Per-character key byte = Xorshift32( seed ^ Knuth(idx) )  folded to 8 bits
//  where seed is unique per macro invocation:
//    seed = ct_seed_from_time(__TIME__) ^ (__COUNTER__ * 1234567u + 987654321u)
//  __TIME__ = "HH:MM:SS" changes every second; __COUNTER__ increments per use.
//  Together they guarantee a distinct seed for every OBF/WOBF call site in the
//  entire TU, even when the same string literal is reused.
//
//  Decryption buffer
//  ─────────────────
//  Each template instantiation owns a thread_local static buffer.
//  The function returns a raw pointer valid for the duration of the statement.
//  Suitable for direct use in WinAPI calls (LPCSTR / LPCWSTR).
//
//  Macros
//  ──────
//    OBF(s)    – const char*    (narrow, decrypted on the fly)
//    OBFS(s)   – std::string    (narrow, heap copy)
//    WOBF(s)   – const wchar_t* (wide, decrypted on the fly)
//    WOBFS(s)  – std::wstring   (wide, heap copy)
//=============================================================================

#include <cstdint>
#include <cstddef>
#include <string>

namespace obf::detail {

//──────────────────────── compile-time seed from __TIME__ ─────────────────────
//  __TIME__ is always "HH:MM:SS" (9 chars including null).
//  We convert it to total-seconds [0, 86400) to get a 17-bit integer.
constexpr uint32_t ct_seed_from_time( const char* t ) noexcept
{
    return  ( static_cast<uint32_t>( t[0] - '0' ) * 10u + static_cast<uint32_t>( t[1] - '0' ) ) * 3600u
          + ( static_cast<uint32_t>( t[3] - '0' ) * 10u + static_cast<uint32_t>( t[4] - '0' ) ) * 60u
          + ( static_cast<uint32_t>( t[6] - '0' ) * 10u + static_cast<uint32_t>( t[7] - '0' ) );
}

//──────────────────────── per-character key byte ──────────────────────────────
//  Three rounds of Xorshift32 on (seed ^ Knuth_multiply(idx+1)),
//  then fold all 4 bytes to 8 bits and mix in an affine term on idx.
constexpr uint8_t key_byte( uint32_t seed, uint32_t idx ) noexcept
{
    uint32_t x = seed ^ ( ( idx + 1u ) * 2654435761u );  // Knuth multiplicative hash
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;            // xorshift32 round 1
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;            // xorshift32 round 2
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;            // xorshift32 round 3
    uint8_t b = static_cast<uint8_t>( x ^ ( x >> 8 ) ^ ( x >> 16 ) ^ ( x >> 24 ) );
    b = static_cast<uint8_t>( b ^ static_cast<uint8_t>( idx * 0x6Du ) );
    return b;
}

//──────────────────────── narrow (char) obfuscated string ─────────────────────
template<uint32_t Seed, std::size_t N>
struct ObfStr
{
    char enc[ N ];  // compile-time encrypted payload (only this lives in the binary)

    // consteval constructor: runs exclusively at compile time
    consteval explicit ObfStr( const char ( &src )[ N ] ) noexcept
    {
        for ( std::size_t i = 0; i < N; ++i )
            enc[ i ] = static_cast<char>(
                static_cast<uint8_t>( src[ i ] ) ^ key_byte( Seed, static_cast<uint32_t>( i ) ) );
    }

    // Decrypts through a volatile read so the optimizer cannot see through
    // the XOR to recover the plaintext from the compile-time enc[] values.
    [[nodiscard]] const char* decrypt() const noexcept
    {
        thread_local static char buf[ N ];
        volatile const char* ve = enc;   // volatile prevents constant-fold
        for ( std::size_t i = 0; i < N; ++i )
            buf[ i ] = static_cast<char>(
                static_cast<uint8_t>( ve[ i ] ) ^ key_byte( Seed, static_cast<uint32_t>( i ) ) );
        return buf;
    }

    [[nodiscard]] std::string str() const
    {
        return std::string( decrypt(), N - 1 );  // exclude null terminator
    }
};

//──────────────────────── wide (wchar_t) obfuscated string ────────────────────
template<uint32_t Seed, std::size_t N>
struct ObfWStr
{
    wchar_t enc[ N ];

    consteval explicit ObfWStr( const wchar_t ( &src )[ N ] ) noexcept
    {
        for ( std::size_t i = 0; i < N; ++i ) {
            const uint16_t raw = static_cast<uint16_t>( src[ i ] );
            const uint8_t  lo  = static_cast<uint8_t>( raw & 0xFFu )
                                ^ key_byte( Seed, static_cast<uint32_t>( i * 2u ) );
            const uint8_t  hi  = static_cast<uint8_t>( raw >> 8u )
                                ^ key_byte( Seed, static_cast<uint32_t>( i * 2u + 1u ) );
            enc[ i ] = static_cast<wchar_t>( static_cast<uint16_t>( lo )
                                           | ( static_cast<uint16_t>( hi ) << 8u ) );
        }
    }

    [[nodiscard]] const wchar_t* decrypt() const noexcept
    {
        thread_local static wchar_t buf[ N ];
        volatile const wchar_t* ve = enc;
        for ( std::size_t i = 0; i < N; ++i ) {
            const uint16_t raw = static_cast<uint16_t>( ve[ i ] );
            const uint8_t  lo  = static_cast<uint8_t>( raw & 0xFFu )
                                ^ key_byte( Seed, static_cast<uint32_t>( i * 2u ) );
            const uint8_t  hi  = static_cast<uint8_t>( raw >> 8u )
                                ^ key_byte( Seed, static_cast<uint32_t>( i * 2u + 1u ) );
            buf[ i ] = static_cast<wchar_t>( static_cast<uint16_t>( lo )
                                           | ( static_cast<uint16_t>( hi ) << 8u ) );
        }
        return buf;
    }

    [[nodiscard]] std::wstring str() const
    {
        return std::wstring( decrypt(), N - 1 );
    }
};

} // namespace obf::detail

//═══════════════════════════════ public macros ════════════════════════════════
//
//  _OBF_SEED(ctr)  –  unique 32-bit seed per call site
//    • __TIME__    : seconds-since-midnight (17 bits), unique per compilation
//    • ctr         : __COUNTER__ value (unique per expansion in the TU)
//    Combined they ensure distinct seeds even when many strings share the same
//    __TIME__ value (parallel builds, same-second compilations).
//
#define _OBF_SEED( ctr ) \
    static_cast<uint32_t>( \
        ::obf::detail::ct_seed_from_time( __TIME__ ) \
        ^ static_cast<uint32_t>( static_cast<uint32_t>( ctr ) * 1234567u + 987654321u ) \
    )

// ── OBF(s)  →  const char* (narrow, valid for the duration of the expression)
#define OBF( s ) \
    ( []() noexcept -> const char* { \
        static constexpr ::obf::detail::ObfStr< _OBF_SEED( __COUNTER__ ), sizeof( s ) > _o{ s }; \
        return _o.decrypt(); \
    }() )

// ── OBFS(s)  →  std::string (narrow, owned copy)
#define OBFS( s ) \
    ( []() -> std::string { \
        static constexpr ::obf::detail::ObfStr< _OBF_SEED( __COUNTER__ ), sizeof( s ) > _o{ s }; \
        return _o.str(); \
    }() )

// ── WOBF(s)  →  const wchar_t* (wide, valid for the duration of the expression)
#define WOBF( s ) \
    ( []() noexcept -> const wchar_t* { \
        static constexpr ::obf::detail::ObfWStr< _OBF_SEED( __COUNTER__ ), sizeof( s ) / sizeof( wchar_t ) > _o{ s }; \
        return _o.decrypt(); \
    }() )

// ── WOBFS(s)  →  std::wstring (wide, owned copy)
#define WOBFS( s ) \
    ( []() -> std::wstring { \
        static constexpr ::obf::detail::ObfWStr< _OBF_SEED( __COUNTER__ ), sizeof( s ) / sizeof( wchar_t ) > _o{ s }; \
        return _o.str(); \
    }() )
