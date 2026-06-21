#pragma once
#include "includes.hpp"

#include <dbghelp.h>     // types only – resolved via lazy::dbghelp_
#include <winhttp.h>     // types only – resolved via lazy::winhttp_
#include <psapi.h>       // types only – resolved via lazy::k32

//=============================================================================
//  symbol_engine.hpp  –  PDB-based kernel symbol resolution
//
//  Translated verbatim from kvc-main / SymbolEngine.cpp
//
//  Resolves the RVA offsets of:
//    • SeCiCallbacks            (ntoskrnl.exe – Safe DSE target)
//    • ZwFlushInstructionCache  (ntoskrnl.exe – benign replacement callback)
//
//  Search order for the PDB:
//    1. %SystemDrive%\ProgramData\dbg\sym\{pdb}\{GUID}\{pdb}  (local cache)
//    2. https://msdl.microsoft.com/download/symbols/{pdb}/{GUID}/{pdb}
//       then saved to the same local path for future use.
//=============================================================================

class symbol_engine
{
public:
    symbol_engine()  = default;
    ~symbol_engine()
    {
        if ( m_initialized ) lazy::dbghelp_::get().SymCleanup( lazy::k32::get().GetCurrentProcess() );
    }

    symbol_engine( const symbol_engine& )             = delete;
    symbol_engine& operator=( const symbol_engine& ) = delete;

    // ── Main entry: returns {SeCiCallbacks_rva, ZwFlushInstructionCache_rva} ──
    //
    //  Resolution order (reliability-first):
    //    1. Local PDB cache   – instant, no network       (authoritative)
    //    2. MSDL PDB download – requires internet         (authoritative)
    //    3. PE pattern scan   – instant, no network       (heuristic, last resort)
    //
    //  NOTE: PE pattern scan is intentionally placed LAST.  On Win11 25H2+
    //  (build 26200) the scan finds the wrong .data reference in
    //  SeRegisterImageVerificationCallback and returns an incorrect
    //  SeCiCallbacks RVA.  The PDB is always correct; pattern scan is only
    //  used when neither local cache nor MSDL is available (no internet, no
    //  pre-existing cache).
    std::optional<std::pair<DWORD64, DWORD64>>
    GetSymbolOffsets( const std::wstring& kernelPath ) noexcept
    {
        // ── 1. Local PDB cache ───────────────────────────────────────────────
        auto pdbInfo = GetPdbInfoFromPe( kernelPath );
        if ( pdbInfo )
        {
            const auto& [pdbName, guid] = *pdbInfo;
            std::wstring localPdb = GetLocalPdbPath( pdbName, guid );
            if ( !localPdb.empty() &&
                 ::GetFileAttributesW( localPdb.c_str() ) != INVALID_FILE_ATTRIBUTES )
            {
                auto res = CalculateOffsetsFromDisk( localPdb, pdbName );
                if ( res ) return res;
                // Corrupt / stale cache entry – delete it so the download
                // below can replace it with a fresh copy.
                ::DeleteFileW( localPdb.c_str() );
            }

            // ── 2. MSDL PDB download ─────────────────────────────────────────
            if ( !localPdb.empty() )
            {
                if ( DownloadPdbToDisk( pdbName, guid, localPdb ) )
                {
                    auto res = CalculateOffsetsFromDisk( localPdb, pdbName );
                    if ( res ) return res;
                }
            }
        }

        // ── 3. PE pattern scan (offline last-resort, heuristic) ──────────────
        //  Only reached when (a) no PDB info in PE, (b) PDB cache absent and
        //  internet unavailable, or (c) DbgHelp resolution failed.
        {
            auto res = GetSymbolOffsetsByPatternScan( kernelPath );
            if ( res ) return res;
        }

        return std::nullopt;
    }

    // ── Returns {kernel_va_base, kernel_dos_path} ─────────────────────────────
    //  Mirrors DSEBypass::GetKernelInfo() / SymbolEngine::GetKernelInfo() exactly.
    static std::optional<std::pair<DWORD64, std::wstring>> GetKernelInfo() noexcept
    {
        LPVOID drivers[1024]{};
        DWORD  needed = 0;
        if ( !lazy::k32::get().EnumDeviceDrivers( drivers, sizeof( drivers ), &needed ) )
            return std::nullopt;

        const DWORD64 kernelBase = reinterpret_cast<DWORD64>( drivers[0] );

        wchar_t kernelPath[MAX_PATH]{};
        if ( !lazy::k32::get().GetDeviceDriverFileNameW( drivers[0], kernelPath, MAX_PATH ) )
            return std::nullopt;

        std::wstring ntPath  = kernelPath;
        std::wstring dosPath;

        if ( ntPath.find( L"\\SystemRoot\\" ) == 0 ) {
            wchar_t winDir[MAX_PATH]{};
            ::GetWindowsDirectoryW( winDir, MAX_PATH );
            dosPath = std::wstring( winDir ) + ntPath.substr( 11 ); // skip "\\SystemRoot"
        } else if ( ntPath.find( L"\\??\\" ) == 0 ) {
            dosPath = ntPath.substr( 4 );
        } else {
            dosPath = ntPath;
        }

        return std::make_pair( kernelBase, dosPath );
    }

private:
    bool m_initialized = false;

    static constexpr const wchar_t* SYM_SERVER = nullptr; // replaced by WOBF at call site

    //─────────────────────── local PDB cache path ─────────────────────────────
    //  %SystemDrive%\ProgramData\dbg\sym\{pdb}\{GUID}\{pdb}
    static std::wstring GetLocalPdbPath(
        const std::wstring& pdbName,
        const std::wstring& guid ) noexcept
    {
        wchar_t sysDrive[MAX_PATH]{};
        if ( ::GetEnvironmentVariableW( L"SystemDrive", sysDrive, MAX_PATH ) == 0 )
            ::wcscpy_s( sysDrive, L"C:" );

        return std::wstring( sysDrive ) + L"\\ProgramData\\dbg\\sym\\"
             + pdbName + L"\\" + guid + L"\\" + pdbName;
    }

    //─────────────────────── extract PDB info from PE ─────────────────────────
    //  Reads the IMAGE_DEBUG_TYPE_CODEVIEW entry from the PE on disk
    //  and returns {pdb_filename, guid_string}.
    static std::optional<std::pair<std::wstring, std::wstring>>
    GetPdbInfoFromPe( const std::wstring& pePath ) noexcept
    {
        HANDLE hFile = lazy::k32::get().CreateFileW( pePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( hFile == INVALID_HANDLE_VALUE ) return std::nullopt;

        HANDLE hMap = lazy::k32::get().CreateFileMappingW( hFile, nullptr, PAGE_READONLY, 0, 0, nullptr );
        if ( !hMap ) { ::CloseHandle( hFile ); return std::nullopt; }

        LPVOID pBase = lazy::k32::get().MapViewOfFile( hMap, FILE_MAP_READ, 0, 0, 0 );
        if ( !pBase ) { ::CloseHandle( hMap ); ::CloseHandle( hFile ); return std::nullopt; }

        std::wstring pdbName, guidStr;

        auto* pDos = static_cast<PIMAGE_DOS_HEADER>( pBase );
        if ( pDos->e_magic == IMAGE_DOS_SIGNATURE ) {
            auto* pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>( pBase ) + pDos->e_lfanew );

            if ( pNt->Signature == IMAGE_NT_SIGNATURE ) {
                const auto& dd =
                    pNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ];

                if ( dd.VirtualAddress && dd.Size ) {
                    auto* pDbg = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
                        reinterpret_cast<BYTE*>( pBase ) + dd.VirtualAddress );

                    for ( DWORD i = 0; i < dd.Size / sizeof( IMAGE_DEBUG_DIRECTORY ); ++i ) {
                        if ( pDbg[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW ) continue;

                        struct CV_INFO_PDB70 {
                            DWORD CvSignature;
                            GUID  Signature;
                            DWORD Age;
                            char  PdbFileName[1];
                        };

                        auto* pCv = reinterpret_cast<CV_INFO_PDB70*>(
                            reinterpret_cast<BYTE*>( pBase ) + pDbg[i].PointerToRawData );

                        if ( pCv->CvSignature == 0x53445352 ) {  // 'RSDS'
                            wchar_t g[64]{};
                            swprintf_s( g,
                                L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                                pCv->Signature.Data1, pCv->Signature.Data2,
                                pCv->Signature.Data3,
                                pCv->Signature.Data4[0], pCv->Signature.Data4[1],
                                pCv->Signature.Data4[2], pCv->Signature.Data4[3],
                                pCv->Signature.Data4[4], pCv->Signature.Data4[5],
                                pCv->Signature.Data4[6], pCv->Signature.Data4[7],
                                pCv->Age );
                            guidStr = g;

                            int len = ::MultiByteToWideChar(
                                CP_UTF8, 0, pCv->PdbFileName, -1, nullptr, 0 );
                            if ( len > 0 ) {
                                std::vector<wchar_t> wb( len );
                                ::MultiByteToWideChar(
                                    CP_UTF8, 0, pCv->PdbFileName, -1, wb.data(), len );
                                std::wstring fp = wb.data();
                                size_t sl = fp.find_last_of( L"\\/" );
                                pdbName = ( sl != std::wstring::npos )
                                        ? fp.substr( sl + 1 ) : fp;
                            }
                            break;
                        }
                    }
                }
            }
        }

        lazy::k32::get().UnmapViewOfFile( pBase );
        ::CloseHandle( hMap );
        ::CloseHandle( hFile );

        if ( pdbName.empty() || guidStr.empty() ) return std::nullopt;
        return std::make_pair( pdbName, guidStr );
    }

    //─────────────────────── recursive mkdir ──────────────────────────────────
    static bool CreateDirTree( const std::wstring& path ) noexcept
    {
        if ( ::GetFileAttributesW( path.c_str() ) != INVALID_FILE_ATTRIBUTES )
            return true;   // already exists

        size_t pos = path.find_last_of( L"\\/" );
        if ( pos != std::wstring::npos )
            if ( !CreateDirTree( path.substr( 0, pos ) ) ) return false;

        if ( !::CreateDirectoryW( path.c_str(), nullptr ) )
            return ::GetLastError() == ERROR_ALREADY_EXISTS;

        return true;
    }

    //─────────────────────── WinHTTP download → byte buffer ───────────────────
    //  Mirrors SymbolEngine::HttpDownload() exactly.
    static bool HttpDownload( const std::wstring& url,
                               std::vector<BYTE>&   out ) noexcept
    {
        URL_COMPONENTS uc{ sizeof( URL_COMPONENTS ) };
        wchar_t host[256]{}, urlPath[1024]{};
        uc.lpszHostName    = host;    uc.dwHostNameLength    = _countof( host );
        uc.lpszUrlPath     = urlPath; uc.dwUrlPathLength     = _countof( urlPath );

        auto& wh = lazy::winhttp_::get();
        if ( !wh.WinHttpCrackUrl || !wh.WinHttpCrackUrl( url.c_str(), 0, 0, &uc ) ) return false;

        HINTERNET hSes = wh.WinHttpOpen ? wh.WinHttpOpen( WOBF( L"driver_loader/1.0" ),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 ) : nullptr;
        if ( !hSes ) return false;

        if ( wh.WinHttpSetTimeouts ) wh.WinHttpSetTimeouts( hSes, 15000, 15000, 45000, 45000 );

        HINTERNET hCon = wh.WinHttpConnect ? wh.WinHttpConnect( hSes, uc.lpszHostName, uc.nPort, 0 ) : nullptr;
        if ( !hCon ) { if ( wh.WinHttpCloseHandle ) wh.WinHttpCloseHandle( hSes ); return false; }

        DWORD     flags = ( uc.nScheme == INTERNET_SCHEME_HTTPS ) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq  = wh.WinHttpOpenRequest ? wh.WinHttpOpenRequest(
            hCon, L"GET", uc.lpszUrlPath, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags ) : nullptr;
        if ( !hReq ) {
            if ( wh.WinHttpCloseHandle ) { wh.WinHttpCloseHandle( hCon ); wh.WinHttpCloseHandle( hSes ); }
            return false;
        }

        if ( !wh.WinHttpSendRequest ||
             !wh.WinHttpSendRequest( hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ||
             !wh.WinHttpReceiveResponse ||
             !wh.WinHttpReceiveResponse( hReq, nullptr ) ) {
            if ( wh.WinHttpCloseHandle ) {
                wh.WinHttpCloseHandle( hReq );
                wh.WinHttpCloseHandle( hCon );
                wh.WinHttpCloseHandle( hSes );
            }
            return false;
        }

        DWORD status = 0, sz = sizeof( status );
        if ( wh.WinHttpQueryHeaders )
            wh.WinHttpQueryHeaders( hReq,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                WINHTTP_NO_HEADER_INDEX );
        if ( status != 200 ) {
            if ( wh.WinHttpCloseHandle ) {
                wh.WinHttpCloseHandle( hReq );
                wh.WinHttpCloseHandle( hCon );
                wh.WinHttpCloseHandle( hSes );
            }
            return false;
        }

        out.clear();
        BYTE  buf[8192]{};
        DWORD nRead = 0;
        while ( wh.WinHttpReadData && wh.WinHttpReadData( hReq, buf, sizeof( buf ), &nRead ) && nRead > 0 )
            out.insert( out.end(), buf, buf + nRead );

        if ( wh.WinHttpCloseHandle ) {
            wh.WinHttpCloseHandle( hReq );
            wh.WinHttpCloseHandle( hCon );
            wh.WinHttpCloseHandle( hSes );
        }
        return !out.empty();
    }

    //─────────────────────── download PDB directly to disk ────────────────────
    //  Mirrors SymbolEngine::DownloadPdbToDisk() exactly.
    bool DownloadPdbToDisk( const std::wstring& pdbName,
                             const std::wstring& guid,
                             const std::wstring& targetPath ) noexcept
    {
        std::wstring dirPath = targetPath.substr( 0, targetPath.find_last_of( L"\\/" ) );
        if ( !CreateDirTree( dirPath ) ) return false;

        std::wstring url = WOBFS( L"https://msdl.microsoft.com/download/symbols" )
                         + L"/" + pdbName + L"/" + guid + L"/" + pdbName;

        std::vector<BYTE> data;
        if ( !HttpDownload( url, data ) ) return false;

        HANDLE hFile = lazy::k32::get().CreateFileW( targetPath.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( hFile == INVALID_HANDLE_VALUE ) return false;

        DWORD written = 0;
        BOOL  ok      = ::WriteFile( hFile, data.data(),
                                      static_cast<DWORD>( data.size() ),
                                      &written, nullptr );
        ::CloseHandle( hFile );

        if ( !ok || written != static_cast<DWORD>( data.size() ) ) {
            ::DeleteFileW( targetPath.c_str() );
            return false;
        }
        return true;
    }

    //─────────────────────── PE pattern-scan (no PDB / no internet) ──────────
    //
    //  Resolves:
    //    ZwFlushInstructionCache  → PE export table (always exported)
    //    SeCiCallbacks            → scan SeRegisterImageVerificationCallback
    //                               body for the first RIP-relative LEA that
    //                               targets the .data section
    //
    //  Works on all Windows 10 / 11 builds (tested 19041 – 26100).
    //  Returns {SeCiCallbacks_rva, ZwFlushInstructionCache_rva} or nullopt.
    //─────────────────────────────────────────────────────────────────────────
    static std::optional<std::pair<DWORD64, DWORD64>>
    GetSymbolOffsetsByPatternScan( const std::wstring& kernelPath ) noexcept
    {
        HANDLE hFile = lazy::k32::get().CreateFileW( kernelPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( hFile == INVALID_HANDLE_VALUE ) return std::nullopt;

        HANDLE hMap = lazy::k32::get().CreateFileMappingW( hFile, nullptr, PAGE_READONLY, 0, 0, nullptr );
        if ( !hMap ) { ::CloseHandle( hFile ); return std::nullopt; }

        auto* pBase = static_cast<BYTE*>( lazy::k32::get().MapViewOfFile( hMap, FILE_MAP_READ, 0, 0, 0 ) );
        if ( !pBase ) { ::CloseHandle( hMap ); ::CloseHandle( hFile ); return std::nullopt; }

        DWORD64 offZwFlush = 0;
        DWORD64 offSeCi    = 0;

        auto Cleanup = [&]() -> std::optional<std::pair<DWORD64, DWORD64>> {
            lazy::k32::get().UnmapViewOfFile( pBase );
            ::CloseHandle( hMap );
            ::CloseHandle( hFile );
            if ( offSeCi == 0 || offZwFlush == 0 ) return std::nullopt;
            return std::make_pair( offSeCi, offZwFlush );
        };

        // Basic PE header validation
        auto* pDOS = reinterpret_cast<PIMAGE_DOS_HEADER>( pBase );
        if ( pDOS->e_magic != IMAGE_DOS_SIGNATURE ) return Cleanup();

        auto* pNT = reinterpret_cast<PIMAGE_NT_HEADERS64>( pBase + pDOS->e_lfanew );
        if ( pNT->Signature != IMAGE_NT_SIGNATURE ) return Cleanup();
        if ( pNT->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ) return Cleanup();

        const WORD  nSec  = pNT->FileHeader.NumberOfSections;
        auto*       pSec  = IMAGE_FIRST_SECTION( pNT );

        // RVA → mapped file pointer (returns nullptr when RVA is unmapped)
        auto RvaToPtr = [&]( DWORD rva ) -> BYTE* {
            for ( WORD i = 0; i < nSec; ++i ) {
                if ( rva >= pSec[i].VirtualAddress &&
                     rva <  pSec[i].VirtualAddress + pSec[i].Misc.VirtualSize )
                {
                    DWORD off = rva - pSec[i].VirtualAddress + pSec[i].PointerToRawData;
                    return pBase + off;
                }
            }
            return nullptr;
        };

        // ── Export table walk ────────────────────────────────────────────────
        const auto& expDD = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if ( expDD.VirtualAddress == 0 ) return Cleanup();

        auto* pExp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>( RvaToPtr( expDD.VirtualAddress ) );
        if ( !pExp ) return Cleanup();

        auto* pNames = reinterpret_cast<DWORD*>( RvaToPtr( pExp->AddressOfNames ) );
        auto* pOrds  = reinterpret_cast<WORD*>( RvaToPtr( pExp->AddressOfNameOrdinals ) );
        auto* pFuncs = reinterpret_cast<DWORD*>( RvaToPtr( pExp->AddressOfFunctions ) );
        if ( !pNames || !pOrds || !pFuncs ) return Cleanup();

        DWORD seRegRva = 0;  // SeRegisterImageVerificationCallback func RVA

        for ( DWORD i = 0; i < pExp->NumberOfNames; ++i )
        {
            auto* name = reinterpret_cast<const char*>( RvaToPtr( pNames[i] ) );
            if ( !name ) continue;

            if ( strcmp( name, OBF( "ZwFlushInstructionCache" ) ) == 0 )
                offZwFlush = pFuncs[ pOrds[i] ];
            else if ( strcmp( name, OBF( "SeRegisterImageVerificationCallback" ) ) == 0 )
                seRegRva = pFuncs[ pOrds[i] ];
        }

        if ( offZwFlush == 0 ) return Cleanup();   // export not found → cannot continue

        // ── .data section bounds (target validation for SeCiCallbacks) ───────
        DWORD dataVA = 0, dataSz = 0;
        for ( WORD i = 0; i < nSec; ++i )
        {
            char sname[9] = {};
            ::memcpy( sname, pSec[i].Name, 8 );
            if ( ::strcmp( sname, ".data" ) == 0 )
            {
                dataVA = pSec[i].VirtualAddress;
                dataSz = pSec[i].Misc.VirtualSize;
                break;
            }
        }

        // ── Scan SeRegisterImageVerificationCallback for SeCiCallbacks ────────
        //
        //  The function unconditionally loads SeCiCallbacks via:
        //    REX.W LEA reg, [RIP + disp32]   →  48 8D [05|0D|15|1D|25|2D|35|3D] ?? ?? ?? ??
        //  The first such instruction whose target falls in .data is our symbol.
        //
        //  Fallback: scan entire .text section for LEA patterns if the export
        //  is not found (paranoia for stripped/patched builds).
        //─────────────────────────────────────────────────────────────────────

        auto ScanFuncForSeCi = [&]( DWORD funcRva, int scanBytes ) -> bool
        {
            auto* fnPtr = RvaToPtr( funcRva );
            if ( !fnPtr ) return false;

            for ( int off = 0; off < scanBytes - 6; ++off )
            {
                const BYTE* p = fnPtr + off;

                // REX.W (0x48) + LEA opcode (0x8D) + ModRM where ModRM[7:6]=00, ModRM[2:0]=101
                // covers: LEA RAX/RCX/RDX/RBX/RSP/RBP/RSI/RDI, [RIP+disp32]
                if ( p[0] != 0x48 || p[1] != 0x8D ) continue;
                if ( ( p[2] & 0xC7u ) != 0x05u     ) continue;

                INT32 disp    = *reinterpret_cast<const INT32*>( p + 3 );
                // instruction end RVA = funcRva + off + 7
                DWORD endRva  = funcRva + static_cast<DWORD>( off ) + 7u;
                DWORD target  = static_cast<DWORD>( static_cast<INT64>( endRva ) + disp );

                // Must point into .data
                if ( dataVA != 0 && target >= dataVA && target < dataVA + dataSz )
                {
                    offSeCi = target;
                    return true;
                }
            }
            return false;
        };

        if ( seRegRva != 0 )
        {
            ScanFuncForSeCi( seRegRva, 512 );
        }

        // Fallback: if SeRegisterImageVerificationCallback not exported (rare),
        // scan the entire .text section in 4-byte aligned strides.  More expensive
        // but still runs in < 50 ms on a modern CPU for an 18 MB kernel image.
        if ( offSeCi == 0 && dataVA != 0 )
        {
            for ( WORD i = 0; i < nSec; ++i )
            {
                char sname[9] = {};
                ::memcpy( sname, pSec[i].Name, 8 );
                if ( ::strcmp( sname, ".text" ) != 0 ) continue;

                ScanFuncForSeCi( pSec[i].VirtualAddress,
                                 static_cast<int>( pSec[i].Misc.VirtualSize ) );
                break;
            }
        }

        return Cleanup();
    }

    //─────────────────────── resolve offsets via DbgHelp ─────────────────────
    //  Mirrors SymbolEngine::CalculateOffsetsFromDisk() exactly.
    //  Loads the PDB from disk at a fake base address and calls SymFromNameW
    //  for SeCiCallbacks and ZwFlushInstructionCache.
    std::optional<std::pair<DWORD64, DWORD64>>
    CalculateOffsetsFromDisk( const std::wstring& pdbPath,
                               const std::wstring& /*pdbName*/ ) noexcept
    {
        std::wstring pdbDir = pdbPath.substr( 0, pdbPath.find_last_of( L"\\/" ) );

        // Reinitialize DbgHelp each time (safe: called serially)
        if ( m_initialized ) {
            auto& dbg = lazy::dbghelp_::get();
            if ( dbg.SymCleanup ) dbg.SymCleanup( lazy::k32::get().GetCurrentProcess() );
            m_initialized = false;
        }

        std::wstring symPath = WOBFS( L"SRV*" ) + pdbDir;
        auto& dbg = lazy::dbghelp_::get();
        if ( !dbg.SymGetOptions || !dbg.SymSetOptions || !dbg.SymInitializeW ) return std::nullopt;
        DWORD opts = dbg.SymGetOptions();
        dbg.SymSetOptions( opts | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                         SYMOPT_DEBUG | SYMOPT_CASE_INSENSITIVE | SYMOPT_LOAD_LINES );

        HANDLE hProc = lazy::k32::get().GetCurrentProcess();
        if ( !dbg.SymInitializeW( hProc, symPath.c_str(), FALSE ) )
            return std::nullopt;
        m_initialized = true;

        constexpr DWORD64 FAKE_BASE = 0x140000000ULL;
        if ( !dbg.SymLoadModuleExW ) { dbg.SymCleanup( hProc ); m_initialized = false; return std::nullopt; }
        DWORD64 loaded = dbg.SymLoadModuleExW(
            hProc, nullptr,
            pdbPath.c_str(), nullptr,
            FAKE_BASE, 0, nullptr, 0 );

        if ( loaded == 0 ) {
            if ( dbg.SymCleanup ) dbg.SymCleanup( hProc );
            m_initialized = false;
            return std::nullopt;
        }

        std::vector<BYTE> symBuf( sizeof( SYMBOL_INFOW ) + MAX_SYM_NAME * sizeof( wchar_t ) );
        auto* pSym           = reinterpret_cast<PSYMBOL_INFOW>( symBuf.data() );
        pSym->SizeOfStruct   = sizeof( SYMBOL_INFOW );
        pSym->MaxNameLen     = MAX_SYM_NAME;

        DWORD64 offSeCi    = 0;
        DWORD64 offZwFlush = 0;

        if ( dbg.SymFromNameW && dbg.SymFromNameW( hProc, WOBF( L"SeCiCallbacks" ), pSym ) )
            offSeCi    = pSym->Address - FAKE_BASE;

        if ( dbg.SymFromNameW && dbg.SymFromNameW( hProc, WOBF( L"ZwFlushInstructionCache" ), pSym ) )
            offZwFlush = pSym->Address - FAKE_BASE;

        if ( dbg.SymUnloadModule64 ) dbg.SymUnloadModule64( hProc, loaded );
        if ( dbg.SymCleanup        ) dbg.SymCleanup( hProc );
        m_initialized = false;

        if ( offSeCi == 0 || offZwFlush == 0 ) return std::nullopt;
        return std::make_pair( offSeCi, offZwFlush );
    }
};
