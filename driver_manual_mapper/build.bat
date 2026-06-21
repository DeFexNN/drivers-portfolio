@echo off
setlocal EnableDelayedExpansion

:: ─────────────────────────────────────────────────────────────
:: MidnightSoftware Manual Mapper – EWDK build script
:: Output: bin\mapper.exe
:: ─────────────────────────────────────────────────────────────

set EWDK_ROOT=C:\ewdk\EWDK_ge_release_svc_prod1_26100_250904-1728
set EWDK_ENV=%EWDK_ROOT%\BuildEnv\SetupBuildEnv.cmd
set MSVC_VER=14.44.35207
set SDK_VER=10.0.26100.0

set CL_EXE=%EWDK_ROOT%\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\%MSVC_VER%\bin\HostX64\x64\cl.exe

set MSVC_INC=%EWDK_ROOT%\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\%MSVC_VER%\include
set SDK_UCRT_INC=%EWDK_ROOT%\Program Files\Windows Kits\10\Include\%SDK_VER%\ucrt
set SDK_SHARED_INC=%EWDK_ROOT%\Program Files\Windows Kits\10\Include\%SDK_VER%\shared
set SDK_UM_INC=%EWDK_ROOT%\Program Files\Windows Kits\10\Include\%SDK_VER%\um

set MSVC_LIB=%EWDK_ROOT%\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\%MSVC_VER%\lib\x64
set SDK_UCRT_LIB=%EWDK_ROOT%\Program Files\Windows Kits\10\Lib\%SDK_VER%\ucrt\x64
set SDK_UM_LIB=%EWDK_ROOT%\Program Files\Windows Kits\10\Lib\%SDK_VER%\um\x64

if not exist bin mkdir bin

:: ── Set up EWDK environment ────────────────────────────────────
echo [1/2] Setting up EWDK environment...
call "%EWDK_ENV%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to init EWDK. Check: %EWDK_ENV%
    exit /b 1
)

:: ── Compile ────────────────────────────────────────────────────
echo [2/2] Compiling mapper...

set CL_FLAGS=/nologo /std:c++17 /EHsc /MT /O2 /W3 ^
 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WIN32 /DWIN64 /D_WIN64 ^
 /I"." /I".." ^
 /I"%MSVC_INC%" ^
 /I"%SDK_UCRT_INC%" ^
 /I"%SDK_SHARED_INC%" ^
 /I"%SDK_UM_INC%"

set LINK_FLAGS=/nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE ^
 /OUT:"bin\mapper.exe" ^
 /LIBPATH:"%MSVC_LIB%" ^
 /LIBPATH:"%SDK_UCRT_LIB%" ^
 /LIBPATH:"%SDK_UM_LIB%"

set LIBS=kernel32.lib user32.lib ntdll.lib

"%CL_EXE%" %CL_FLAGS% mapper.cpp /link %LINK_FLAGS% %LIBS%

if %ERRORLEVEL% == 0 (
    echo.
    echo [OK] bin\mapper.exe built successfully.
) else (
    echo.
    echo [FAIL] Build failed with error %ERRORLEVEL%.
    exit /b 1
)
