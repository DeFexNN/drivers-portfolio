@echo off
::  ==========================================================================
::  debug.bat  -  MidnightSoftware fast build  (Release binaries, NO VMProtect)
::
::  Steps:
::    1. Build MidnightSoftware driver.sys      (EWDK / fallback MSBuild)
::    2. Build MidnightSoftware.exe          (VS MSBuild)
::    3. Encrypt binaries           (encrypt_bins.ps1 -SkipBuild)
::    4. Build driver_loader.exe    (VS MSBuild)
::
::  VMProtect is intentionally skipped – outputs land beside the originals:
::    MidnightSoftware.exe        (plain, not virtualised)
::    driver_loader.exe  (plain, not virtualised)
::
::  Usage:  debug.bat [Release|Debug]
::  ==========================================================================

setlocal EnableDelayedExpansion

:: ── Configuration ───────────────────────────────────────────────────────────
set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Release"
set "PLATFORM=x64"

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"      & :: strip trailing backslash

:: Derived paths
set "DRV_PROJ=%ROOT%\..\MidnightSoftwareDriver\MidnightSoftwareDriver\MidnightSoftwareDriver.vcxproj"
set "SDK_PROJ=%ROOT%\..\..\Menus\War_Thunder\war_thunder_sdk\sdk.vcxproj"
set "SDK_OUT=%ROOT%\..\..\Menus\War_Thunder\war_thunder_sdk\x64\%CONFIG%"
set "DRV_OUT=%ROOT%\..\MidnightSoftwareDriver\MidnightSoftwareDriver\x64\%CONFIG%\MidnightSoftwareDriver.sys"
set "LOADER_SLN=%ROOT%\driver_loader.sln"
set "ENCRYPT_PS1=%ROOT%\encrypt_bins.ps1"
set "LOADER_EXE=%ROOT%\bin\%CONFIG%\driver_loader.exe"

:: ── Locate MSBuild ──────────────────────────────────────────────────────────
echo.
echo  [debug] Locating MSBuild...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo  [ERROR] vswhere.exe not found – is Visual Studio 2022 installed?
    exit /b 1
)
for /f "usebackq delims=" %%i in (
    `"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`
) do set "MSBUILD=%%i"
if not defined MSBUILD (
    echo  [ERROR] MSBuild.exe not found via vswhere.
    exit /b 1
)
echo  [debug] MSBuild: %MSBUILD%

:: ── Locate EWDK ─────────────────────────────────────────────────────────────
echo.
echo  [debug] Locating EWDK...
set "EWDK_ROOT="
set "EWDK_SETUP="
set "EWDK_MSBUILD="

for /f "delims=" %%d in ('dir /b /ad /o-n "C:\ewdk" 2^>nul') do (
    if not defined EWDK_ROOT (
        if exist "C:\ewdk\%%d\BuildEnv\SetupBuildEnv.cmd" (
            set "EWDK_ROOT=C:\ewdk\%%d"
            set "EWDK_SETUP=C:\ewdk\%%d\BuildEnv\SetupBuildEnv.cmd"
        )
    )
)

if defined EWDK_SETUP (
    for /f "delims=" %%m in (
        'dir /s /b "%EWDK_ROOT%\Program Files\*MSBuild.exe" 2^>nul ^| findstr /i "amd64"'
    ) do (
        if not defined EWDK_MSBUILD set "EWDK_MSBUILD=%%m"
    )
    echo  [debug] EWDK: %EWDK_ROOT%
) else (
    echo  [debug] WARNING: EWDK not found - using VS MSBuild for driver
)

:: ==========================================================================
:: STEP 1 - MidnightSoftware driver.sys
:: ==========================================================================
echo.
echo [1/4] Building MidnightSoftware driver [%CONFIG%^|%PLATFORM%]
echo -----------------------------------------------------------------------

if not exist "%DRV_PROJ%" (
    echo  [ERROR] MidnightSoftware driver project not found: %DRV_PROJ%
    exit /b 1
)

if defined EWDK_MSBUILD (
    cmd /C ""%EWDK_SETUP%" && "%EWDK_MSBUILD%" "%DRV_PROJ%" /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /p:UseInf2Cat=false /p:RunInf2Cat=false /p:EnableInf2cat=false /v:minimal /nologo /nodeReuse:false"
) else (
    "%MSBUILD%" "%DRV_PROJ%" /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /p:UseInf2Cat=false /p:RunInf2Cat=false /p:EnableInf2cat=false /v:minimal /nologo
)
if %ERRORLEVEL% NEQ 0 ( echo  [FAIL] MidnightSoftware driver build failed. & exit /b 1 )

if not exist "%DRV_OUT%" (
    echo  [ERROR] MidnightSoftware driver.sys not found after build: %DRV_OUT%
    exit /b 1
)
echo [OK] MidnightSoftware driver.sys

:: ==========================================================================
:: STEP 2 - MidnightSoftware.exe
:: ==========================================================================
echo.
echo [2/4] Building MidnightSoftware SDK [%CONFIG%^|%PLATFORM%]
echo -----------------------------------------------------------------------

if not exist "%SDK_PROJ%" (
    echo  [ERROR] sdk.vcxproj not found: %SDK_PROJ%
    exit /b 1
)
"%MSBUILD%" "%SDK_PROJ%" /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /m /v:minimal /nologo
if %ERRORLEVEL% NEQ 0 ( echo  [FAIL] MidnightSoftware SDK build failed. & exit /b 1 )

if not exist "%SDK_OUT%\MidnightSoftware.exe" (
    echo  [ERROR] MidnightSoftware.exe not found after build: %SDK_OUT%\MidnightSoftware.exe
    exit /b 1
)
echo [OK] MidnightSoftware.exe

:: ==========================================================================
:: STEP 3 - Encrypt binaries  (uses plain MidnightSoftware.exe, no VMP)
:: ==========================================================================
echo.
echo [3/4] Encrypting binaries
echo -----------------------------------------------------------------------

if not exist "%ENCRYPT_PS1%" (
    echo  [ERROR] encrypt_bins.ps1 not found: %ENCRYPT_PS1%
    exit /b 1
)

:: Delete any stale MidnightSoftware_vmp.exe so encrypt_bins falls back to plain exe
if exist "%SDK_OUT%\MidnightSoftware_vmp.exe" del /f /q "%SDK_OUT%\MidnightSoftware_vmp.exe"

powershell -NoProfile -ExecutionPolicy Bypass ^
    -File "%ENCRYPT_PS1%" -Configuration %CONFIG% -Platform %PLATFORM% -SkipBuild
if %ERRORLEVEL% NEQ 0 ( echo  [FAIL] encrypt_bins.ps1 failed. & exit /b 1 )

:: ==========================================================================
:: STEP 4 - driver_loader.exe
:: ==========================================================================
echo.
echo [4/4] Building driver_loader [%CONFIG%^|%PLATFORM%]
echo -----------------------------------------------------------------------

"%MSBUILD%" "%LOADER_SLN%" ^
    /p:Configuration=%CONFIG% ^
    /p:Platform=%PLATFORM% ^
    /m ^
    /nologo ^
    /v:minimal
if %ERRORLEVEL% NEQ 0 ( echo  [FAIL] driver_loader build failed. & exit /b 1 )

if not exist "%LOADER_EXE%" (
    echo  [ERROR] driver_loader.exe not found after build: %LOADER_EXE%
    exit /b 1
)
echo [OK] driver_loader.exe

echo.
echo =======================================================================
echo  BUILD COMPLETE  [%CONFIG%^|%PLATFORM%]  ^(no VMProtect^)
echo.
echo  MidnightSoftware.exe        : %SDK_OUT%\MidnightSoftware.exe
echo  MidnightSoftware_driver.sys : %DRV_OUT%
echo  driver_loader.exe  : %LOADER_EXE%
echo =======================================================================
echo.
endlocal
