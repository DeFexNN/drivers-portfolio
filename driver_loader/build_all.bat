@echo off
::  ==========================================================================
::  build_all.bat  -  MidnightSoftware full-pipeline build
::
::  Steps:
::    1. Build MidnightSoftware driver.sys      (EWDK / fallback MSBuild)
::    2. Build MidnightSoftware.exe          (VS MSBuild)
::    3. VMProtect MidnightSoftware.exe      -> MidnightSoftware_vmp.exe
::    4. Encrypt binaries           (encrypt_bins.ps1 -SkipBuild)
::    5. Build driver_loader.exe    (VS MSBuild)
::    6. VMProtect driver_loader.exe -> driver_loader.vmp.exe
::
::  Usage:  build_all.bat [Release|Debug]
::  ==========================================================================

setlocal EnableDelayedExpansion

:: ── Configuration ──────────────────────────────────────────────────────────────────
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

:: VMProtect console runner and project files
set "VMP_CON=C:\Users\DeFexGG\Downloads\VMProtect\VMProtect\VMProtect_Con.exe"
set "VMP_SDK_PROJ=%SDK_OUT%\MidnightSoftware.exe.vmp"
set "SDK_VMP_EXE=%SDK_OUT%\MidnightSoftware_vmp.exe"
set "VMP_LOADER_PROJ=%ROOT%\driver_loader.vmp"
set "LOADER_EXE=%ROOT%\bin\%CONFIG%\driver_loader.exe"
set "LOADER_VMP_EXE=%ROOT%\bin\%CONFIG%\driver_loader.vmp.exe"

:: ── Locate MSBuild ─────────────────────────────────────────────────────────────────
echo.
echo  [build_all] Locating MSBuild...
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
echo  [build_all] MSBuild: %MSBUILD%

:: ── Locate EWDK (for WDK driver build) ──────────────────────────────────────────
echo.
echo  [build_all] Locating EWDK...
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
    :: Find EWDK's own amd64 MSBuild
    for /f "delims=" %%m in (
        'dir /s /b "%EWDK_ROOT%\Program Files\*MSBuild.exe" 2^>nul ^| findstr /i "amd64"'
    ) do (
        if not defined EWDK_MSBUILD set "EWDK_MSBUILD=%%m"
    )
    echo  [build_all] EWDK: %EWDK_ROOT%
) else (
    echo  [build_all] WARNING: EWDK not found - using VS MSBuild for driver
)

:: ==========================================================================
:: STEP 1 - MidnightSoftware driver.sys
:: ==========================================================================
echo.
echo [1/6] Building MidnightSoftware driver [%CONFIG%^|%PLATFORM%]
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
echo [2/6] Building MidnightSoftware SDK [%CONFIG%^|%PLATFORM%]
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
:: STEP 3 - VMProtect MidnightSoftware.exe  ->  MidnightSoftware_vmp.exe
:: ==========================================================================
echo.
echo [3/6] VMProtect: MidnightSoftware.exe ^-^> MidnightSoftware_vmp.exe [%CONFIG%^|%PLATFORM%]
echo -----------------------------------------------------------------------

if not exist "%VMP_CON%" (
    echo  [WARNING] VMProtect_Con.exe not found: %VMP_CON%
    echo  [WARNING] Skipping VMProtect step - MidnightSoftware SDK will NOT be protected.
    set "SDK_VMP_EXE=%SDK_OUT%\MidnightSoftware.exe"
    goto :vmp_sdk_skip
)
if not exist "%VMP_SDK_PROJ%" (
    echo  [WARNING] MidnightSoftware.exe.vmp project not found: %VMP_SDK_PROJ%
    echo  [WARNING] Skipping VMProtect step - MidnightSoftware SDK will NOT be protected.
    set "SDK_VMP_EXE=%SDK_OUT%\MidnightSoftware.exe"
    goto :vmp_sdk_skip
)

pushd "%SDK_OUT%"
"%VMP_CON%" "MidnightSoftware.exe.vmp"
if %ERRORLEVEL% NEQ 0 (
    popd
    echo  [FAIL] VMProtect_Con.exe failed for MidnightSoftware SDK.
    exit /b 1
)
popd

if not exist "%SDK_VMP_EXE%" (
    echo  [ERROR] MidnightSoftware_vmp.exe not found after VMProtect: %SDK_VMP_EXE%
    exit /b 1
)
echo [OK] MidnightSoftware_vmp.exe

:vmp_sdk_skip

:: ==========================================================================
:: STEP 4 - encrypt_bins.ps1  (uses MidnightSoftware_vmp.exe if present)
:: ==========================================================================
echo.
echo [4/6] Encrypting binaries
echo -----------------------------------------------------------------------

if not exist "%ENCRYPT_PS1%" (
    echo  [ERROR] encrypt_bins.ps1 not found: %ENCRYPT_PS1%
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass ^
    -File "%ENCRYPT_PS1%" -Configuration %CONFIG% -Platform %PLATFORM% -SkipBuild
if %ERRORLEVEL% NEQ 0 ( echo  [FAIL] encrypt_bins.ps1 failed. & exit /b 1 )

:: ==========================================================================
:: STEP 5 - driver_loader.exe
:: ==========================================================================
echo.
echo [5/6] Building driver_loader [%CONFIG%^|%PLATFORM%]
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

:: ==========================================================================
:: STEP 6 - VMProtect driver_loader.exe  ->  driver_loader.vmp.exe
:: ==========================================================================
echo.
echo [6/6] VMProtect: driver_loader.exe ^-^> driver_loader.vmp.exe [%CONFIG%^|%PLATFORM%]
echo -----------------------------------------------------------------------

if not exist "%VMP_CON%" (
    echo  [WARNING] VMProtect_Con.exe not found: %VMP_CON%
    echo  [WARNING] Skipping VMProtect step - loader will NOT be protected.
    set "LOADER_VMP_EXE=%LOADER_EXE%"
    goto :vmp_loader_skip
)
if not exist "%VMP_LOADER_PROJ%" (
    echo  [WARNING] driver_loader.vmp project not found: %VMP_LOADER_PROJ%
    echo  [WARNING] Skipping VMProtect step - loader will NOT be protected.
    set "LOADER_VMP_EXE=%LOADER_EXE%"
    goto :vmp_loader_skip
)

pushd "%ROOT%"
"%VMP_CON%" "%VMP_LOADER_PROJ%"
if %ERRORLEVEL% NEQ 0 (
    popd
    echo  [FAIL] VMProtect_Con.exe failed for driver_loader.
    exit /b 1
)
popd

if not exist "%LOADER_VMP_EXE%" (
    echo  [ERROR] driver_loader.vmp.exe not found after VMProtect: %LOADER_VMP_EXE%
    exit /b 1
)
echo [OK] driver_loader.vmp.exe

:vmp_loader_skip

echo.
echo =======================================================================
echo  BUILD COMPLETE [%CONFIG%^|%PLATFORM%]
echo.
echo  MidnightSoftware_vmp.exe       : %SDK_VMP_EXE%
echo  MidnightSoftware_driver.sys : %DRV_OUT%
echo  driver_loader_vmp.exe : %LOADER_VMP_EXE%
echo =======================================================================
echo.
endlocal
