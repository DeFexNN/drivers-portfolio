@echo off
:: ─────────────────────────────────────────────────────────────────────────────
::  build.bat  –  MidnightSoftware Loader quick-build script (MSBuild / Visual Studio 2022)
:: ─────────────────────────────────────────────────────────────────────────────
setlocal

set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Release"

:: Try to locate vswhere to find the VS install path
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Is Visual Studio 2022 installed?
    exit /b 1
)

for /f "usebackq delims=" %%i in (
    `"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`
) do set "MSBUILD=%%i"

if not defined MSBUILD (
    echo [ERROR] MSBuild.exe not found via vswhere.
    exit /b 1
)

echo.
echo  Building driver_loader  [%CONFIG%|x64]
echo  MSBuild: %MSBUILD%
echo.

"%MSBUILD%" driver_loader.sln ^
    /p:Configuration=%CONFIG% ^
    /p:Platform=x64 ^
    /m ^
    /nologo ^
    /v:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [FAIL] Build failed.
    exit /b %ERRORLEVEL%
)

echo  [OK] driver_loader.exe

:: ── VMProtect  driver_loader.exe  ->  driver_loader_vmp.exe ─────────────────
set "VMP_CON=C:\Users\DeFexGG\Downloads\VMProtect\VMProtect\VMProtect_Con.exe"
set "VMP_PROJ=%~dp0driver_loader.vmp"
set "VMP_OUT=%~dp0bin\%CONFIG%\driver_loader_vmp.exe"

echo.
echo  VMProtect: driver_loader.exe ^-^> driver_loader_vmp.exe
if not exist "%VMP_CON%" (
    echo  [WARNING] VMProtect_Con.exe not found – skipping protection.
    echo  [WARNING] Unprotected binary: bin\%CONFIG%\driver_loader.exe
    goto :vmp_skip
)
if not exist "%VMP_PROJ%" (
    echo  [WARNING] driver_loader.vmp not found – skipping protection.
    goto :vmp_skip
)

pushd "%~dp0"
"%VMP_CON%" "driver_loader.vmp"
set "VMP_ERR=%ERRORLEVEL%"
popd

if %VMP_ERR% NEQ 0 (
    echo  [FAIL] VMProtect_Con.exe failed (exit %VMP_ERR%).
    exit /b %VMP_ERR%
)
if not exist "%VMP_OUT%" (
    echo  [ERROR] driver_loader_vmp.exe not found after VMProtect: %VMP_OUT%
    exit /b 1
)

:vmp_skip
echo.
echo  [OK] Output: bin\%CONFIG%\driver_loader_vmp.exe
echo.
