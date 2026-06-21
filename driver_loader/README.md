# driver_loader.vmp.exe - MidnightSoftware Kernel Driver Loader

A VMProtect-protected driver loader utility that manages kernel driver injection and DMA-SDK payload execution with integrated authentication.

## Overview

**driver_loader.vmp.exe** is a secure driver loader designed to:
- Authenticate users via ImGui UI interface
- Load kernel drivers (MidnightSoftwareDriver.sys) into memory
- Launch DMA-SDK payloads for memory access operations
- Maintain driver persistence for as long as needed
- Hide execution by self-relocating to temporary directories

## System Requirements

- **OS**: Windows 10/11
- **Architecture**: 64-bit (x64)
- **Privileges**: Administrator/System privileges required
- **Dependencies**:
  - Direct3D 11 (Windows SDK)
  - .NET Runtime (if applicable for DMA-SDK)
  - Kernel-mode access permissions

## Execution Flow

```
1. Start driver_loader.vmp.exe
    ↓
2. Self-Relocate Check
   - If not in %TEMP%: Copy to %TEMP%\<random-hex>.exe
   - Mark as HIDDEN, SYSTEM, and TEMPORARY
   - Relaunch from temp and exit original
    ↓
3. Create D3D11 Window (400x220)
   - DirectX 11 rendering surface
   - ImGui UI framework
   - Centered on screen
    ↓
4. Authentication UI
   - Login screen (auth.hpp::draw_login_ui)
   - Validate credentials
    ↓
5. Kernel Driver Loading
   - Use kvc (kernel chaining) module mapping
   - Inject MidnightSoftwareDriver.sys
   - Establish kernel communication
    ↓
6. Launch DMA-SDK Payload
   - Spawn DMA-SDK with driver access
   - Window closes after launch
    ↓
7. Driver Remains Resident
   - MidnightSoftwareDriver.sys stays loaded
   - Available for DMA-SDK operations
```

## How to Use

### Basic Usage

1. **Run with Administrator Privileges**:
   ```bash
   driver_loader.vmp.exe
   ```
   The application requires elevated privileges to load kernel drivers.

2. **Follow Authentication**:
   - A 400x220 ImGui window will appear
   - Enter required authentication credentials
   - Credentials are validated against the auth module

3. **Wait for Driver Loading**:
   - After successful auth, the driver loading sequence begins
   - Progress is displayed in the window
   - The DMA-SDK payload is automatically launched

4. **Window Closes**:
   - Once the driver is loaded and payload launched, the window closes automatically
   - The driver remains loaded in kernel memory

### Advanced Usage

#### Self-Relocation Behavior

The loader automatically copies itself to:
```
%TEMP%\<10-character-hex-name>.exe
```

**Benefits:**
- Task Manager shows random filename each execution
- Original file path remains hidden
- Temporary files auto-cleanup system integration

**Override**: If already running from %TEMP%, this step is skipped automatically.

#### Embedded Resources

The loader extracts embedded resources temporarily:
- Driver binaries
- Configuration files
- DMA-SDK components

These are cleaned up via `embedded::Cleanup()` on exit.

#### Manual Driver Permanence

**Important**: The MidnightSoftwareDriver.sys is intentionally NOT unloaded when the loader exits:
- Driver stays resident in kernel memory
- DMA-SDK maintains access as long as needed
- Require manual system service removal to unload

### Command-Line Arguments

Currently, the loader accepts no command-line arguments. All configuration is embedded or done via UI.

### Configuration Files (if used)

Check the `src/` subdirectory for:
- `auth.hpp` - Authentication configuration
- `embedded.hpp` - Embedded resource management
- `includes.hpp` - Core configuration

## Troubleshooting

### "Access Denied" Error

**Solution**: Run as Administrator
```bash
# Option 1: Right-click → "Run as administrator"
# Option 2: From admin PowerShell
& ".\driver_loader.vmp.exe"
```

### Window Doesn't Appear

**Possible Causes**:
- D3D11 not available (missing graphics drivers)
- Running from network path
- Windows Defender blocking execution

**Solution**:
```powershell
# Check if WARP fallback activates
# The loader uses WARP (CPU rasterizer) as fallback if GPU fails
```

### Authentication Fails

- Verify credentials in `src/auth.hpp`
- Check auth module compile flags
- Verify embedded credentials are included

### Driver Loading Fails

- Verify driver binary is embedded correctly
- Check kvc module compilation
- Ensure system allows kernel driver loading (not in Safe Mode)
- Verify VMProtect SDK integration

### Window Freezes / UI Unresponsive

- The loader may be stuck on driver loading
- Kill process and check system logs
- Verify no other driver loader instances running

## File Structure

```
driver_loader/
├── main.cpp                    # Entry point, D3D11 window, main loop
├── src/
│   ├── auth.hpp               # Authentication UI and logic
│   ├── embedded.hpp           # Extracted resource management
│   ├── includes.hpp           # Common headers and macros
│   ├── log.hpp                # Logging utility
│   ├── VMProtectSDK.h         # VMProtect 3.x SDK
│   └── ...                    # Additional modules
├── driver_loader.vcxproj      # MSVC project file
├── driver_loader.rc           # Resource file (icons, version)
├── build.bat                  # Build script
├── debug.bat                  # Debug launcher
└── ...
```

## Build Information

**Environment**:
- Compiler: MSVC (Visual Studio 2022+ recommended)
- C++ Standard: C++17 or later
- Protection: VMProtect 3.x

**Build Steps**:
```bash
# Debug build
debug.bat

# Release build (with VMProtect)
build.bat
```

**Output**: Generates `driver_loader.vmp.exe` in `bin/` folder

## Security Notes

- **VMProtect Protection**: Executable is protected against reverse engineering
- **Self-Relocation**: Hides execution from static analysis
- **Embedded Resources**: Driver and payloads embedded in binary
- **Admin Requirement**: Kernel operations require elevated privileges
- **No Persistence**: Loader itself doesn't create registry entries or scheduled tasks

## Environment Variables

The loader respects standard Windows variables:
- `%TEMP%` - Temporary directory for relocation
- `%SystemRoot%` - Windows system directory
- `%ALLUSERSPROFILE%` - Common application data

## Performance Notes

- **Initial Launch**: ~1-3 seconds (includes D3D11 initialization)
- **Driver Loading**: ~2-5 seconds (kernel operations)
- **Memory Usage**: ~50-100 MB (including embedded driver/payload)

## Cleanup

On successful completion:
1. Window closes automatically
2. Temporary extracted files cleaned via `embedded::Cleanup()`
3. But: Driver stays resident in kernel (by design)

To fully remove driver:
```powershell
# From Admin PowerShell - stop and remove the driver service
Stop-Service MidnightSoftwareDriver -Force
Remove-Item -Path "Driver binary path" -Force
```

## Related Components

- **MidnightSoftwareDriver.sys** - Kernel driver (loaded by this tool)
- **DMA-SDK** - Payload launched after driver loading
- **kvc** - Kernel chaining module mapper
- **ImGui** - UI framework

## Version

- **Base Version**: 1.0
- **Protection**: VMProtect 3.x
- **Last Updated**: 2026

## Support / Notes

For issues or modifications:
- Check embedded resource extraction via `embedded::Cleanup()`
- Verify auth credentials in `src/auth.hpp`
- Monitor output logs from `src/log.hpp`
- Inspect D3D11 initialization fallback to WARP

---

*This is a specialized kernel utility for advanced system operations. Use with appropriate security considerations.*
