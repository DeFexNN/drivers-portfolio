# Kernel Drivers & Loader Portfolio

This monorepo groups kernel and loader projects built for driver development, kernel-user IPC, and secure payload deployment. It highlights systems-level engineering, secure design, and practical driver tooling.

Who this is for

- Employers seeking low-level Windows engineers, driver developers, or security researchers.

Core skills demonstrated

- Kernel-mode development (WDK), IOCTL and device interfaces
- Driver loading strategies, manual mapping, and DMA-assisted memory access
- Secure loader design: authentication, VMProtect integration, safe resource handling

Projects

- MidnightSoftwareDriver — kernel driver providing IPC and memory-access primitives.
- driver_loader — VMProtect-protected loader that authenticates users and installs the kernel driver (detailed README included).
- driver_manual_mapper — small utility demonstrating manual driver mapping techniques.

Getting started

1. Open each project folder and follow its README for build instructions.
2. Build environment: Visual Studio + Windows WDK, Administrator privileges required.

Security note

These tools operate at kernel level — use only on lab/test systems and with proper authorization. Always follow legal and ethical guidelines when working with kernel components.