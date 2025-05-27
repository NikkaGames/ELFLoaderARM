# ARM64 ELF Loader

**ARM64 ELF Loader** is a high-performance, stealth-focused runtime ELF binary loader tailored for ARM64 (AArch64) platforms on Android. It enables secure, dynamic execution of encrypted and compressed ELF payloads via Zygisk integration, featuring advanced memory handling, TLS setup, and symbol resolution.

## Project Overview

| Field              | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| **Author**         | [Nikka](https://github.com/NikkaGames)                            |
| **Architecture**   | ARM64 (AArch64)                                                    |
| **Platform**       | Android (Zygisk module integration)                                |
| **Language**       | C++17                                                              |
| **Compression**    | LZMA with custom error handling                                    |
| **Encryption**     | XOR-based cipher with dynamic key mutation and bit-shifting        |
| **Obfuscation**    | Heavy: OBFUSCATE macros, base64 paths, encrypted strings           |
| **Threading**      | Multi-threaded via `std::thread`                                   |
| **TLS**            | Manual ARM64 TLS setup (`TPIDR_EL0`)                               |
| **Symbol Resolution** | Hybrid: `dlsym` + manual lookup via `.dynsym`/`.dynstr`         |

## Features

- 🔐 **Security**: Anti-reversing measures, obfuscated strings/paths, memory layout randomization.
- ⚙️ **Dynamic ELF Support**: Manual parsing of ELF headers, relocation resolution, TLS segment setup.
- 🚀 **Performance**: Fast execution with minimal overhead, threaded network operations.
- 📦 **Integration**: Embedded as part of a Zygisk module, executed during the app specialization phase.
- 🌐 **JNI/Java Interop**: Safe JNI attachment with obfuscated network access via `HttpURLConnection`.

## Loader Lifecycle

1. **Trigger**: Hooked via `preAppSpecialize` / `postAppSpecialize` in Zygisk.
2. **Linker Wait**: Loader dynamically waits for `linker64` initialization.
3. **Payload Handling**:
   - Decrypts embedded ELF binary via XOR cipher.
   - Decompresses using LZMA.
4. **ELF Mapping**:
   - Allocates memory via `mmap` with R/W/X.
   - Parses and loads relevant segments (PT_LOAD, PT_TLS).
5. **Relocations**:
   - Supports: `R_AARCH64_RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`.
6. **Execution**: Calls ELF entry point post-relocation.

## Critical Functions

- `load_elf()`, `unload_elf()`, `resolve_symbol()`
- `xor_cipher()`, `decompress_lzma()`
- complete ELF lifecycle management

## Security Highlights

- Base64 encoding for critical paths
- Tamper detection (host file scanning for blacklisted keywords)
- Randomized memory allocation to mitigate static analysis
- LLVM IR-level obfuscation hints (OLLVM) (nosub, fla, split attributes)

## Build & Integration

### Prerequisites

- Android NDK (r24 or later)
- CMake + Ninja
- Zygisk module boilerplate

### Building

Android Studio with r24 ndk

### Deployment

Place the built `.so` in your Zygisk module’s `zygisk/` directory, rename it to `arm64-v8a.so`.

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE) for more information.
