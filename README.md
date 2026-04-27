# ELFLoaderARM

ELFLoaderARM is an Android native module that loads an embedded ARM64 ELF image inside a selected application process through Zygisk. The module is implemented in C++17 and built with Android NDK `ndk-build`.

The loader is intended for controlled research and development environments where the target process, payload, and device are owned or explicitly authorized by the operator.

## Overview

At runtime, the Zygisk module checks the app process name, starts a loader thread only for the configured target process, decodes the embedded payload from `data.h`, maps the ELF image manually, applies relocations, runs initialization routines, and transfers execution to the payload entry point.

The current source is configured for:

| Item | Value |
| --- | --- |
| Platform | Android / Zygisk |
| Architecture | ARM64 (`arm64-v8a`) |
| Language standard | C++17 |
| Build system | Gradle + Android NDK `ndk-build` |
| Android Gradle Plugin | 8.7.0 |
| NDK version | 24.0.8215888 |
| Compression | LZMA via bundled static `liblzma.a` |
| Payload storage | `app/src/main/jni/data.h` |
| Target process setting | `pname` in `app/src/main/jni/URL.h` |

## Runtime Flow

1. `Socket_Module` is registered with Zygisk by `REGISTER_ZYGISK_MODULE`.
2. `onLoad` stores the Zygisk API handle and Java VM reference.
3. `preAppSpecialize` compares the process `nice_name` against `pname`.
4. `postAppSpecialize` starts `load_elf_thread` only when the process matches.
5. The loader waits until `bin/linker64` appears in `/proc/self/maps`.
6. The embedded `chdata` byte array is decrypted with `xor_cipher`.
7. The decrypted buffer is decompressed with `decompress_lzma`.
8. `load_elf` validates the ELF header, reserves memory, maps `PT_LOAD` segments, handles `PT_TLS`, resolves dynamic symbols, applies supported ARM64 relocations, and runs ELF init callbacks.
9. The loader calls the ELF entry point and then attempts to resolve and call `_Z6awakenv`.
10. After loading completes, the module requests `DLCLOSE_MODULE_LIBRARY` through the Zygisk API.

## ELF Loader Details

The manual loader supports the parts of the ELF format that are required by the embedded ARM64 payload:

- `PT_LOAD` segment mapping with page alignment and final memory protections derived from ELF program header flags.
- `PT_TLS` allocation and thread-pointer setup for AArch64 through `TPIDR_EL0`.
- Dynamic dependency loading from `DT_NEEDED` entries using `dlopen`.
- Symbol lookup through the loaded image's dynamic symbol/string tables, falling back to `dlsym(RTLD_DEFAULT, ...)`.
- Relocation handling for `R_AARCH64_RELATIVE`, `R_AARCH64_GLOB_DAT`, `R_AARCH64_JUMP_SLOT`, `R_AARCH64_ABS64`, and `R_AARCH64_IRELATIVE`.
- Execution of `DT_PREINIT_ARRAY`, `DT_INIT`, and `DT_INIT_ARRAY` callbacks before jumping to the entry point.
- Optional finalization support through `DT_FINI_ARRAY` and `DT_FINI` in `unload_elf`.

The loader does not implement a complete Android dynamic linker. Payloads should be tested against the exact relocation types, dependencies, TLS usage, and initialization behavior required by this implementation.

## Payload Format

The payload is compiled into the module as `char chdata[]` in `app/src/main/jni/data.h`. The runtime expects this array to contain an LZMA-compressed ELF image encrypted with the same transform implemented by `xor_cipher`.

The loader currently decrypts with:

```cpp
xor_cipher(elf_data, OBFUSCATE("System.Reflection"), false);
```

When replacing the payload, generate bytes with the matching compression and encryption pipeline, then replace only the contents of `chdata`.

## Configuration

`app/src/main/jni/URL.h` contains runtime configuration values:

```cpp
const char* durl = OBFUSCATE("...");
const char* pname = OBFUSCATE("...");
```

`pname` is used to restrict loading to a single process name. `durl` and the JNI `HttpURLConnection` helper are present in the source, but the current loader path uses the embedded `data.h` payload instead of downloading a payload.

## Build

Prerequisites:

- Android Studio or a Gradle environment capable of building Android projects.
- Android SDK with compile SDK 35.
- Android NDK 24.0.8215888.
- Static `liblzma.a` for each enabled ABI under `app/src/main/jni/libraries/<abi>/`.

Build the project with:

```sh
./gradlew assembleRelease
```

The native module is built by `app/src/main/jni/Android.mk` as the shared library module `zygisk`. The Gradle configuration currently enables only `arm64-v8a`.

## Deployment

Copy the produced native shared object into the `zygisk/` directory of a Magisk/Zygisk module using the ABI filename expected by Zygisk, typically:

```text
zygisk/arm64-v8a.so
```

Deploy only to devices and applications where you have authorization to run injected native code.

## Important Notes

- `LDEBUG` is disabled by default. Define it in `main.cpp` to enable verbose Android log output.
- `checkc()` reads `/system/etc/hosts` and prevents loading if specific blocked strings are found.
- `get_random_mem_size()` and the JNI URL fetch helper are present but are not part of the current embedded-payload loading path.
- The code uses obfuscated string macros and optional LLVM obfuscation flags in `Android.mk`; those flags are currently commented out.
- This repository contains bundled third-party components, including Zygisk API headers and liblzma headers/static libraries. Review their licenses before redistribution.

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for the full license text.
