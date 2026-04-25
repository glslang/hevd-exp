# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Rust workspace of Windows kernel exploit proof-of-concepts targeting [HackSys Extreme Vulnerable Driver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). All exploits target Windows 11 and depend on the shared [`win-kexp`](https://github.com/glslang/win-kexp) library for Windows API wrappers, shellcode, and ROP utilities.

**Build target: Windows x86-64 only.** These exploits cannot be built or run on Linux.

## Commands

```bash
# Check formatting (CI requirement)
cargo fmt --all --verbose -- --check

# Auto-fix formatting
cargo fmt --all

# Build all exploits
cargo build --verbose

# Build a specific exploit
cargo build -p stack_buffer_overflow_token_stealing

# Run tests
cargo test --verbose

# Update dependencies
cargo update
```

CI also requires MSBuild and MASM (`glslang/setup-masm`) because `win-kexp` contains inline assembly that must be assembled with MASM.

## Architecture

### Workspace Layout

Each subdirectory is an independent exploit crate with a single `src/main.rs`. All crates share a single external dependency: `win-kexp` (fetched from GitHub).

| Crate | Vulnerability | Technique | Mitigations Bypassed |
|---|---|---|---|
| `stack_buffer_overflow_token_stealing` | Stack buffer overflow | Token stealing shellcode | None (SMEP/KPTI disabled) |
| `stack_buffer_overflow_acl_edit` | Stack buffer overflow | ACL edit + process injection into winlogon | None (SMEP/KPTI disabled) |
| `stack_buffer_overflow_token_stealing_smep_no_kvashadow` | Stack buffer overflow | Token stealing + ROP SMEP disable | SMEP (no KVA Shadow) |
| `stack_buffer_overflow_token_stealing_smep_no_kvashadow_pte` | Stack buffer overflow | Token stealing + PTE-based SMEP disable via ROP | SMEP (no KVA Shadow) |
| `buffer_overflow_non_paged_pool_nx` | UAF / Non-Paged Pool NX | Pool normalization primitive | — |
| `memory_disclosure_non_paged_pool_nx_named_pipe` | Memory disclosure + UAF | NamedPipe pool spray, heap grooming, pointer leak | — |

### The `win-kexp` Library

All exploit logic delegated to utility code lives in `win-kexp`. Key modules used across exploits:

- **`win32k`** — Windows kernel interaction wrappers: `get_device_handle`, `io_device_control`, `allocate_shellcode`, `get_ntoskrnl_base_address`, `load_library_no_resolve`, `allocate_memory`, `lock_memory`
- **`shellcode`** — Pre-built kernel shellcode blobs: `token_stealing_shellcode`, `token_stealing_shellcode_smep_no_kvashadow`, `token_stealing_shellcode_smep_no_kvashadow_pte`, `acl_edit_shellcode`, `spawn_cmd_shellcode`
- **`rop`** — ROP gadget scanning: `get_executable_sections`, `find_gadget_offset` (scans ntoskrnl sections loaded in userspace via `load_library_no_resolve`)
- **`process`** — `inject_shellcode_to_target_process` (classic remote thread injection)
- **`pool`** — `AnonymousPipe` RAII wrapper for pool spray primitives
- **Macros** — `IOCTL!` (computes IOCTL code from function code), `CTL_CODE!`, `create_rop_chain!` (builds a byte Vec from addresses + padding), `concat_rop_chain_to_buffer!`

### Common Patterns

**IOCTL definitions** — All exploits define IOCTL constants using the macro:
```rust
const HEVD_IOCTL_BUFFER_OVERFLOW_STACK: u32 = IOCTL!(0x800);
```

**Stack overflow trigger** — The HEVD stack buffer overflow return address is always at offset `0x818`. A padding buffer of `0x41` bytes is built up to that offset, then the shellcode/ROP chain address is appended.

**SMEP bypass via ROP (`smep_no_kvashadow`)** — Finds `pop rcx ; ret` and `mov cr4, rcx ; ret` gadgets in ntoskrnl, then builds a chain that sets CR4 bit 20 to 0 (disabling SMEP) before jumping to shellcode.

**SMEP bypass via PTE (`smep_no_kvashadow_pte`)** — Allocates a fake stack at a fixed user-mode address (`0x23400000`), builds a complex ROP chain that calls `MiGetPteAddress` (hardcoded offset `kernel_base + 0x288b28`) to locate and flip the NX bit in the PTE for both the shellcode and fake stack pages.

**ACL edit technique** — Executes kernel shellcode to modify the winlogon DACL (replacing the SYSTEM SID sub-authority with Authenticated Users `0x0B`) and disabling the mandatory integrity policy on the current process token, then injects a second shellcode into winlogon to spawn an elevated shell.
