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

## CI / Automation

### GitHub Actions (`.github/workflows/ci.yml`)

Triggers on push/PR to `main` and manual dispatch. Runs on `windows-latest` with Rust stable. Steps in order:

1. Checkout (`actions/checkout@v6`)
2. Setup MSBuild (`microsoft/setup-msbuild@v3`)
3. Setup MASM (`glslang/setup-masm@v1`)
4. Install Rust stable (`rustup update stable && rustup default stable`)
5. Cache Cargo registry and build artifacts (`Swatinem/rust-cache@v2`)
6. `cargo fmt --all --verbose -- --check` — formatting gate; must pass
7. `cargo update` — refresh dependencies
8. `cargo build --verbose`
9. `cargo test --verbose`

### Dependabot (`.github/dependabot.yml`)

- **Cargo**: weekly on Monday 09:00 UTC, limit 10 PRs, label `dependencies`/`rust`, prefix `cargo`
- **GitHub Actions**: weekly on Monday 09:00 UTC, limit 5 PRs, label `dependencies`/`github-actions`, prefix `ci`
- Reviewer/assignee: `glslang`

## Architecture

### Workspace Layout

Each subdirectory is an independent exploit crate with a single `src/main.rs`. All crates share a single external dependency: `win-kexp` (fetched from GitHub, no version pin — always latest `main`).

| Crate | Vulnerability | Technique | Mitigations Bypassed |
|---|---|---|---|
| `stack_buffer_overflow_token_stealing` | Stack buffer overflow | Token stealing shellcode | None (SMEP/KPTI disabled) |
| `stack_buffer_overflow_acl_edit` | Stack buffer overflow | ACL edit + process injection into winlogon | None (SMEP/KPTI disabled) |
| `stack_buffer_overflow_token_stealing_smep_no_kvashadow` | Stack buffer overflow | Token stealing + ROP SMEP disable via CR4 | SMEP (no KVA Shadow) |
| `stack_buffer_overflow_token_stealing_smep_no_kvashadow_pte` | Stack buffer overflow | Token stealing + PTE-based SMEP disable via ROP | SMEP (no KVA Shadow) |
| `buffer_overflow_non_paged_pool_nx` | UAF / Non-Paged Pool NX | Pool normalization primitive | — |
| `memory_disclosure_non_paged_pool_nx_named_pipe` | Memory disclosure + UAF | NamedPipe pool spray, heap grooming, pointer leak | — |

### The `win-kexp` Library

All exploit logic delegated to utility code lives in `win-kexp`. Key modules used across exploits:

- **`win32k`** — Windows kernel interaction wrappers: `get_device_handle`, `io_device_control`, `allocate_shellcode`, `get_ntoskrnl_base_address`, `load_library_no_resolve`, `allocate_memory`, `lock_memory`, `close_handle`, `create_cmd_process`; constants `FILE_ANY_ACCESS`, `FILE_DEVICE_UNKNOWN`, `METHOD_NEITHER`, `MEM_COMMIT`, `MEM_RESERVE`, `PAGE_EXECUTE_READWRITE`, `HANDLE`
- **`shellcode`** — Pre-built kernel shellcode blobs: `token_stealing_shellcode`, `token_stealing_shellcode_smep_no_kvashadow`, `token_stealing_shellcode_smep_no_kvashadow_pte`, `acl_edit_shellcode`, `spawn_cmd_shellcode`
- **`rop`** — ROP gadget scanning: `get_executable_sections`, `find_gadget_offset` (scans ntoskrnl sections loaded in userspace via `load_library_no_resolve`)
- **`process`** — `inject_shellcode_to_target_process` (classic remote thread injection into a named process)
- **`pool`** — `AnonymousPipe` RAII wrapper for pool spray primitives
- **`util`** — `bytes_to_hex_string` (formats a raw pointer + length as a hex string for diagnostic output)
- **Macros** — `IOCTL!` (computes IOCTL code from function code), `CTL_CODE!`, `create_rop_chain!` (builds a byte `Vec` from addresses + `base_offset` padding), `concat_rop_chain_to_buffer!` (writes multiple chains into a mutable slice)

## IOCTL Codes

All exploits define IOCTL constants at the top of `main.rs` using the `IOCTL!` macro:

```rust
const HEVD_IOCTL_BUFFER_OVERFLOW_STACK: u32                    = IOCTL!(0x800);
const HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX: u32      = IOCTL!(0x813);
const HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX: u32    = IOCTL!(0x814);
```

## Common Patterns

**Device path** — All exploits open the same device: `r"\\.\HackSysExtremeVulnerableDriver\0"`

**Stack overflow trigger** — The HEVD stack buffer overflow return address is always at offset `0x818`. The payload buffer is `0x818` bytes of `0x41` filler followed by the 8-byte little-endian address:

```rust
let user_buffer: Vec<u8> = iter::repeat_n(0x41u8, 0x818)
    .chain(target_address.to_le_bytes().iter().cloned())
    .collect();
```

**SMEP bypass via ROP (`smep_no_kvashadow`)** — Loads ntoskrnl with `load_library_no_resolve`, scans executable sections, finds two gadgets, builds a three-entry ROP chain:

```
pop rcx ; ret      → bytes [0x59, 0xC3]
mov cr4, rcx ; ret → bytes [0x0F, 0x22, 0xE1, 0xC3]
```

Chain: `pop rcx` → `0xA50EF8` (CR4 value with bit 20 cleared, disabling SMEP) → `mov cr4, rcx` → shellcode address.

**SMEP bypass via PTE (`smep_no_kvashadow_pte`)** — The most complex exploit. Allocates a fake stack at the fixed user-mode address `0x23400000` (size `0x28000`, `PAGE_EXECUTE_READWRITE`, locked), fills it with `0x41`, then writes ROP sub-chains starting at offset `+0x18f1b` within the allocation. The main overflow chain contains a single stack-pivot gadget (`mov esp, 0xC48348FF`), diverting execution to the fake stack where five sub-chains run in sequence:

1. `restore_rsp_rop_chain` — restores RSP from the fake stack
2. `restore_r15_rop_chain` — restores R15 (with pointer dereference)
3. `disable_fake_stack_smep_chain` — calls `MiGetPteAddress` on the fake stack page and XORs the NX bit (`0x4`)
4. `disable_shellcode_smep_chain` — same for the shellcode page
5. `prologue_chain` — `add rsp, 0x28` shadow-space cleanup then jump to shellcode

`MiGetPteAddress` is at hardcoded offset `kernel_base + 0x288b28`.

**PTE gadget set** (15 gadgets, all in ntoskrnl, all found via `find_gadget_offset`):

| Gadget | Bytes |
|---|---|
| `pop rcx ; ret` | `59 C3` |
| `pop r15 ; ret` | `41 5F C3` |
| `pop rax ; ret` | `58 C3` |
| `push rax ; ret` | `36 50 C3` |
| `mov r8, rax ; mov rax, r8 ; ret` | `4C 8B C0 49 8B C0 C3` |
| `mov rcx, r8 ; mov rax, rcx ; ret` | `49 8B C8 48 8B C1 C3` |
| `xor [rcx], rax ; ret` | `48 31 01 C3` |
| `mov [r8], rcx ; ret` | `49 89 08 C3` |
| `pop r8 ; ret` | `41 58 C3` |
| `pop rsp ; ret` | `5C C3` |
| `mov esp, 0xC48348FF ; ret` (stack pivot) | `BC 1B 8F 41 23 C3` |
| `add rsp, 0x28 ; ret` | `48 83 C4 28 C3` |
| `pop r9 ; ret` | `41 59 C3` |
| `add rcx, r9 ; cmp r8, rcx ; setae al ; ret` | `49 03 C9 4C 3B C1 0F 93 C0 C3` |
| `mov rcx, [rcx] ; cmp rcx, rdx ; sete al ; ret` | `48 8B 09 48 3B CA 0F 94 C0 C3` |

**ACL edit technique** — Executes `acl_edit_shellcode` in kernel context via the overflow (no SMEP). The shellcode:
- Walks `ActiveProcessLinks` to find winlogon's EPROCESS
- Locates the security descriptor at `EPROCESS - 0x30 + 0x28` (masked: `& 0xFFFFFFFFFFFFFFF0`)
- Adds `0x48` to reach the first ACE and writes `0x0B` (Authenticated Users sub-authority) over the SYSTEM SID sub-authority
- Locates the current process token at `EPROCESS + TOKEN_OFFSET` (masked) and writes `0` at `+ 0xD4` to set `TOKEN_MANDATORY_POLICY_OFF`

Windows 11 (build 22631) kernel structure offsets used by the shellcode:

```asm
KTHREAD_OFFSET        EQU 188h   ; GS → current KTHREAD
EPROCESS_OFFSET       EQU 0B8h   ; KTHREAD → EPROCESS
ACTIVEPROCESSLINKS    EQU 448h
IMAGEFILENAME_OFFSET  EQU 5A8h
TOKEN_OFFSET          EQU 4B8h
```

After the kernel shellcode returns, `spawn_cmd_shellcode` is injected into winlogon via `inject_shellcode_to_target_process("winlogon.exe", &shellcode)`.

**Pool normalization** (`buffer_overflow_non_paged_pool_nx`) — Calls `HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX` (`0x814`) 0x80 times to fill fragmentation holes before the main exploitation step.

**Pool spray + memory disclosure** (`memory_disclosure_non_paged_pool_nx_named_pipe`) — Full heap-grooming sequence:

1. Normalize: 0x80 UAF allocations
2. Spray: 0x800 `AnonymousPipe` objects (buffer size = `0x70 - 0x48 = 0x28`), write `0x41` bytes to each
3. Create holes: drop every other pipe (odd indices via `step_by(2)`)
4. Fill holes: 0x800 more UAF allocations
5. Remove remaining pipes
6. Leak loop (up to 100 iterations): call `HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX` (`0x813`), read 0x100-byte output into a 0x700 buffer
7. Scan 8-byte-aligned chunks for leak signature:
   - `(ptr[i] & 0xFFFFFFFF00000000) == 0x6b63614800000000` — ASCII "hack" watermark at low 32 bits
   - `(ptr[i+2] & 0xFFFFF00000000000) == 0xFFFFF00000000000` — kernel-mode address
8. Calculate HEVD base: `leaked_UaFObjectCallback_ptr - 0x880E8`
