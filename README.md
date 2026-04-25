# hevd-exp ![Build Status](https://github.com/glslang/hevd-exp/actions/workflows/ci.yml/badge.svg) [![Dependency status](https://deps.rs/repo/github/glslang/hevd-exp/status.svg)](https://deps.rs/repo/github/glslang/hevd-exp)

Windows kernel exploit proof-of-concepts written in Rust, targeting [HackSys Extreme Vulnerable Driver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) on Windows 11.

## Exploits

| Crate | Vulnerability | Technique | Mitigations Bypassed |
|---|---|---|---|
| `stack_buffer_overflow_token_stealing` | Stack buffer overflow | Token stealing shellcode | None (SMEP/KPTI disabled) |
| `stack_buffer_overflow_acl_edit` | Stack buffer overflow | ACL edit + process injection into winlogon | None (SMEP/KPTI disabled) |
| `stack_buffer_overflow_token_stealing_smep_no_kvashadow` | Stack buffer overflow | Token stealing + ROP SMEP disable | SMEP (no KVA Shadow) |
| `stack_buffer_overflow_token_stealing_smep_no_kvashadow_pte` | Stack buffer overflow | Token stealing + PTE-based SMEP disable via ROP | SMEP (no KVA Shadow) |
| `buffer_overflow_non_paged_pool_nx` | UAF / Non-Paged Pool NX | Pool normalization primitive | — |
| `memory_disclosure_non_paged_pool_nx_named_pipe` | Memory disclosure + UAF | NamedPipe pool spray, heap grooming, pointer leak | — |

## Prerequisites

- Windows 11 x86-64
- Rust stable toolchain (`rustup update stable`)
- MSBuild and MASM (required by the [`win-kexp`](https://github.com/glslang/win-kexp) dependency for inline assembly)
- HEVD installed and running on the target system

## Build

```bash
# Build all exploits
cargo build --verbose

# Build a single exploit
cargo build -p stack_buffer_overflow_token_stealing
```

## Dependencies

All shared logic (Windows API wrappers, shellcode blobs, ROP utilities, pool primitives) lives in [`win-kexp`](https://github.com/glslang/win-kexp).

## References

- [HackSys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
- [win-kexp utility library](https://github.com/glslang/win-kexp)
- [Windows Kernel Shellcode on Windows 10 Part 2 (Improsec)](https://blog.improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2) — ACL edit technique
