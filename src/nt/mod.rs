use std::intrinsics::transmute;

use winapi::{shared::{minwindef::{FARPROC, ULONG}, ntdef::{HANDLE, NTSTATUS, PVOID, UCHAR, USHORT}}, um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA}};

#[repr(C)]
pub struct RtlProcessModuleInformation {
    pub section: HANDLE,
    pub mapped_base: PVOID,
    pub image_base: PVOID,
    pub image_size: ULONG,
    pub flags: ULONG,
    pub load_order_index: USHORT, 
    pub init_order_index: USHORT,
    pub load_count: USHORT,
    pub offset_to_file_name: USHORT,
    pub full_path_name: [UCHAR; 256],
}

#[repr(C)]
pub struct RtlProcessModules {
    pub number_of_modules: ULONG,
    pub modules: [RtlProcessModuleInformation; 1],
}

pub const STATUS_INFO_LENGHT_MISMATCH: u32 = 0xC0000004;

pub fn query_system_information(buffer: &mut usize, size: &mut u64) -> NTSTATUS {
    let mut nt = unsafe { GetModuleHandleA("ntdll.dll".as_ptr() as *const i8) };

    if nt.is_null() {
        nt = unsafe { LoadLibraryA("ntdll.dll".as_ptr() as *const i8) };

        if nt.is_null() {
            panic!("Couldn't get handle to NTDLL.dll");
        }
    }

    let query_system_info_address =
        unsafe { GetProcAddress(nt, "NtQuerySystemInformation".as_ptr() as *const i8) };

    if query_system_info_address.is_null() {
        panic!("Couldn't find NtQuerySystemInformation");
    }

    let query_system_info = unsafe {
        transmute::<FARPROC, fn(i32, *mut usize, u64, *const u64) -> NTSTATUS>(
            query_system_info_address,
        )
    };

    query_system_info(11, buffer as _, *size, size)
}
