use std::intrinsics::transmute;

use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{DWORD, FARPROC, ULONG},
        ntdef::{HANDLE, NTSTATUS, PULONG, PVOID, UCHAR, USHORT},
    },
    um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
};

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

pub struct QuerySystemInformationReturnValue {
    pub buffer: *mut c_void,
    pub buffer_size: DWORD,
    pub result: NTSTATUS,
}

pub fn query_system_information(
    buffer: *mut c_void,
    out_buffer_size: &mut DWORD,
) -> QuerySystemInformationReturnValue {
    let mut nt = unsafe { GetModuleHandleA("ntdll.dll\0".as_ptr() as _) };

    if nt.is_null() {
        nt = unsafe { LoadLibraryA("ntdll.dll\0".as_ptr() as _) };

        if nt.is_null() {
            panic!("Couldn't get handle to NTDLL.dll");
        }
    }

    let query_system_info_address =
        unsafe { GetProcAddress(nt, "NtQuerySystemInformation\0".as_ptr() as *const i8) };

    if query_system_info_address.is_null() {
        panic!("Couldn't find NtQuerySystemInformation");
    }

    let query_system_info = unsafe {
        transmute::<FARPROC, unsafe extern "system" fn(i32, *mut c_void, ULONG, PULONG) -> NTSTATUS>(
            query_system_info_address,
        )
    };

    let mut buffer_size: DWORD = *out_buffer_size;

    let result = unsafe { query_system_info(11, buffer, buffer_size, &mut buffer_size as *mut _) };
    *out_buffer_size = buffer_size;

    QuerySystemInformationReturnValue {
        buffer,
        buffer_size,
        result,
    }
}
