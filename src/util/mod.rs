use core::panic;
use std::{
    ffi::{CStr, CString},
    io::{Read, Write},
};

use winapi::{
    shared::ntdef::NT_SUCCESS,
    um::{
        memoryapi::{VirtualAlloc, VirtualFree},
        winnt::{
            DELETE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE, SERVICE_KERNEL_DRIVER,
        },
        winsvc::{
            CloseServiceHandle, ControlService, CreateServiceA, DeleteService, OpenSCManagerA,
            OpenServiceA, StartServiceA, SC_MANAGER_CREATE_SERVICE, SERVICE_CONTROL_STOP,
            SERVICE_START, SERVICE_STATUS, SERVICE_STOP,
        },
    },
};

use crate::nt;

pub fn create_file_from_memory(file: &str, address: usize, size: usize) -> bool {
    let mut file = std::fs::File::create(file).expect("Couldn't create/open file!");

    let mut data = vec![0u8; size]; // spawn a buffer size of the memory
    unsafe {
        std::ptr::copy(
            address as *const i8,
            data.as_mut_ptr() as *mut _,
            data.len(),
        )
    };

    file.write_all(data.as_slice()).expect("Couldn't write file");

    true
}

pub fn read_file_from_memory(file: &str, buffer: &mut Vec<u8>) -> bool {
    let mut file = std::fs::File::open(file).expect("Couldn't open file");

    file.read_to_end(buffer).expect("Couldn't read file");

    true
}

pub fn create_and_start_service(file: &str) -> bool {
    let filename = CString::new(
        std::path::Path::new(file)
            .file_name()
            .expect("Couldn't get filname")
            .to_str()
            .expect("Couldn't convert to str"),
    )
    .expect("Couldn't convert to CString");

    let manager = unsafe {
        OpenSCManagerA(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            SC_MANAGER_CREATE_SERVICE,
        )
    };

    if manager.is_null() {
        panic!("Failed to open service manager!");
    }

    let mut service = unsafe {
        CreateServiceA(
            manager,
            filename.as_ptr(),
            filename.as_ptr(),
            SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            file.as_ptr() as *const i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if service.is_null() {
        println!("Unable to create service, attempting to open instead");

        service = unsafe { OpenServiceA(manager, filename.as_ptr(), SERVICE_START) };

        if service.is_null() {
            unsafe { CloseServiceHandle(manager) };
            panic!("Unable to create service!");
        }
    }

    let result = unsafe { StartServiceA(service, 0, std::ptr::null_mut()) };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    result == 1
}

pub fn delete_and_stop_service(name: &str) -> bool {
    let manager = unsafe {
        OpenSCManagerA(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            SC_MANAGER_CREATE_SERVICE,
        )
    };

    if manager.is_null() {
        panic!("Unable to open service manager!");
    }

    let service =
        unsafe { OpenServiceA(manager, name.as_ptr() as *const i8, SERVICE_STOP | DELETE) };

    if service.is_null() {
        unsafe { CloseServiceHandle(service) };
        panic!("Failed to open service");
    }

    let mut status: SERVICE_STATUS = unsafe { core::mem::zeroed() };

    let result = unsafe {
        ControlService(service, SERVICE_CONTROL_STOP, &mut status as *mut _) == 1
            && DeleteService(service) == 1
    };

    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }

    result
}

pub fn get_kernel_module_address(name: &str) -> usize {
    let mut buffer: usize = 0;
    let mut buffer_size = 0u64;

    let mut system_info = nt::query_system_information(&mut buffer, &mut buffer_size);

    while system_info as u32 == nt::STATUS_INFO_LENGHT_MISMATCH {
        unsafe { VirtualFree(buffer as _, 0, MEM_RELEASE) };

        buffer = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                buffer_size as _,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        } as _;
        system_info = nt::query_system_information(&mut buffer, &mut buffer_size);
    }

    if !NT_SUCCESS(system_info) {
        unsafe { VirtualFree(buffer as _, 0, MEM_RELEASE) };
        return 0usize;
    }

    let modules: nt::RtlProcessModules = unsafe { (buffer as *mut nt::RtlProcessModules).read() };

    for i in 0..modules.number_of_modules {
        let module_name = unsafe {
            CStr::from_ptr(
                (modules.modules[i as usize].full_path_name.as_ptr() as usize
                    + modules.modules[i as usize].offset_to_file_name as usize)
                    as _,
            )
            .to_str()
            .expect("Couldn't parse name")
            .to_string()
        };

        if module_name.eq(name) {
            let result = modules.modules[i as usize].image_base as usize;

            unsafe { VirtualFree(buffer as _, 0, MEM_RELEASE) };

            return result;
        }
    }

    unsafe { VirtualFree(buffer as _, 0, MEM_RELEASE) };

    0usize
}
