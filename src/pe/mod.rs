use std::{ffi::CStr, intrinsics::transmute};

use winapi::um::winnt::{
    IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PIMAGE_BASE_RELOCATION, PIMAGE_DOS_HEADER,
    PIMAGE_IMPORT_BY_NAME, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS64, PIMAGE_THUNK_DATA64,
};

#[derive(Default)]
pub struct FunctionImportInfo {
    name: String,
    address: usize, // NOTE: apparently a pointer to an adress (so void*)
}

impl FunctionImportInfo {
    pub fn get_address(&self) -> *const u64 {
        self.address as _
    }
}

pub struct RelocationInfo {
    address: u64,
    item: *const u16,
    count: i32,
}

#[derive(Default)]
pub struct ImportInfo {
    name: String,
    function_info: Vec<FunctionImportInfo>,
}

pub fn get_nt_headers(base: *mut u8) -> PIMAGE_NT_HEADERS64 {
    unsafe {
        let dos_header = transmute::<*mut u8, PIMAGE_DOS_HEADER>(base);

        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return std::ptr::null_mut();
        }

        let nt_headers = transmute::<usize, PIMAGE_NT_HEADERS64>(
            base as usize + (*dos_header).e_lfanew as usize,
        );

        if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return std::ptr::null_mut();
        }

        nt_headers
    }
}

pub fn get_relocations(base: *mut u8) -> Option<Vec<RelocationInfo>> {
    let nt_headers = get_nt_headers(base);

    if nt_headers.is_null() {
        return None;
    }

    let mut current_base_relocation = unsafe {
        transmute::<usize, PIMAGE_BASE_RELOCATION>(
            base as usize
                + (*nt_headers).OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
                    .VirtualAddress as usize,
        )
    };

    let relocation_end = unsafe {
        current_base_relocation as usize
            + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
                .Size as usize
    };

    let mut result = vec![];

    while unsafe {
        (*current_base_relocation).VirtualAddress != 0u32
            && (*current_base_relocation).VirtualAddress as usize <= relocation_end
            && (*current_base_relocation).SizeOfBlock != 0u32
    } {
        let mut info = unsafe {
            RelocationInfo {
                ..core::mem::zeroed()
            }
        };

        info.address =
            unsafe { base as usize + (*current_base_relocation).VirtualAddress as usize } as _;
        info.item = unsafe {
            transmute::<usize, *const u16>(
                current_base_relocation as usize + std::mem::size_of::<IMAGE_BASE_RELOCATION>(),
            )
        };
        info.count = unsafe {
            ((*current_base_relocation).SizeOfBlock as usize
                - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<u16>()
        } as _;

        result.push(info);

        current_base_relocation = unsafe {
            transmute::<usize, PIMAGE_BASE_RELOCATION>(
                current_base_relocation as usize + (*current_base_relocation).SizeOfBlock as usize,
            )
        };
    }

    Some(result)
}

pub fn get_imports(base: *mut u8) -> Option<Vec<ImportInfo>> {
    let nt_headers = get_nt_headers(base);

    if nt_headers.is_null() {
        return None;
    }

    let mut result = vec![];

    let mut current_import_descriptor = unsafe {
        transmute::<usize, PIMAGE_IMPORT_DESCRIPTOR>(
            base as usize
                + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
                    .VirtualAddress as usize,
        )
    };

    while unsafe { (*current_import_descriptor).FirstThunk } != 0 {
        let mut info = ImportInfo::default();

        info.name = unsafe {
            CStr::from_ptr(transmute::<usize, *const i8>(
                base as usize + (*current_import_descriptor).Name as usize,
            ))
            .to_str()
            .unwrap_or_default()
            .to_string()
        };
        let mut current_first_thunk = unsafe {
            transmute::<usize, PIMAGE_THUNK_DATA64>(
                base as usize + (*current_import_descriptor).FirstThunk as usize,
            )
        };
        let mut current_original_first_thunks = unsafe {
            transmute::<usize, PIMAGE_THUNK_DATA64>(
                base as usize + *(*current_import_descriptor).u.OriginalFirstThunk() as usize,
            )
        };

        while unsafe { *(*current_original_first_thunks).u1.Function() != 0 } {

            let mut function_info: FunctionImportInfo = FunctionImportInfo::default();

            let thunk_data = unsafe {
                transmute::<usize, PIMAGE_IMPORT_BY_NAME>(
                    base as usize + *(*current_original_first_thunks).u1.AddressOfData() as usize,
                )
            };

            function_info.name = unsafe {
                CStr::from_ptr((*thunk_data).Name.as_ptr())
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };

            function_info.address = unsafe { &*(*current_first_thunk).u1.Function() } as *const _ as usize;

            info.function_info.push(function_info);

            current_first_thunk = unsafe { current_first_thunk.offset(1) };
            current_original_first_thunks = unsafe { current_first_thunk.offset(1) };
        }

        result.push(info);
        current_import_descriptor = unsafe { current_import_descriptor.offset(1) };
    }

    Some(result)
}
