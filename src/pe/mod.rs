use std::{ffi::CStr, intrinsics::transmute};

use winapi::um::winnt::{
    IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, PIMAGE_BASE_RELOCATION, PIMAGE_DOS_HEADER,
    PIMAGE_IMPORT_BY_NAME, PIMAGE_IMPORT_DESCRIPTOR, PIMAGE_NT_HEADERS64, PIMAGE_THUNK_DATA64,
};

#[derive(Default)]
pub struct FunctionImportInfo {
    pub name: String,
    pub address: usize, // NOTE: apparently a pointer to an adress (so void*)
}

impl FunctionImportInfo {
    pub fn get_address(&self) -> *mut u64 {
        self.address as _
    }
}

pub struct RelocationInfo {
    pub address: u64,
    pub item: *const u16,
    pub count: i32,
}

#[derive(Default)]
pub struct ImportInfo {
    pub name: String,
    pub function_info: Vec<FunctionImportInfo>,
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

    unsafe {
        let import_va = (*nt_headers).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress;

        if import_va == 0 {
            return None;
        }

        let mut vec_imports = Vec::new();

        let mut current_import_descriptor =
            (base as usize + import_va as usize) as PIMAGE_IMPORT_DESCRIPTOR;

        while (*current_import_descriptor).FirstThunk != 0 {
            let mut import_info = ImportInfo::default();

            import_info.name = CStr::from_ptr(
                (base as usize + (*current_import_descriptor).Name as usize) as *const i8,
            )
            .to_str()
            .expect("Couldn't convert to str")
            .to_string();

            let mut current_first_thunk = (base as usize
                + (*current_import_descriptor).FirstThunk as usize)
                as PIMAGE_THUNK_DATA64;
            let mut current_original_first_thunk = (base as usize
                + *(*current_import_descriptor).u.OriginalFirstThunk() as usize)
                as PIMAGE_THUNK_DATA64;

            while (*(*current_original_first_thunk).u1.Function()) != 0 {
                let mut import_function_data = FunctionImportInfo::default();

                let thunk_data = (base as usize
                    + *(*current_original_first_thunk).u1.AddressOfData() as usize)
                    as PIMAGE_IMPORT_BY_NAME;

                import_function_data.name = CStr::from_ptr((*thunk_data).Name.as_ptr())
                    .to_str()
                    .expect("couldn't convert to str")
                    .to_string();
                import_function_data.address =
                    (*current_first_thunk).u1.Function_mut() as *mut u64 as usize;

                import_info.function_info.push(import_function_data);

                current_original_first_thunk = (current_original_first_thunk as usize
                    + std::mem::size_of::<PIMAGE_THUNK_DATA64>())
                    as PIMAGE_THUNK_DATA64;
                current_first_thunk = (current_first_thunk as usize
                    + std::mem::size_of::<PIMAGE_THUNK_DATA64>())
                    as PIMAGE_THUNK_DATA64;
            }

            vec_imports.push(import_info);
            current_import_descriptor = (current_import_descriptor as usize
                + std::mem::size_of::<PIMAGE_IMPORT_DESCRIPTOR>())
                as PIMAGE_IMPORT_DESCRIPTOR;
        }

        Some(vec_imports)
    }
}
