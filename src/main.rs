use winapi::{um::{errhandlingapi::GetLastError, handleapi::INVALID_HANDLE_VALUE}};

#[cfg(not(windows))]
compile_error!("Can't compile, this is exclusive to Windows.");

pub mod mapper;
pub mod nt;
pub mod pe;
pub mod service;
pub mod util;

fn main() {
    let service = mapper::load_service("iqvw64e.sys");

    if service.is_null() || service == INVALID_HANDLE_VALUE {
        unsafe {
            println!(
                "Failed to create a handle to the service! Last error code: {}",
                GetLastError()
            );
        }
        panic!("See logs for panic!")
    }

    if mapper::load_image_into_kernel(
        service,
        "C:\\Users\\Zor\\source\\repos\\TestDriver\\x64\\Release\\TestDriver.sys".to_string(),
    ) == 0
    {
        unsafe {
            println!(
                "Failed to load image into kernel! Last error code: {}",
                GetLastError()
            );
        }
        panic!("See logs for panic!")
    }

    println!("Loaded image into kernel!");

    if !mapper::unload_service(service, "iqvw64e.sys\0") {
        unsafe {
            println!(
                "Failed to unload service! Last error code: {}",
                GetLastError()
            );
        }
        panic!("See logs for panic!")
    }

    println!("Unloaded service!");
}
