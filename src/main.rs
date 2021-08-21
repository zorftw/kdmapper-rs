#[cfg(not(windows))]
compile_error!("Can't compile, this is exclusive to Windows.");

pub mod util;
pub mod nt;
pub mod pe;

fn main() {
    println!("Hello, world!");
}
