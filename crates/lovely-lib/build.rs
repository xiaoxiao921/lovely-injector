// build.rs
fn main() {
    // Tell Cargo to tell rustc to link against the required Windows libs
    println!("cargo:rustc-link-lib=userenv");
    println!("cargo:rustc-link-lib=ntdll");
    println!("cargo:rustc-link-lib=ws2_32");
}
