use libc::{c_int, socket};
use std::ffi::c_void;

#[repr(C)]
pub struct OsxInterpose {
    pub new_func: *const std::ffi::c_void,
    pub orig_func: *const std::ffi::c_void,
}
unsafe impl Sync for OsxInterpose {}

fn real_socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int {
    unsafe { socket(domain, type_, protocol) }
}

#[no_mangle]
pub extern "C" fn __interpose_socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int {
    println!(
        "Interposed socket function called with domain: {}, type: {}, protocol: {}",
        domain, type_, protocol
    );

    let ret = real_socket(domain, type_, protocol);

    ret
}

#[link_section = "__DATA,__interpose"]
#[used]
static __OSX_INTERPOSE_SOCKET: OsxInterpose = OsxInterpose {
    new_func: __interpose_socket as *const fn(c_int, c_int, c_int) -> c_int as *const c_void,
    orig_func: socket as *const fn(c_int, c_int, c_int) -> c_int as *const c_void,
};