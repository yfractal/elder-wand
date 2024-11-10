use libc::{c_int, socket};
use std::ffi::c_void;

extern "C" {
    fn SSL_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int;
}

#[repr(C)]
pub struct OsxInterpose {
    pub new_func: *const std::ffi::c_void,
    pub orig_func: *const std::ffi::c_void,
}
unsafe impl Sync for OsxInterpose {}

#[link_section = "__DATA,__interpose"]
#[used]
static __OSX_INTERPOSE_SOCKET: OsxInterpose = OsxInterpose {
    new_func: __interpose_socket as *const fn(c_int, c_int, c_int) -> c_int as *const c_void,
    orig_func: socket as *const fn(c_int, c_int, c_int) -> c_int as *const c_void,
};

#[link_section = "__DATA,__interpose"]
#[used]
static __OSX_INTERPOSE_SSL_READ: OsxInterpose = OsxInterpose {
    new_func: __interpose_SSL_read as *const fn(*mut c_void, *mut c_void, c_int) -> c_int
        as *const c_void,
    orig_func: SSL_read as *const fn(*mut c_void, *mut c_void, c_int) -> c_int as *const c_void,
};

fn real_socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int {
    unsafe { socket(domain, type_, protocol) }
}

fn real_ssl_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int {
    unsafe { SSL_read(ssl, buf, num) }
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

#[no_mangle]
pub extern "C" fn __interpose_SSL_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int {
    println!("Interposed SSL_read ssl={:?}, buf={:?}, num={}", ssl, buf, num);

    let ret = real_ssl_read(ssl, buf, num);

    ret
}
