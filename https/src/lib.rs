use flate2::read::GzDecoder;
use libc::{c_char, c_int, socket};
use std::ffi::{c_void, CStr};
use std::io::{self, Read};
use std::slice;

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

fn skip_crlf(body: &[u8]) -> &[u8] {
    assert_eq!(&body[0..2], b"\r\n");
    &body[2..]
}

fn read_chunk_size(body: &[u8]) -> (usize, &[u8]) {
    // Find the position of the first CR in the chunk size
    let chunk_size_str = match body.iter().position(|&x| x == b'\r') {
        Some(pos) => &body[..pos],
        None => return (0, body), // If no CR found, return 0 size and the original body
    };

    // Convert the byte slice to a string, then parse it as a hexadecimal number
    let chunk_size = match std::str::from_utf8(chunk_size_str) {
        Ok(s) => match usize::from_str_radix(s, 16) {
            Ok(size) => size,
            Err(_) => return (0, body), // Parsing failed, return 0 size
        },
        Err(_) => return (0, body), // UTF-8 conversion failed, return 0 size
    };

    // Skip the CRLF after the chunk size
    let rest = skip_crlf(&body[chunk_size_str.len() + 2..]); // Skip the CRLF as well

    (chunk_size, rest)
}

fn read_chunked_http_body(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded_body = Vec::new();
    let mut body_len = body.len();
    let mut body = body;

    while body_len > 0 {
        let (chunk_size, rest) = read_chunk_size(body);
        body_len -= rest.as_ptr() as usize - body.as_ptr() as usize;
        body = rest;

        if chunk_size == 0 {
            break;
        }

        if body_len < chunk_size {
            decoded_body.extend_from_slice(&body[..body_len]);
            return Ok(decoded_body);
        }

        decoded_body.extend_from_slice(&body[..chunk_size]);
        body = &body[chunk_size..];
        body_len -= chunk_size;

        if body_len < 2 || &body[0..2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing CRLF after chunk",
            ));
        }
        body = skip_crlf(body);
        body_len -= 2;
    }

    Ok(decoded_body)
}

fn decompress_gzip(compressed_data: &[u8], output_len: usize) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(compressed_data);
    let mut output = vec![0; output_len];
    decoder.read_exact(&mut output)?;
    Ok(output)
}

fn http_body_offset(http_str: &[u8]) -> i32 {
    if let Some(pos) = http_str.windows(4).position(|w| w == b"\r\n\r\n") {
        (pos + 4) as i32
    } else {
        -1
    }
}

fn print_buffer(buff: *const c_char, len: usize) {
    // Convert C-style string to Rust string
    unsafe {
        // Make sure the pointer is valid and the length is correct
        let c_str = CStr::from_ptr(buff);
        let str_slice = c_str.to_str().unwrap_or("");

        println!("[print_buffer] Buffer:");
        for (_, c) in str_slice.chars().take(len).enumerate() {
            print!("{}", c);
        }

        println!();
    }
}

#[no_mangle]
pub extern "C" fn __interpose_SSL_read(ssl: *mut c_void, buf: *mut c_void, num: i32) -> i32 {
    let ret = real_ssl_read(ssl, buf, num);
    println!("[debug] SSL ret {}", ret);

    let buf_slice: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, ret as usize) };

    if ret > 0 {
        let body_offset = http_body_offset(buf_slice);

        if body_offset == -1 {
            println!("Not HTTP body: {:?}", ssl);
            return ret;
        }

        print_buffer(buf as *const c_char, (body_offset - 1) as usize);

        let _body_len = ret - body_offset;
        let mut _result_body: Vec<u8> = Vec::new();
        let _ = read_chunked_http_body(&buf_slice[body_offset as usize..]);
    }

    ret
}
