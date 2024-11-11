#[macro_use]
extern crate lazy_static;

use flate2::read::GzDecoder;
use libc::{c_int, socket};
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{self, Read};
use std::slice;
use std::sync::Mutex;

lazy_static! {
    static ref GLOBAL_HASHMAP: Mutex<HashMap<usize, Vec<u8>>> = Mutex::new(HashMap::new());
}

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
    assert_eq!(&body[0..2], b"\r\n"); // b"\r\n" = [13, 10]
    &body[2..]
}

fn read_chunk_size(body: &[u8]) -> (usize, &[u8]) {
    // Find the position of the first CR in the chunk size
    let chunk_pos = match body.iter().position(|&x| x == b'\r') {
        Some(pos) => pos,
        None => return (0, body), // If no CR found, return 0 size and the original body
    };

    // Convert the byte slice to a string, then parse it as a hexadecimal number
    let chunk_size = match std::str::from_utf8(&body[..chunk_pos]) {
        Ok(s) => match usize::from_str_radix(s, 16) {
            Ok(size) => size,
            Err(_) => return (0, body), // Parsing failed, return 0 size
        },
        Err(_) => return (0, body), // UTF-8 conversion failed, return 0 size
    };

    println!(
        "[debug][read_chunk_size] chunk_size={:?}, chunk_pos={:?}, body.len={:?}",
        chunk_size,
        chunk_pos,
        body.len()
    );

    // Skip the CRLF after the chunk size
    let end_of_size = body
        .windows(2) // Iterate over windows of 2 bytes
        .position(|window| window == b"\r\n") // Find the position of the "\r\n" sequence
        .map(|pos| &body[pos..]); // Get a slice starting from the found position

    match end_of_size {
        Some(slice) => {
            println!("end_of_size");
            let rest = skip_crlf(&slice);
            return (chunk_size, rest);
        }
        None => return (chunk_size, body),
    }
}

fn read_chunked_http_body(body: &[u8]) -> io::Result<Vec<u8>> {
    println!("[read_chunked_http_body] enter");
    let mut decoded_body = Vec::new();
    let mut body_len = body.len();
    let mut body = body;
    println!("body={:?}\n", body);

    while body_len > 0 {
        let (chunk_size, rest) = read_chunk_size(body);
        println!("[read_chunked_http_body] chunk_size={}...", chunk_size);

        body = rest;
        body_len = rest.len();

        if chunk_size == 0 {
            break;
        }

        if body_len < chunk_size {
            println!(
                "[debug][read_chunked_http_body] not enough, remain={:?}, chunk_size=#{:?}, body_len={:?}",
                chunk_size - body_len,
                chunk_size,
                body_len
            );
            decoded_body.extend_from_slice(&body[..body_len]);
            return Ok(decoded_body);
        }

        decoded_body.extend_from_slice(&body[..chunk_size]);
        body = &body[chunk_size..];

        body_len -= chunk_size;

        if body_len < 2 || &body[0..2] != b"\r\n" {
            println!("[debug] Remain body_len < 2");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing CRLF after chunk",
            ));
        }
        println!("[debug] body={:?}", body);
        body = skip_crlf(body);

        body_len -= 2;
    }

    // get remain body

    decoded_body.extend_from_slice(&body);
    println!("decoded_body={:?}", decoded_body);

    Ok(decoded_body)
}

fn decompress_gzip(compressed_data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    Ok(decompressed_data)
}

fn http_body_offset(http_str: &[u8]) -> i32 {
    if let Some(pos) = http_str.windows(4).position(|w| w == b"\r\n\r\n") {
        (pos + 4) as i32
    } else {
        -1
    }
}

fn print_buffer(buff: &[u8], len: usize) {
    let mut i = 0;
    println!("[print_buffer] Buffer: len={}", len);

    while i < len {
        print!("{}", buff[i] as char);
        i += 1;
    }
}

#[no_mangle]
pub extern "C" fn __interpose_SSL_read(ssl: *mut c_void, buf: *mut c_void, num: i32) -> i32 {
    let ret = real_ssl_read(ssl, buf, num);
    println!("length ={}", ret);
    if ret > 0 {
        let buf_slice: &[u8] = unsafe { slice::from_raw_parts(buf as *const u8, ret as usize) };

        if buf_slice.ends_with(b"0\r\n\r\n") {
            let mut map = GLOBAL_HASHMAP.lock().unwrap();
            let mut buffer = map.get(&(ssl as usize)).unwrap().to_vec();
            buffer.extend(buf_slice);
            map.remove(&(ssl as usize));

            let body_offset = http_body_offset(&buffer);

            if body_offset == -1 {
                println!("Not HTTP body: {:?}", ssl);
                return ret;
            }

            println!("body_offset={}", body_offset);

            match read_chunked_http_body(&buffer[body_offset as usize..]) {
                Ok(body) => {
                    let decompressed_output = match decompress_gzip(&body) {
                        Ok(output) => output,
                        Err(e) => {
                            eprintln!("Decompression error: {}", e);
                            return ret;
                        }
                    };
                    println!("decompressed_output ={:?}", decompressed_output);

                    print_buffer(&decompressed_output, decompressed_output.len());
                    return ret;
                }
                Err(_) => {
                    return ret;
                }
            }
        } else {
            let mut map = GLOBAL_HASHMAP.lock().unwrap();
            if map.contains_key(&(ssl as usize)) {
                let mut buffer = map.get(&(ssl as usize)).unwrap().to_vec();
                buffer.extend(buf_slice);
                map.insert(ssl as usize, buffer);
            } else {
                map.insert(ssl as usize, buf_slice.to_vec());
            }

            println!("not ended");
        }
    }

    ret
}
