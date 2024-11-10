fn main() {
    // Link paths for OpenSSL
    println!("cargo:rustc-link-search=native=/opt/homebrew/Cellar/openssl@1.1/1.1.1w/lib");
    println!("cargo:rustc-link-search=native=/usr/lib"); // Link path for libz

    // Include path for OpenSSL headers
    println!("cargo:include=/opt/homebrew/Cellar/openssl@1.1/1.1.1w/include");

    // Link OpenSSL and zlib libraries
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=z");
}
