## How to use it
DYLD_INSERT_LIBRARIES works for Ruby but not Ruby scripts, so for capturing https plaintext in Rails, we need to run Rails through:

```
DYLD_INSERT_LIBRARIES=/{PATH_TO_CURRENT_DIR}/target/release/libhttps.dylib ruby /Users/y/.rvm/gems/ruby-3.1.5/bin/puma -p 3000
```

More info: https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection