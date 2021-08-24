# kdmapper-rs
Rust port of the popular kdmapper to manually map unloaded drivers in kernel-memory utilizing the vulnerable intel driver

# where is the driver?
I am 100% you have the driver somewhere, considering the fact it is a binary, I couldn't release the source to UC or any other site
if the repo contained binaries. So I removed it for that purpose. Note: It's location should be in `src/mapper/` with the name `driver.sys`

# warning
Currently still very much in development, it runs on Windows 20H2 succesfully

!image_info[](img/fn.png)

# how to compile
```
cargo build --release
```

# dependencies
* win-api