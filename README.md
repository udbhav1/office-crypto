office-crypto
=============
[![crates.io](https://img.shields.io/crates/v/office-crypto)](https://crates.io/crates/office-crypto)
[![docs](https://img.shields.io/docsrs/office-crypto)](https://docs.rs/office-crypto)

Pure Rust library to decrypt password-protected MS Office files.

https://docs.rs/office-crypto

## Example

This crate exposes two functions: `decrypt_from_file` and `decrypt_from_bytes`, which do exactly what they say they do. The resulting bytes can then be interpreted by any MS Office parser like [docx-rs](https://crates.io/crates/docx-rs) or [calamine](https://crates.io/crates/calamine).

```rust
use docx_rs::read_docx;
use office_crypto::decrypt_from_file;

let path = "protected.docx";
let decrypted = decrypt_from_file(path, "Password1234_").unwrap(); 
let docx = read_docx(&decrypted).unwrap();
```

## Formats

* [x] ECMA-376 (Agile Encryption/Standard Encryption)
    * [x] MS-DOCX (OOXML) (Word 2007-Present)
    * [x] MS-XLSX (OOXML) (Excel 2007-Present)
    * [x] MS-PPTX (OOXML) (PowerPoint 2007-Present)
* [-] Office Binary Document RC4 CryptoAPI
    * [x] MS-DOC (Word 2002, 2003, 2004)
    * [ ] MS-XLS (Excel 2002, 2003, 2004)
    * [ ] MS-PPT (PowerPoint 2002, 2003, 2004)
* [ ] ECMA-376 (Extensible Encryption)

Non-SHA512 hash functions are not yet implemented. This only affects Agile encrypted files, but I have yet to find one that doesn't use SHA512.

## Performance

Measured on an M4 Max:
```
test bench_agile_sha512        ... bench:  15,029,308 ns/iter (+/- 372,423)
test bench_agile_sha512_large  ... bench:  45,220,041 ns/iter (+/- 3,078,352)
test bench_standard            ... bench:   3,080,678 ns/iter (+/- 95,020)
test bench_doc97_rc4_cryptoapi ... bench:      42,690 ns/iter (+/- 1,393)
```

File sizes for tests:
- `bench_agile_sha512` => 25 KB
- `bench_agile_sha512_large` => 7.1 MB
- `bench_standard` => 7 KB
- `bench_doc97_rc4_cryptoapi` => 23 KB

Note that the latest version of Word will create an Agile encrypted document.

## Acknowledgements

This crate is essentially a port of the OOXML-specific features from [msoffcrypto](https://github.com/nolze/msoffcrypto-tool) and [olefile](https://github.com/decalage2/olefile).

