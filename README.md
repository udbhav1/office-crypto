office-crypto
=============
[![crates.io](https://img.shields.io/crates/v/office-crypto)](https://crates.io/crates/office-crypto)
[![docs](https://img.shields.io/docsrs/office-crypto)](https://docs.rs/office-crypto)

Pure Rust library to decrypt password-protected MS Office files.

https://docs.rs/office-crypto

## Example

This crate exposes two functions: `decrypt_from_file` and `decrypt_from_bytes`, which do exactly what they say they do. The resulting bytes can then be interpreted by any MS Office parser like [docx](https://crates.io/crates/docx) or [calamine](https://crates.io/crates/calamine).

```rust
use docx_rs::read_docx;
use office_crypto::decrypt_from_file;

// This example code is just for illustration.
// In a real application, handle errors properly.
let path = "protected.docx";
if let Ok(decrypted) = decrypt_from_file(path, "Password1234_") {
    let _docx = read_docx(&decrypted).unwrap();
    // Now we can access the docx content
}
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

Measured on an Intel Core i7-7800X (Linux x86_64):
```
running 4 tests
test bench_agile_sha512        ... bench:  42,440,027 ns/iter (+/- 2,788,737)
test bench_agile_sha512_large  ... bench:  55,902,807 ns/iter (+/- 151,747)
test bench_doc97_rc4_cryptoapi ... bench:     155,237 ns/iter (+/- 10,914)
test bench_standard            ... bench:  10,537,347 ns/iter (+/- 13,077)
```

File sizes for tests:
- `bench_agile_sha512` => 25 KB
- `bench_agile_sha512_large` => 7.1 MB
- `bench_standard` => 7 KB
- `bench_doc97_rc4_cryptoapi` => 23 KB

Note that the latest version of Word will create an Agile encrypted document.

## Acknowledgements

This crate is essentially a port of the OOXML-specific features from [msoffcrypto](https://github.com/nolze/msoffcrypto-tool) and [olefile](https://github.com/decalage2/olefile). 