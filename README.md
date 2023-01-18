office-crypto
=============
[![crates.io](https://img.shields.io/crates/v/office-crypto)](https://crates.io/crates/office-crypto)
[![docs](https://img.shields.io/docsrs/office-crypto)](https://docs.rs/office-crypto)

Pure Rust library to decrypt password-protected MS Office files

https://docs.rs/office-crypto

## Example

This crate exposes two functions: `decrypt_from_file` and `decrypt_from_bytes`, which do exactly what they say they do. The resulting bytes can then be interpreted by any MS Office parser like [docx](https://crates.io/crates/docx) or [calamine](https://crates.io/crates/calamine).

```rust
use docx::DocxFile;
use office_crypto::decrypt_from_file;
use std::io::Cursor;

let decrypted: Vec<u8> = decrypt_from_file("protected.docx", "Password1234_").unwrap();

let docx = DocxFile::from_reader(Cursor::new(decrypted)).unwrap();
let docx = docx.parse().unwrap();

// Now we can access the docx content
```

## Formats

* [x] ECMA-376 (Agile Encryption/Standard Encryption)
    * [x] MS-DOCX (OOXML) (Word 2007-Present)
    * [x] MS-XLSX (OOXML) (Excel 2007-Present)
    * [x] MS-PPTX (OOXML) (PowerPoint 2007-Present)
* [ ] Office Binary Document RC4 CryptoAPI
    * [ ] MS-DOC (Word 2002, 2003, 2004)
    * [ ] MS-XLS (Excel 2002, 2003, 2004)
    * [ ] MS-PPT (PowerPoint 2002, 2003, 2004)
* [ ] ECMA-376 (Extensible Encryption)

Non-SHA512 hash functions are not yet implemented. This only affects Agile encrypted files, but I have yet to find one that doesn't use SHA512.

## Performance

Measured on an M1 Pro:
```
running 3 tests
test bench_agile_sha512       ... bench:  27,106,487 ns/iter (+/- 505,175)
test bench_agile_sha512_large ... bench:  71,372,716 ns/iter (+/- 3,915,458)
test bench_standard           ... bench:   6,379,766 ns/iter (+/- 100,688)
```

File sizes for tests:
- `bench_agile_sha512` => 25 KB
- `bench_agile_sha512_large` => 7.1 MB
- `bench_standard` => 7 KB

Note that the latest version of Word will create an Agile encrypted document.

## Acknowledgements

This crate is essentially a port of the OOXML-specific features from [msoffcrypto](https://github.com/nolze/msoffcrypto-tool) and [olefile](https://github.com/decalage2/olefile). 