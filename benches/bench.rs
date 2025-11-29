#[macro_use]
extern crate bencher;

use bencher::{black_box, Bencher};
use office_crypto::decrypt_from_bytes;
use std::fs::File;
use std::io::*;
use std::path::PathBuf;

pub fn read_test_file(name: &str) -> Vec<u8> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests");
    dir.push("files");
    dir.push(name);
    let mut f = File::open(dir).unwrap();
    let mut data: Vec<u8> = Vec::new();
    f.read_to_end(&mut data).unwrap();

    data
}

fn bench_agile_sha512(b: &mut Bencher) {
    b.iter(|| {
        let data = read_test_file("testAgileSha512.docx");
        black_box(decrypt_from_bytes(data, "testPassword").unwrap());
    });
}

fn bench_agile_sha512_large(b: &mut Bencher) {
    b.iter(|| {
        let data = read_test_file("testAgileSha512Large.docx");
        black_box(decrypt_from_bytes(data, "testPassword").unwrap());
    });
}

fn bench_standard(b: &mut Bencher) {
    b.iter(|| {
        let data = read_test_file("testStandard.docx");
        black_box(decrypt_from_bytes(data, "Password1234_").unwrap());
    });
}

fn bench_doc97_rc4_cryptoapi(b: &mut Bencher) {
    b.iter(|| {
        // Encrypted legacy DOC (RC4 CryptoAPI)
        let data = read_test_file("testRC4CryptoAPI.doc");
        black_box(decrypt_from_bytes(data, "Password1234_").unwrap());
    });
}

benchmark_group!(
    benches,
    bench_agile_sha512,
    bench_agile_sha512_large,
    bench_standard,
    bench_doc97_rc4_cryptoapi
);
benchmark_main!(benches);
