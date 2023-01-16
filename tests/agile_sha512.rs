use office_crypto::decrypt_from_file;
use std::fs::File;
use std::io::*;
use std::path::PathBuf;

#[test]
fn agile_sha512() {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests/testAgileSha512.docx");
    let decrypted = decrypt_from_file(dir.to_str().unwrap(), "testPassword").unwrap();

    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests/expectedAgileSha512.txt");
    let mut expected_file = File::open(dir).unwrap();
    let mut expected: Vec<u8> = Vec::new();
    expected_file.read_to_end(&mut expected).unwrap();
    // std::fs::write(dir, &decrypted).unwrap();

    assert!(decrypted == expected);
}
