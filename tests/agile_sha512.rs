use office_crypto::*;

mod utils;

#[test]
fn agile_sha512() {
    let decrypted = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512.docx"),
        "testPassword",
    )
    .unwrap();
    let expected = utils::read_test_file("expectedAgileSha512.txt");
    // std::fs::write("tests/files/expectedAgileSha512.txt", &decrypted).unwrap();

    assert!(decrypted == expected);
}

#[test]
fn agile_sha512_large() {
    let decrypted = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512Large.docx"),
        "testPassword",
    )
    .unwrap();
    let expected = utils::read_test_file("expectedAgileSha512Large.txt");
    // std::fs::write("tests/files/expectedAgileSha512Large.txt", &decrypted).unwrap();

    assert!(decrypted == expected);
}
