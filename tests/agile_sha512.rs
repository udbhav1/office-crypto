use office_crypto::*;

mod utils;

#[test]
fn agile_sha512() {
    let dec_docx = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512.docx"),
        "testPassword",
    )
    .unwrap();
    let expected_docx = utils::read_test_file("expectedAgileSha512.docx");
    // std::fs::write("tests/files/expectedAgileSha512.docx", &dec_docx).unwrap();

    let dec_xlsx = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512.xlsx"),
        "testPassword",
    )
    .unwrap();
    let expected_xlsx = utils::read_test_file("expectedAgileSha512.xlsx");
    // std::fs::write("tests/files/expectedAgileSha512.xlsx", &dec_xlsx).unwrap();

    assert!(dec_docx == expected_docx);
    assert!(dec_xlsx == expected_xlsx);
}

#[test]
fn agile_sha512_large() {
    let decrypted = decrypt_from_bytes(
        utils::read_test_file("testAgileSha512Large.docx"),
        "testPassword",
    )
    .unwrap();
    let expected = utils::read_test_file("expectedAgileSha512Large.docx");
    // std::fs::write("tests/files/expectedAgileSha512Large.docx", &decrypted).unwrap();

    assert!(decrypted == expected);
}
