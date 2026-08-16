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

#[test]
fn standard_sha512() {
    // from msofficecrypto tests
    let decrypted =
        decrypt_from_bytes(utils::read_test_file("testStandard.docx"), "Password1234_").unwrap();
    let expected = utils::read_test_file("expectedStandard.docx");
    // std::fs::write("tests/files/expectedStandard.docx", &decrypted).unwrap();

    assert!(decrypted == expected);
}

#[test]
fn rc4_cryptoapi_doc() {
    // from msoffcrypto-tool tests
    let decrypted =
        decrypt_from_bytes(utils::read_test_file("testRC4CryptoAPI.doc"), "Password1234_")
            .unwrap();
    let expected = utils::read_test_file("expectedRC4CryptoAPI.doc");

    assert_eq!(decrypted, expected);
}

#[test]
fn oversized_declared_size_is_rejected_not_panicking() {
    // craftedOversizedSize.docx reuses a genuine agile EncryptionInfo but its
    // EncryptedPackage is 16 bytes whose header declares a ~4 GiB plaintext.
    // Before the size check this triggered a ~4 GiB allocation request and an
    // out-of-range panic; it must now return a clean error instead.
    let result = decrypt_from_bytes(
        utils::read_test_file("craftedOversizedSize.docx"),
        "anyPassword",
    );

    assert!(matches!(result, Err(DecryptError::InvalidStructure)));
}

#[test]
fn doc97_not_encrypted() {
    // expectedRC4CryptoAPI.doc is an unencrypted doc file
    let result =
        decrypt_from_bytes(utils::read_test_file("expectedRC4CryptoAPI.doc"), "anypassword");

    assert!(matches!(result, Err(DecryptError::NotEncrypted)));
}
