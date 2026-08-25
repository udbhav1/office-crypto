use office_crypto::decrypt_from_bytes;

mod utils;

#[test]
fn truncated_ooxml_containers_return_errors_instead_of_panicking() {
    for fixture in ["testAgileSha512.docx", "testStandard.docx"] {
        let bytes = utils::read_test_file(fixture);

        // Cover every structural region without turning this regression test into a slow fuzzer.
        for len in (0..bytes.len()).step_by(127) {
            let truncated = bytes[..len].to_vec();
            let result = std::panic::catch_unwind(|| decrypt_from_bytes(truncated, "testPassword"));
            assert!(result.is_ok(), "{fixture} panicked when truncated to {len} bytes");
            assert!(result.unwrap().is_err());
        }
    }
}
