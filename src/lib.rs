//! Pure Rust library to decrypt password-protected MS Office files.
//!
//! ## Example
//!
//! This crate exposes two functions: [`decrypt_from_file`] and [`decrypt_from_bytes`], which do exactly what they say they do. The resulting bytes can then be interpreted by any MS Office parser like [docx](https://crates.io/crates/docx) or [calamine](https://crates.io/crates/calamine).
//!
//! ```ignore
//! # extern crate docx;
//! use docx::DocxFile;
//! use office_crypto::decrypt_from_file;
//! use std::io::Cursor;
//!
//! let path = "protected.docx";
//! let decrypted: Vec<u8> = decrypt_from_file(path, "Password1234_").unwrap();
//!
//! let docx = DocxFile::from_reader(Cursor::new(decrypted)).unwrap();
//! let docx = docx.parse().unwrap();
//!
//! // Now we can access the docx content
//! ```
//!
//! ## Formats
//!
//! * [x] ECMA-376 (Agile Encryption/Standard Encryption)
//!     * [x] MS-DOCX (OOXML) (Word 2007-Present)
//!     * [x] MS-XLSX (OOXML) (Excel 2007-Present)
//!     * [x] MS-PPTX (OOXML) (PowerPoint 2007-Present)
//! * [~] Office Binary Document RC4 CryptoAPI
//!     * [x] MS-DOC (Word 2002, 2003, 2004)
//!     * [ ] MS-XLS (Excel 2002, 2003, 2004)
//!     * [ ] MS-PPT (PowerPoint 2002, 2003, 2004)
//! * [ ] ECMA-376 (Extensible Encryption)
//!
//! Agile encrypted files that use non-SHA512 hash functions will yield [`DecryptError::Unimplemented`], though I haven't yet encountered such a file.
//!
//! Note that the latest version of Word will create an Agile encrypted document.

mod crypto;
mod format;
mod method;
mod ole;

use crypto::{AgileEncryptionInfo, StandardEncryptionInfo};
use format::doc97;
use ole::OleFile;
use std::path::Path;
use thiserror::Error;

macro_rules! validate {
    ($assert:expr, $err:expr) => {{
        if ($assert) {
            Ok(())
        } else {
            let error_code: DecryptError = $err;
            Err(error_code)
        }
    }};
}

pub(crate) use validate;

/// Open and decrypt an MS Office file, returning the decrypted bytes.
///
/// Returns [`DecryptError`] if any part of the file is malformed.
pub fn decrypt_from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Vec<u8>, DecryptError> {
    let mut olefile = OleFile::from_file(path)?;
    olefile.init()?;

    decrypt(&mut olefile, password)
}

/// Decrypt bytes as an MS Office file, returning the decrypted bytes.
///
/// Returns [`DecryptError`] if any part of the file is malformed.
pub fn decrypt_from_bytes(raw: Vec<u8>, password: &str) -> Result<Vec<u8>, DecryptError> {
    let mut olefile = OleFile::new(raw)?;
    olefile.init()?;

    decrypt(&mut olefile, password)
}

fn decrypt(olefile: &mut OleFile, password: &str) -> Result<Vec<u8>, DecryptError> {
    // Detect format. OOXML has EncryptionInfo stream, binary formats don't
    if olefile.exists(&["EncryptionInfo".to_owned()])? {
        decrypt_ooxml(olefile, password)
    } else if olefile.exists(&["WordDocument".to_owned()])? {
        doc97::decrypt_doc97(olefile, password)
    } else if olefile.exists(&["Workbook".to_owned()])? {
        Err(DecryptError::Unimplemented("Excel binary format (.xls) not yet supported".to_owned()))
    } else if olefile.exists(&["Current User".to_owned()])? {
        Err(DecryptError::Unimplemented("PowerPoint binary format (.ppt) not yet supported".to_owned()))
    } else {
        Err(DecryptError::InvalidStructure)
    }
}

fn decrypt_ooxml(olefile: &mut OleFile, password: &str) -> Result<Vec<u8>, DecryptError> {
    let encryption_info_stream = olefile.open_stream(&["EncryptionInfo".to_owned()])?;
    let encrypted_package_stream = olefile.open_stream(&["EncryptedPackage".to_owned()])?;

    match encryption_info_stream.stream.get(..4) {
        Some([4, 0, 4, 0]) => {
            let aei = AgileEncryptionInfo::new(&encryption_info_stream)?;
            let secret_key = aei.key_from_password(password)?;

            aei.decrypt(&secret_key, &encrypted_package_stream)
        }
        Some([2 | 3 | 4, 0, 2, 0]) => {
            let sei = StandardEncryptionInfo::new(&encryption_info_stream)?;
            let secret_key = sei.key_from_password(password)?;

            sei.decrypt(&secret_key, &encrypted_package_stream)
        }
        _ => Err(DecryptError::InvalidStructure),
    }
}

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("IO Error")]
    IoError(std::io::Error),
    #[error("Invalid Olefile Header")]
    InvalidHeader,
    #[error("Invalid File Structure")]
    InvalidStructure,
    #[error("Unimplemented: `{0}`")]
    Unimplemented(String),
    #[error("Unknown Error")]
    Unknown,
}
