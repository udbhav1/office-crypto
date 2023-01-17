mod crypto;
mod ole;

use crypto::{AgileEncryptionInfo, StandardEncryptionInfo};
use ole::OleFile;
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

pub fn decrypt_from_file(path: &str, password: &str) -> Result<Vec<u8>, DecryptError> {
    let mut olefile = OleFile::from_file(path)?;
    olefile.init()?;

    decrypt(&mut olefile, password)
}

// takes ownership of raw
pub fn decrypt_from_bytes(raw: Vec<u8>, password: &str) -> Result<Vec<u8>, DecryptError> {
    let mut olefile = OleFile::new(raw)?;
    olefile.init()?;

    decrypt(&mut olefile, password)
}

fn decrypt(olefile: &mut OleFile, password: &str) -> Result<Vec<u8>, DecryptError> {
    let encryption_info_stream = olefile.open_stream(&["EncryptionInfo".to_owned()])?;
    let encrypted_package_stream = olefile.open_stream(&["EncryptedPackage".to_owned()])?;

    match encryption_info_stream.stream[..4] {
        [4, 0, 4, 0] => {
            let aei = AgileEncryptionInfo::new(&encryption_info_stream)?;
            let secret_key = aei.key_from_password(password)?;

            aei.decrypt(&secret_key, &encrypted_package_stream)
        }
        [2, 0, 2, 0] | [3, 0, 2, 0] | [4, 0, 2, 0] => {
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
