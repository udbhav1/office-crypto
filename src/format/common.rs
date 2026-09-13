//! Structures shared by the Office binary formats (Word, Excel, PowerPoint 97-2004).

use crate::validate;
use crate::DecryptError::{self, *};

/// Default key size, in bits, when the header leaves it at zero.
const DEFAULT_KEY_SIZE: u32 = 0x28;

#[derive(Debug)]
pub struct RC4CryptoAPIHeader {
    pub salt: Vec<u8>,
    pub key_size: u32,
    pub encrypted_verifier: Vec<u8>,
    pub encrypted_verifier_hash: Vec<u8>,
}

/// Parse an RC4 CryptoAPI EncryptionHeader followed by its EncryptionVerifier.
///
/// `data` starts at the EncryptionVersionInfo, which the caller has already read to decide that
/// this is RC4 CryptoAPI rather than one of the other schemes.
///
/// <https://msdn.microsoft.com/en-us/library/dd926359(v=office.12).aspx>
pub fn parse_rc4_cryptoapi_header(data: &[u8]) -> Result<RC4CryptoAPIHeader, DecryptError> {
    // EncryptionVersionInfo (4 bytes, already read by the caller), Flags (4), HeaderSize (4).
    validate!(data.len() >= 12, InvalidStructure)?;

    let header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    validate!(data.len() >= 12 + header_size, InvalidStructure)?;

    let header_data = &data[12..(12 + header_size)];
    validate!(header_data.len() >= 32, InvalidStructure)?;

    let key_size = u32::from_le_bytes([
        header_data[16],
        header_data[17],
        header_data[18],
        header_data[19],
    ]);
    let key_size = if key_size == 0 {
        DEFAULT_KEY_SIZE
    } else {
        key_size
    };

    let verifier_offset = 12 + header_size;
    validate!(data.len() >= verifier_offset + 60, InvalidStructure)?;
    let verifier_data = &data[verifier_offset..];

    Ok(RC4CryptoAPIHeader {
        salt: verifier_data[4..20].to_vec(),
        key_size,
        encrypted_verifier: verifier_data[20..36].to_vec(),
        encrypted_verifier_hash: verifier_data[40..60].to_vec(),
    })
}
