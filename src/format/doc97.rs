//! MS-DOC (Word 97-2004) binary format decryption
//! Based on msoffcrypto-tool's doc97.py implementation.
//! https://msdn.microsoft.com/en-us/library/dd944620(v=office.12).aspx

use crate::method::rc4::{DocumentRC4, DocumentRC4CryptoAPI};
use crate::ole::OleFile;
use crate::validate;
use crate::DecryptError::{self, *};
use std::io::Read;

const FIB_BASE_LENGTH: usize = 32;
const FIB_LENGTH: usize = 0x44; // 68 bytes

/// File Information Block Base structure for Word documents
/// https://msdn.microsoft.com/en-us/library/dd944620(v=office.12).aspx
#[derive(Debug, Clone)]
pub struct FibBase {
    pub w_ident: u16,
    pub n_fib: u16,
    pub unused: u16,
    pub lid: u16,
    pub pn_next: u16,
    pub flags: u16,
    pub n_fib_back: u16,
    pub i_key: u32,
    pub envr: u8,
    pub flags2: u8,
    pub reserved3: u16,
    pub reserved4: u16,
    pub reserved5: u32,
    pub reserved6: u32,
}

impl FibBase {
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecryptError> {
        validate!(data.len() >= FIB_BASE_LENGTH, InvalidStructure)?;

        let w_ident = u16::from_le_bytes([data[0], data[1]]);
        let n_fib = u16::from_le_bytes([data[2], data[3]]);
        let unused = u16::from_le_bytes([data[4], data[5]]);
        let lid = u16::from_le_bytes([data[6], data[7]]);
        let pn_next = u16::from_le_bytes([data[8], data[9]]);
        let flags = u16::from_le_bytes([data[10], data[11]]);
        let n_fib_back = u16::from_le_bytes([data[12], data[13]]);
        let i_key = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
        let envr = data[18];
        let flags2 = data[19];
        let reserved3 = u16::from_le_bytes([data[20], data[21]]);
        let reserved4 = u16::from_le_bytes([data[22], data[23]]);
        let reserved5 = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let reserved6 = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Ok(FibBase {
            w_ident,
            n_fib,
            unused,
            lid,
            pn_next,
            flags,
            n_fib_back,
            i_key,
            envr,
            flags2,
            reserved3,
            reserved4,
            reserved5,
            reserved6,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        (self.flags & (1 << 8)) != 0
    }
    pub fn is_obfuscated(&self) -> bool {
        (self.flags & (1 << 15)) != 0
    }

    pub fn table_stream_name(&self) -> &str {
        if (self.flags & (1 << 9)) != 0 {
            "1Table"
        } else {
            "0Table"
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIB_BASE_LENGTH);
        bytes.extend_from_slice(&self.w_ident.to_le_bytes());
        bytes.extend_from_slice(&self.n_fib.to_le_bytes());
        bytes.extend_from_slice(&self.unused.to_le_bytes());
        bytes.extend_from_slice(&self.lid.to_le_bytes());
        bytes.extend_from_slice(&self.pn_next.to_le_bytes());
        bytes.extend_from_slice(&self.flags.to_le_bytes());
        bytes.extend_from_slice(&self.n_fib_back.to_le_bytes());
        bytes.extend_from_slice(&self.i_key.to_le_bytes());
        bytes.push(self.envr);
        bytes.push(self.flags2);
        bytes.extend_from_slice(&self.reserved3.to_le_bytes());
        bytes.extend_from_slice(&self.reserved4.to_le_bytes());
        bytes.extend_from_slice(&self.reserved5.to_le_bytes());
        bytes.extend_from_slice(&self.reserved6.to_le_bytes());
        bytes
    }

    /// Decrypted version of FibBase (fEncrypted=0, fObfuscation=0, IKey=0)
    pub fn decrypted_copy(&self) -> Self {
        let mut copy = self.clone();
        copy.flags &= !(1 << 8); // Clear fEncrypted
        copy.flags &= !(1 << 15); // Clear fObfuscation
        copy.i_key = 0;
        copy
    }
}

#[derive(Debug)]
struct RC4Header {
    salt: Vec<u8>,
    encrypted_verifier: Vec<u8>,
    encrypted_verifier_hash: Vec<u8>,
}

#[derive(Debug)]
struct RC4CryptoAPIHeader {
    salt: Vec<u8>,
    key_size: u32,
    encrypted_verifier: Vec<u8>,
    encrypted_verifier_hash: Vec<u8>,
}

/// https://msdn.microsoft.com/en-us/library/dd908560(v=office.12).aspx
fn parse_rc4_header(data: &[u8]) -> Result<RC4Header, DecryptError> {
    validate!(data.len() >= 48, InvalidStructure)?;

    Ok(RC4Header {
        salt: data[0..16].to_vec(),
        encrypted_verifier: data[16..32].to_vec(),
        encrypted_verifier_hash: data[32..48].to_vec(),
    })
}

/// https://msdn.microsoft.com/en-us/library/dd926359(v=office.12).aspx
fn parse_rc4_cryptoapi_header(data: &[u8]) -> Result<RC4CryptoAPIHeader, DecryptError> {

    // EncryptionVersionInfo (first 4 bytes) - already parsed
    // Then read Flags (4 bytes) and HeaderSize (4 bytes)
    validate!(data.len() >= 12, InvalidStructure)?;

    let _flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

    // Header structure offset by 4 (version already parsed) + 8 (flags + headerSize) = 12
    if data.len() < 12 + header_size {
        return Err(InvalidStructure);
    }

    let header_data = &data[12..(12 + header_size)];
    if header_data.len() < 32 {
        return Err(InvalidStructure);
    }

    // Parse EncryptionHeader structure
    let _alg_id = u32::from_le_bytes([
        header_data[8],
        header_data[9],
        header_data[10],
        header_data[11],
    ]);
    let _alg_id_hash = u32::from_le_bytes([
        header_data[12],
        header_data[13],
        header_data[14],
        header_data[15],
    ]);
    let key_size = u32::from_le_bytes([
        header_data[16],
        header_data[17],
        header_data[18],
        header_data[19],
    ]);

    // Default key size if 0
    let key_size = if key_size == 0 { 0x28 } else { key_size };

    // Parse EncryptionVerifier structure
    let verifier_offset = 12 + header_size;
    validate!(data.len() >= verifier_offset + 36, InvalidStructure)?;

    let verifier_data = &data[verifier_offset..];
    let _salt_size = u32::from_le_bytes([
        verifier_data[0],
        verifier_data[1],
        verifier_data[2],
        verifier_data[3],
    ]);
    let salt = verifier_data[4..20].to_vec();
    let encrypted_verifier = verifier_data[20..36].to_vec();
    let _verifier_hash_size = u32::from_le_bytes([
        verifier_data[36],
        verifier_data[37],
        verifier_data[38],
        verifier_data[39],
    ]);
    let encrypted_verifier_hash = verifier_data[40..60].to_vec();

    Ok(RC4CryptoAPIHeader {
        salt,
        key_size,
        encrypted_verifier,
        encrypted_verifier_hash,
    })
}

/// Word 97-2004 (.doc)
pub fn decrypt_doc97(olefile: &mut OleFile, password: &str) -> Result<Vec<u8>, DecryptError> {
    // Read WordDocument stream to get FIB
    let word_document_stream = olefile.open_stream(&["WordDocument".to_owned()])?;
    let mut fib_data = vec![0u8; FIB_LENGTH];
    word_document_stream
        .stream
        .as_slice()
        .read_exact(&mut fib_data)
        .map_err(|_e| {
            InvalidStructure
        })?;

    let fib_base = FibBase::from_bytes(&fib_data)?;

    if !fib_base.is_encrypted() {
        return Err(NotEncrypted);
    }

    // Table stream name
    let table_name = fib_base.table_stream_name();
    let encryption_header_size = fib_base.i_key as usize;

    // Encryption based on type
    let (encryption_type, _key, salt, key_size) = if fib_base.is_obfuscated() {
        return Err(Unimplemented("XOR obfuscation".to_owned()));
    } else {
        // Encryption info from table stream
        let table_stream = olefile.open_stream(&[table_name.to_owned()])?;

        let mut version_info = [0u8; 4];
        table_stream
            .stream
            .as_slice()
            .read_exact(&mut version_info)
            .map_err(|_e| {
                InvalidStructure
            })?;

        let v_major = u16::from_le_bytes([version_info[0], version_info[1]]);
        let v_minor = u16::from_le_bytes([version_info[2], version_info[3]]);

        if v_major == 0x0001 && v_minor == 0x0001 {
            // RC4
            let mut header_data = vec![0u8; 48];
            table_stream
                .stream
                .as_slice()
                .read_exact(&mut header_data)
                .map_err(|_| InvalidStructure)?;

            let header = parse_rc4_header(&header_data)?;

            validate!(
                DocumentRC4::verify_password(
                    password,
                    &header.salt,
                    &header.encrypted_verifier,
                    &header.encrypted_verifier_hash
                ),
                InvalidStructure
            )?;

            ("rc4", password.to_owned(), header.salt, 0)
        } else if (v_major == 0x0002 || v_major == 0x0003 || v_major == 0x0004) && v_minor == 0x0002
        {
            // RC4 CryptoAPI
            // Re-open the table stream to read from the beginning
            let table_stream = olefile.open_stream(&[table_name.to_owned()])?;
            let mut header_data = vec![0u8; encryption_header_size];
            table_stream
                .stream
                .as_slice()
                .read_exact(&mut header_data)
                .map_err(|_e| {
                    InvalidStructure
                })?;

            let header = parse_rc4_cryptoapi_header(&header_data)?;

            let password_valid = DocumentRC4CryptoAPI::verify_password(
                password,
                &header.salt,
                header.key_size,
                &header.encrypted_verifier,
                &header.encrypted_verifier_hash
            );

            validate!(password_valid, InvalidStructure)?;

            ("rc4_cryptoapi", password.to_owned(), header.salt, header.key_size)
        } else {
            return Err(Unimplemented(format!(
                "Encryption version {}.{}",
                v_major, v_minor
            )));
        }
    };

    // Decrypt WordDocument stream
    // NOTE: Decrypt entire stream including FIB for correct block alignment,
    // but only use the part after FIB_LENGTH
    let word_document_stream = olefile.open_stream(&["WordDocument".to_owned()])?;

    let decrypted_word_stream_full = if encryption_type == "rc4" {
        DocumentRC4::decrypt(password, &salt, &word_document_stream.stream, 0x200)
    } else {
        DocumentRC4CryptoAPI::decrypt(password, &salt, key_size, &word_document_stream.stream, 0x200)
    };

    let decrypted_word_data = decrypted_word_stream_full[FIB_LENGTH..].to_vec();

    // Decrypt table stream (decrypt ENTIRE stream including header)
    let table_stream = olefile.open_stream(&[table_name.to_owned()])?;

    let decrypted_table_data = if encryption_type == "rc4" {
        DocumentRC4::decrypt(password, &salt, &table_stream.stream, 0x200)
    } else {
        DocumentRC4CryptoAPI::decrypt(password, &salt, key_size, &table_stream.stream, 0x200)
    };

    // Decrypt Data stream if it exists
    let decrypted_data_stream = if olefile.exists(&["Data".to_owned()])? {
        let data_stream = olefile.open_stream(&["Data".to_owned()])?;
        Some(if encryption_type == "rc4" {
            DocumentRC4::decrypt(password, &salt, &data_stream.stream, 0x200)
        } else {
            DocumentRC4CryptoAPI::decrypt(password, &salt, key_size, &data_stream.stream, 0x200)
        })
    } else {
        None
    };

    // Build decrypted FIB
    let decrypted_fib = fib_base.decrypted_copy();
    let mut decrypted_fib_bytes = decrypted_fib.to_bytes();
    decrypted_fib_bytes.extend_from_slice(&fib_data[FIB_BASE_LENGTH..FIB_LENGTH]);

    // Reconstruct decrypted WordDocument stream
    let mut new_word_document = Vec::with_capacity(FIB_LENGTH + decrypted_word_data.len());
    new_word_document.extend_from_slice(&decrypted_fib_bytes);
    new_word_document.extend_from_slice(&decrypted_word_data);

    // Write streams back to OLE file
    olefile.write_stream(&["WordDocument".to_owned()], &new_word_document)?;
    olefile.write_stream(&[table_name.to_owned()], &decrypted_table_data)?;
    if let Some(data) = decrypted_data_stream {
        olefile.write_stream(&["Data".to_owned()], &data)?;
    }

    // Return the modified OLE file as bytes
    olefile.to_bytes()
}
