//! RC4 encryption methods for Office Binary formats (Office 97-2004)
//! Based on msoffcrypto-tool's RC4 and RC4CryptoAPI implementations.

use md5::{Digest, Md5};
use rc4::{
    consts::{U10, U11, U12, U13, U14, U15, U16, U5, U6, U7, U8, U9},
    KeyInit, Rc4, StreamCipher,
};
use sha1::Sha1;

/// Apply an RC4 keystream to `data`, with a key of whatever length the file asked for.
///
/// An RC4 CryptoAPI file names its key size in bits, anywhere from 40 to 128 in steps of 8,
/// and the cipher takes the key at exactly that length. The cipher carries its key length in
/// its type, so the length has to be matched into a type here. A length outside that range is
/// padded to 128 bits, which is what a 40-bit key is given for the same reason.
fn apply_rc4(key: &[u8], data: &mut [u8]) {
    macro_rules! by_key_length {
        ($($len:literal => $size:ty),+ $(,)?) => {
            match key.len() {
                $($len => Rc4::<$size>::new(key.into()).apply_keystream(data),)+
                _ => {
                    let mut padded = [0u8; 16];
                    let taken = key.len().min(16);
                    padded[..taken].copy_from_slice(&key[..taken]);
                    Rc4::<U16>::new(padded.as_slice().into()).apply_keystream(data);
                }
            }
        };
    }

    by_key_length!(
        5 => U5, 6 => U6, 7 => U7, 8 => U8, 9 => U9, 10 => U10,
        11 => U11, 12 => U12, 13 => U13, 14 => U14, 15 => U15, 16 => U16,
    );
}

/// Intermediate key for RC4 encryption
/// https://msdn.microsoft.com/en-us/library/dd920360(v=office.12).aspx
fn makekey_rc4(password: &str, salt: &[u8], block: u32) -> Vec<u8> {
    let password_utf16: Vec<u16> = password.encode_utf16().collect();
    let password_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            password_utf16.as_ptr() as *const u8,
            password_utf16.len() * 2,
        )
    };

    let h0 = Md5::digest(password_bytes);
    let truncated_hash = &h0[..5];

    let mut intermediate_buffer = Vec::with_capacity(16 * (truncated_hash.len() + salt.len()));
    for _ in 0..16 {
        intermediate_buffer.extend_from_slice(truncated_hash);
        intermediate_buffer.extend_from_slice(salt);
    }

    let h1 = Md5::digest(&intermediate_buffer);
    let truncated_hash = &h1[..5];

    let block_bytes = block.to_le_bytes();
    let mut final_input = Vec::with_capacity(truncated_hash.len() + block_bytes.len());
    final_input.extend_from_slice(truncated_hash);
    final_input.extend_from_slice(&block_bytes);

    let hfinal = Md5::digest(&final_input);
    hfinal[..16].to_vec() // 128 bits / 8 = 16 bytes
}

/// Intermediate key for RC4 CryptoAPI encryption (Office 2002-2004)
/// https://msdn.microsoft.com/en-us/library/dd920677(v=office.12).aspx
fn makekey_rc4_cryptoapi(password: &str, salt: &[u8], key_length: u32, block: u32) -> Vec<u8> {
    let password_utf16: Vec<u16> = password.encode_utf16().collect();
    let password_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            password_utf16.as_ptr() as *const u8,
            password_utf16.len() * 2,
        )
    };

    let mut h0_input = Vec::with_capacity(salt.len() + password_bytes.len());
    h0_input.extend_from_slice(salt);
    h0_input.extend_from_slice(password_bytes);
    let h0 = Sha1::digest(&h0_input);

    let block_bytes = block.to_le_bytes();
    let mut hfinal_input = Vec::with_capacity(h0.len() + block_bytes.len());
    hfinal_input.extend_from_slice(&h0);
    hfinal_input.extend_from_slice(&block_bytes);
    let hfinal = Sha1::digest(&hfinal_input);

    if key_length == 40 {
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&hfinal[..5]);
        key.extend_from_slice(&[0u8; 11]);
        key
    } else {
        hfinal[..(key_length as usize / 8)].to_vec()
    }
}

/// RC4 document encryption (Office 97-2000)
pub struct DocumentRC4;

impl DocumentRC4 {
    /// Verify password
    /// https://msdn.microsoft.com/en-us/library/dd952648(v=office.12).aspx
    pub fn verify_password(
        password: &str,
        salt: &[u8],
        encrypted_verifier: &[u8],
        encrypted_verifier_hash: &[u8],
    ) -> bool {
        let block = 0;
        let key = makekey_rc4(password, salt, block);

        // Same cipher for both verifier and hash
        // The state must not restart
        // One cipher for both: the keystream must not restart between them.
        let mut both = encrypted_verifier.to_vec();
        both.extend_from_slice(encrypted_verifier_hash);
        apply_rc4(&key, &mut both);
        let (verifier, verifier_hash) = both.split_at(encrypted_verifier.len());

        let hash = Md5::digest(verifier);
        hash.as_slice() == verifier_hash
    }

    pub fn decrypt(
        password: &str,
        salt: &[u8],
        encrypted_data: &[u8],
        blocksize: usize,
    ) -> Vec<u8> {
        let mut decrypted = Vec::with_capacity(encrypted_data.len());
        let mut block = 0u32;

        for chunk in encrypted_data.chunks(blocksize) {
            let key = makekey_rc4(password, salt, block);
            let mut dec_chunk = chunk.to_vec();
            apply_rc4(&key, &mut dec_chunk);
            decrypted.extend_from_slice(&dec_chunk);
            block += 1;
        }

        decrypted
    }
}

/// RC4 CryptoAPI document encryption (Office 2002-2004)
pub struct DocumentRC4CryptoAPI;

impl DocumentRC4CryptoAPI {
    /// https://msdn.microsoft.com/en-us/library/dd953617(v=office.12).aspx
    pub fn verify_password(
        password: &str,
        salt: &[u8],
        key_size: u32,
        encrypted_verifier: &[u8],
        encrypted_verifier_hash: &[u8],
    ) -> bool {
        let block = 0;
        let key = makekey_rc4_cryptoapi(password, salt, key_size, block);

        // One cipher for both: the keystream must not restart between them.
        let mut both = encrypted_verifier.to_vec();
        both.extend_from_slice(encrypted_verifier_hash);
        apply_rc4(&key, &mut both);
        let (verifier, verifier_hash) = both.split_at(encrypted_verifier.len());

        let hash = Sha1::digest(verifier);
        hash.as_slice() == verifier_hash
    }

    /// Decrypt one block, keyed by an explicit block number rather than by position.
    ///
    /// Word numbers the blocks of a stream from zero and rekeys every `blocksize` bytes.
    /// PowerPoint encrypts each persist object on its own, keyed by the object's persist
    /// identifier, so the block number comes from the caller and the data is one block
    /// however long it is.
    pub fn decrypt_block(
        password: &str,
        salt: &[u8],
        key_size: u32,
        encrypted_data: &[u8],
        block: u32,
    ) -> Vec<u8> {
        let key = makekey_rc4_cryptoapi(password, salt, key_size, block);
        let mut decrypted = encrypted_data.to_vec();
        apply_rc4(&key, &mut decrypted);
        decrypted
    }

    pub fn decrypt(
        password: &str,
        salt: &[u8],
        key_size: u32,
        encrypted_data: &[u8],
        blocksize: usize,
    ) -> Vec<u8> {
        let mut decrypted = Vec::with_capacity(encrypted_data.len());
        let mut block = 0u32;

        for chunk in encrypted_data.chunks(blocksize) {
            let key = makekey_rc4_cryptoapi(password, salt, key_size, block);
            let mut dec_chunk = chunk.to_vec();
            apply_rc4(&key, &mut dec_chunk);
            decrypted.extend_from_slice(&dec_chunk);
            block += 1;
        }

        decrypted
    }
}
