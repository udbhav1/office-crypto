use crate::ole::OleStream;
use crate::validate;
use crate::DecryptError::{self, *};

use aes::cipher::{
    block_padding::NoPadding, generic_array::typenum::consts::U16, generic_array::GenericArray,
    BlockDecryptMut, KeyInit, KeyIvInit,
};
use base64::engine::general_purpose;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha1::Sha1;
use sha2::{Digest, Sha512};
use std::io::prelude::*;
use std::io::Cursor;

// unused blocks are meant to verify password/file integrity
const _BLOCK1: [u8; 8] = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const _BLOCK2: [u8; 8] = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const BLOCK3: [u8; 8] = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];
const _BLOCK4: [u8; 8] = [0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6];
const _BLOCK5: [u8; 8] = [0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33];

const SEGMENT_LENGTH: usize = 4096;
const ITER_COUNT: u32 = 50000;

fn b64_decode(bytes: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut wrapped_reader = Cursor::new(bytes);
    let mut decoder =
        base64::read::DecoderReader::new(&mut wrapped_reader, &general_purpose::STANDARD);

    let mut result = Vec::new();
    decoder.read_to_end(&mut result).map_err(|_| Unknown)?;
    Ok(result)
}

#[allow(dead_code)]
#[derive(Default, Debug)]
pub(crate) struct AgileEncryptionInfo {
    key_data_salt: Vec<u8>,
    key_data_hash_algorithm: String,
    key_data_block_size: u32,
    encrypted_hmac_key: Vec<u8>,
    encrypted_hmac_value: Vec<u8>,
    encrypted_verifier_hash_input: Vec<u8>,
    encrypted_verifier_hash_value: Vec<u8>,
    encrypted_key_value: Vec<u8>,
    spin_count: u32,
    password_salt: Vec<u8>,
    password_hash_algorithm: String,
    password_key_bits: u32,
}

impl AgileEncryptionInfo {
    pub fn new(encryption_info: &OleStream) -> Result<Self, DecryptError> {
        let raw_xml = String::from_utf8(encryption_info.stream[8..].to_vec())
            .map_err(|_| InvalidStructure)?;

        let mut reader = Reader::from_str(&raw_xml);
        reader.trim_text(true);

        let mut aei = Self::default();
        let mut set_key_data = false;
        let mut set_hmac_data = false;
        let mut set_password_node = false;

        loop {
            match reader.read_event().unwrap() {
                Event::Empty(e) => match e.name().as_ref() {
                    b"keyData" if !set_key_data => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|_| InvalidStructure)?;
                            match attr.key.as_ref() {
                                b"saltValue" => {
                                    aei.key_data_salt = b64_decode(&attr.value)?;
                                }
                                b"hashAlgorithm" => {
                                    aei.key_data_hash_algorithm =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?;
                                }
                                b"blockSize" => {
                                    aei.key_data_block_size =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?
                                            .parse()
                                            .map_err(|_| InvalidStructure)?;
                                }
                                _ => (),
                            }
                        }
                        set_key_data = true;
                    }
                    b"dataIntegrity" if !set_hmac_data => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|_| InvalidStructure)?;
                            match attr.key.as_ref() {
                                b"encryptedHmacKey" => {
                                    aei.encrypted_hmac_key = b64_decode(&attr.value)?;
                                }
                                b"encryptedHmacValue" => {
                                    aei.encrypted_hmac_value = b64_decode(&attr.value)?;
                                }
                                _ => (),
                            }
                        }
                        set_hmac_data = true;
                    }
                    b"p:encryptedKey" if !set_password_node => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|_| InvalidStructure)?;
                            match attr.key.as_ref() {
                                b"encryptedVerifierHashInput" => {
                                    aei.encrypted_verifier_hash_input = b64_decode(&attr.value)?;
                                }
                                b"encryptedVerifierHashValue" => {
                                    aei.encrypted_verifier_hash_value = b64_decode(&attr.value)?;
                                }
                                b"encryptedKeyValue" => {
                                    aei.encrypted_key_value = b64_decode(&attr.value)?;
                                }
                                b"spinCount" => {
                                    aei.spin_count = String::from_utf8(attr.value.into_owned())
                                        .map_err(|_| InvalidStructure)?
                                        .parse()
                                        .map_err(|_| InvalidStructure)?;
                                }
                                b"saltValue" => {
                                    aei.password_salt = b64_decode(&attr.value)?;
                                }
                                b"hashAlgorithm" => {
                                    aei.password_hash_algorithm =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?;
                                }
                                b"keyBits" => {
                                    aei.password_key_bits =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|_| InvalidStructure)?
                                            .parse()
                                            .map_err(|_| InvalidStructure)?;
                                }
                                _ => (),
                            }
                        }
                        set_password_node = true;
                    }
                    _ => (),
                },
                Event::Eof => break,
                _ => (),
            }
        }

        validate!(set_key_data, InvalidStructure)?;
        validate!(set_hmac_data, InvalidStructure)?;
        validate!(set_password_node, InvalidStructure)?;

        Ok(aei)
    }

    pub fn key_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let digest = self.iterated_hash_from_password(password)?;
        let encryption_key = self.encryption_key(&digest, &BLOCK3)?;
        self.decrypt_aes_cbc(&encryption_key)
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        encrypted_stream: &OleStream,
    ) -> Result<Vec<u8>, DecryptError> {
        let total_size = u32::from_le_bytes(
            encrypted_stream.stream[..4]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        ) as usize;
        let mut block_start: usize = 8; // skip first 8 bytes
        let mut block_index: u32 = 0;
        let mut decrypted: Vec<u8> = vec![0; total_size];
        let key_data_salt: &[u8] = &self.key_data_salt;

        match self.key_data_hash_algorithm.as_str() {
            "SHA512" => {
                while block_start < (total_size - SEGMENT_LENGTH) {
                    let iv = Sha512::digest([key_data_salt, &block_index.to_le_bytes()].concat());
                    let iv = &iv[..16];

                    let cbc_cipher = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());

                    // decrypt from encrypted_stream directly to output Vec
                    cbc_cipher
                        .decrypt_padded_b2b_mut::<NoPadding>(
                            &encrypted_stream.stream[block_start..(block_start + SEGMENT_LENGTH)],
                            &mut decrypted[(block_start - 8)..(block_start - 8 + SEGMENT_LENGTH)],
                        )
                        .map_err(|_| InvalidStructure)?;

                    block_index += 1;
                    block_start += SEGMENT_LENGTH;
                }
                // parse last block w less than 4096 bytes
                let remaining = total_size - (block_start - 8);
                let iv = Sha512::digest([key_data_salt, &block_index.to_le_bytes()].concat());
                let iv = &iv[..16];

                let cbc_cipher = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
                let irregular_block_len = remaining % 16;

                // remaining bytes in encrypted_stream should be a multiple of block size even if we only use some of the decrypted bytes
                let ciphertext = &encrypted_stream.stream[block_start..];
                validate!(ciphertext.len() % 16 == 0, InvalidStructure)?;

                let mut plaintext: Vec<u8> = vec![0; ciphertext.len()];
                cbc_cipher
                    .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext)
                    .map_err(|_| InvalidStructure)?;
                let mut copy_span = plaintext.len() - 16 + irregular_block_len;
                if irregular_block_len == 0 {
                    copy_span += 16;
                }
                decrypted[(block_start - 8)..(block_start + copy_span - 8)]
                    .copy_from_slice(&plaintext[..copy_span]);
                Ok(decrypted)
            }
            "SHA384" => Err(Unimplemented("SHA384".to_owned())),
            "SHA256" => Err(Unimplemented("SHA256".to_owned())),
            "SHA1" => Err(Unimplemented("SHA1".to_owned())),
            _ => Err(InvalidStructure),
        }
    }

    // this function is ridiculously expensive as it usually runs 10000 SHA512's
    fn iterated_hash_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let pass_utf16: Vec<u16> = password.encode_utf16().collect();
        let pass_utf16: &[u8] = unsafe { pass_utf16.align_to::<u8>().1 };
        let salted: Vec<u8> = [&self.password_salt, pass_utf16].concat();
        // TODO rewrite and pass ShaXXX:digest() as param?
        // could maybe abstract over T: Digest but the Sha512 type alias is weird
        match self.password_hash_algorithm.as_str() {
            "SHA512" => {
                let mut h = Sha512::digest(salted);
                for i in 0u32..self.spin_count {
                    h = Sha512::digest([&i.to_le_bytes(), h.as_slice()].concat());
                }

                Ok(h.as_slice().to_owned())
            }
            "SHA384" => Err(Unimplemented("SHA384".to_owned())),
            "SHA256" => Err(Unimplemented("SHA256".to_owned())),
            "SHA1" => Err(Unimplemented("SHA1".to_owned())),
            _ => Err(InvalidStructure),
        }
    }

    fn encryption_key(&self, digest: &[u8], block: &[u8]) -> Result<Vec<u8>, DecryptError> {
        match self.password_hash_algorithm.as_str() {
            "SHA512" => {
                let h = Sha512::digest([digest, block].concat());
                Ok(h.as_slice()[..(self.password_key_bits as usize / 8)].to_owned())
            }
            "SHA384" => Err(Unimplemented("SHA384".to_owned())),
            "SHA256" => Err(Unimplemented("SHA256".to_owned())),
            "SHA1" => Err(Unimplemented("SHA1".to_owned())),
            _ => Err(InvalidStructure),
        }
    }

    fn decrypt_aes_cbc(&self, key: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let mut cbc_cipher =
            cbc::Decryptor::<aes::Aes256>::new(key.into(), self.password_salt.as_slice().into());

        // two 16-byte cbc blocks
        // TODO how does the hash func affect # of blocks?
        let i1: GenericArray<u8, U16> =
            GenericArray::clone_from_slice(&self.encrypted_key_value.clone()[..16]);
        let i2: GenericArray<u8, U16> =
            GenericArray::clone_from_slice(&self.encrypted_key_value.clone()[16..]);
        let ciphertext_blocks = [i1, i2];

        let o1: GenericArray<u8, U16> = GenericArray::default();
        let o2: GenericArray<u8, U16> = GenericArray::default();
        let mut plaintext_blocks = [o1, o2];

        cbc_cipher
            .decrypt_blocks_b2b_mut(&ciphertext_blocks, &mut plaintext_blocks)
            .map_err(|_| Unknown)?;

        let plaintext = [
            plaintext_blocks[0].as_slice(),
            plaintext_blocks[1].as_slice(),
        ]
        .concat();

        Ok(plaintext)
    }
}

#[allow(dead_code)]
#[derive(Default, Debug)]
pub(crate) struct StandardEncryptionInfo {
    flags: u32,
    size_extra: u32,
    alg_id: u32,
    alg_id_hash: u32,
    key_size: u32,
    provider_type: u32,
    reserved1: u32,
    reserved2: u32,
    csp_name: String,
    salt_size: u32,
    salt: Vec<u8>,
    encrypted_verifier: Vec<u8>,
    verifier_hash_size: u32,
    encrypted_verifier_hash: Vec<u8>,
}

impl StandardEncryptionInfo {
    pub fn new(encryption_info: &OleStream) -> Result<Self, DecryptError> {
        // let header_flags = u32::from_le_bytes(
        //     encryption_info.stream[4..8]
        //         .try_into()
        //         .map_err(|_| InvalidStructure)?,
        // );
        let header_size = u32::from_le_bytes(
            encryption_info.stream[8..12]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        let header_bytes = &encryption_info.stream[12..(12 + header_size as usize)];
        let mut sei = Self::default();

        // TODO switch to packed struct maybe
        sei.flags = u32::from_le_bytes(header_bytes[..4].try_into().map_err(|_| InvalidStructure)?);
        sei.size_extra = u32::from_le_bytes(
            header_bytes[4..8]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.alg_id = u32::from_le_bytes(
            header_bytes[8..12]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.alg_id_hash = u32::from_le_bytes(
            header_bytes[12..16]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.key_size = u32::from_le_bytes(
            header_bytes[16..20]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.provider_type = u32::from_le_bytes(
            header_bytes[20..24]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.reserved1 = u32::from_le_bytes(
            header_bytes[24..28]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.reserved2 = u32::from_le_bytes(
            header_bytes[28..32]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );

        let csp_utf16 = header_bytes[32..].to_owned();
        let csp_utf16: &[u16] = unsafe { csp_utf16.align_to::<u16>().1 };
        sei.csp_name = String::from_utf16(csp_utf16).map_err(|_| InvalidStructure)?;

        // check if AES, otherwise RC4
        validate!(
            sei.alg_id & 0xFF00 == 0x6600,
            Unimplemented("RC4".to_owned())
        )?;

        let verifier_bytes = &encryption_info.stream[(12 + header_size as usize)..];

        sei.salt_size = u32::from_le_bytes(
            verifier_bytes[..4]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.salt = verifier_bytes[4..20].to_owned();
        sei.encrypted_verifier = verifier_bytes[20..36].to_owned();
        sei.verifier_hash_size = u32::from_le_bytes(
            verifier_bytes[36..40]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        );
        sei.encrypted_verifier_hash = verifier_bytes[40..72].to_owned();

        Ok(sei)
    }

    pub fn key_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let pass_utf16: Vec<u16> = password.encode_utf16().collect();
        let pass_utf16: &[u8] = unsafe { pass_utf16.align_to::<u8>().1 };

        let mut h = Sha1::digest([&self.salt, pass_utf16].concat());
        for i in 0u32..ITER_COUNT {
            h = Sha1::digest([&i.to_le_bytes(), h.as_slice()].concat());
        }

        let block_bytes = [0, 0, 0, 0];
        h = Sha1::digest([h.as_slice(), &block_bytes].concat());
        let cb_required_key_length = self.key_size / 8;
        // let cb_hash = h.len();

        let mut buf1 = [0x36_u8; 64];
        buf1.iter_mut().zip(h.iter()).for_each(|(a, b)| *a ^= *b);
        let x1 = Sha1::digest(buf1);

        let mut buf2 = [0x5c_u8; 64];
        buf2.iter_mut().zip(h.iter()).for_each(|(a, b)| *a ^= *b);
        let x2 = Sha1::digest(buf2);

        Ok([x1, x2].concat()[..(cb_required_key_length as usize)].to_owned())
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        encrypted_stream: &OleStream,
    ) -> Result<Vec<u8>, DecryptError> {
        let total_size = u32::from_le_bytes(
            encrypted_stream.stream[..4]
                .try_into()
                .map_err(|_| InvalidStructure)?,
        ) as usize;
        // has to be big enough to decrypt into
        let mut decrypted: Vec<u8> = vec![0; encrypted_stream.stream.len()];
        let block_start = 8;

        // 16 bit blocks
        validate!(
            (encrypted_stream.stream.len() - 8) % 16 == 0,
            InvalidStructure
        )?;

        let ecb_cipher = ecb::Decryptor::<aes::Aes128>::new(key.into());
        ecb_cipher
            .decrypt_padded_b2b_mut::<NoPadding>(
                &encrypted_stream.stream[block_start..],
                &mut decrypted,
            )
            .map_err(|_| InvalidStructure)?;

        Ok(decrypted[..total_size].to_vec())
    }
}
