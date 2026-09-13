//! MS-PPT (PowerPoint 97-2004) binary format decryption.
//! Based on msoffcrypto-tool's ppt97.py implementation.
//! <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/>
//!
//! A PowerPoint binary file is not encrypted stream by stream the way a Word one is. The
//! PowerPoint Document stream holds a set of *persist objects*, each located through a directory
//! and each encrypted on its own, with the object's persist identifier as the RC4 block number.
//! Three kinds of record are left in the clear, because they are what a reader needs in order to
//! find anything at all: the UserEditAtom, the PersistDirectoryAtom, and the
//! CryptSession10Container that holds the encryption header itself.

use crate::format::common::{parse_rc4_cryptoapi_header, RC4CryptoAPIHeader};
use crate::method::rc4::DocumentRC4CryptoAPI;
use crate::ole::OleFile;
use crate::validate;
use crate::DecryptError::{self, *};
use std::collections::BTreeMap;

const CURRENT_USER_STREAM: &str = "Current User";
const POWERPOINT_DOCUMENT_STREAM: &str = "PowerPoint Document";

const RT_CURRENT_USER_ATOM: u16 = 0x0FF6;
const RT_USER_EDIT_ATOM: u16 = 0x0FF5;
const RT_PERSIST_DIRECTORY_ATOM: u16 = 0x1772;
const RT_CRYPT_SESSION_10_CONTAINER: u16 = 0x2F14;

/// The CurrentUserAtom token that says a file is encrypted, and the one that says it is not.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/940d5700-e4d7-4fc0-ab48-fed5dbc48bc1>
const HEADER_TOKEN_ENCRYPTED: u32 = 0xF3D1C4DF;
const HEADER_TOKEN_PLAIN: u32 = 0xE391C05F;

const RECORD_HEADER_LENGTH: usize = 8;

/// Offset of the headerToken field within the CurrentUserAtom: past its record header and its
/// size field.
const HEADER_TOKEN_OFFSET: usize = RECORD_HEADER_LENGTH + 4;

/// A UserEditAtom is this long with the encryptSessionPersistIdRef field, and four bytes shorter
/// without it. The field is present exactly when the document is encrypted.
const USER_EDIT_ATOM_LEN_ENCRYPTED: u32 = 0x20;
const USER_EDIT_ATOM_LEN_PLAIN: u32 = 0x1C;

/// Offsets within a UserEditAtom, from the start of its record header.
const OFFSET_LAST_EDIT_AT: usize = 16;
const OFFSET_PERSIST_DIRECTORY_AT: usize = 20;
const ENCRYPT_SESSION_REF_AT: usize = 36;

/// How many UserEditAtoms to follow before deciding the chain does not end. A file has one per
/// save, so this is far past anything a real document reaches, and it stops a malformed file
/// from looping forever.
const MAX_USER_EDITS: usize = 1024;

/// A record header, which every record in the stream begins with.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/df201194-0cd0-4dfb-bf10-eea353d8eabc>
#[derive(Debug, Clone, Copy)]
struct RecordHeader {
    rec_type: u16,
    rec_len: u32,
}

impl RecordHeader {
    fn parse(data: &[u8], at: usize) -> Result<Self, DecryptError> {
        let bytes = data
            .get(at..at + RECORD_HEADER_LENGTH)
            .ok_or(InvalidStructure)?;

        Ok(RecordHeader {
            rec_type: u16::from_le_bytes([bytes[2], bytes[3]]),
            rec_len: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    /// Where the record after this one begins.
    fn end(&self, at: usize) -> usize {
        at + RECORD_HEADER_LENGTH + self.rec_len as usize
    }
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, DecryptError> {
    let bytes = data.get(at..at + 4).ok_or(InvalidStructure)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u32(data: &mut [u8], at: usize, value: u32) -> Result<(), DecryptError> {
    let bytes = data.get_mut(at..at + 4).ok_or(InvalidStructure)?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// One UserEditAtom: what a save left behind, and how to find what it saved.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/3ffb3fab-95de-4873-98aa-d508fbbac981>
#[derive(Debug, Clone, Copy)]
struct UserEdit {
    offset: usize,
    offset_last_edit: u32,
    offset_persist_directory: u32,
    encrypt_session_ref: Option<u32>,
}

impl UserEdit {
    fn parse(document: &[u8], at: usize) -> Result<Self, DecryptError> {
        let rh = RecordHeader::parse(document, at)?;
        validate!(rh.rec_type == RT_USER_EDIT_ATOM, InvalidStructure)?;
        validate!(
            rh.rec_len == USER_EDIT_ATOM_LEN_ENCRYPTED || rh.rec_len == USER_EDIT_ATOM_LEN_PLAIN,
            InvalidStructure
        )?;

        let encrypt_session_ref = if rh.rec_len == USER_EDIT_ATOM_LEN_ENCRYPTED {
            Some(read_u32(document, at + ENCRYPT_SESSION_REF_AT)?)
        } else {
            None
        };

        Ok(UserEdit {
            offset: at,
            offset_last_edit: read_u32(document, at + OFFSET_LAST_EDIT_AT)?,
            offset_persist_directory: read_u32(document, at + OFFSET_PERSIST_DIRECTORY_AT)?,
            encrypt_session_ref,
        })
    }
}

/// Follow the chain of UserEditAtoms, newest first, to the oldest one.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/1fc22d56-28f9-4818-bd45-67c2bf721ccf>
fn user_edit_chain(
    document: &[u8],
    offset_to_current_edit: u32,
) -> Result<Vec<UserEdit>, DecryptError> {
    let mut edits = Vec::new();
    let mut at = offset_to_current_edit as usize;

    for _ in 0..MAX_USER_EDITS {
        let edit = UserEdit::parse(document, at)?;
        edits.push(edit);

        if edit.offset_last_edit == 0 {
            return Ok(edits);
        }
        // A chain that goes forwards, or stands still, is a chain that never ends.
        validate!((edit.offset_last_edit as usize) < at, InvalidStructure)?;
        at = edit.offset_last_edit as usize;
    }

    Err(InvalidStructure)
}

/// One entry of a PersistDirectoryAtom: a run of persist identifiers starting at `persist_id`,
/// with the stream offset of each.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/6214b5a6-7ca2-4a86-8a0e-5fd3d3eff1c9>
#[derive(Debug)]
struct DirectoryEntry {
    /// Where the entry's own four-byte header sits in the stream, so that it can be edited in
    /// place without rewriting the records around it.
    at: usize,
    persist_id: u32,
    count: u32,
    offsets: Vec<u32>,
}

/// Read a PersistDirectoryAtom's entries.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/d10a093d-860f-409c-b065-aeb24b830505>
fn parse_persist_directory(
    document: &[u8],
    at: usize,
) -> Result<Vec<DirectoryEntry>, DecryptError> {
    let rh = RecordHeader::parse(document, at)?;
    validate!(rh.rec_type == RT_PERSIST_DIRECTORY_ATOM, InvalidStructure)?;

    let body_start = at + RECORD_HEADER_LENGTH;
    let body_end = body_start + rh.rec_len as usize;
    validate!(document.len() >= body_end, InvalidStructure)?;

    let mut entries = Vec::new();
    let mut pos = body_start;
    while pos < body_end {
        let word = read_u32(document, pos)?;
        let persist_id = word & 0x000F_FFFF;
        let count = word >> 20;

        let mut offsets = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let offset_at = pos + 4 + index * 4;
            validate!(offset_at + 4 <= body_end, InvalidStructure)?;
            offsets.push(read_u32(document, offset_at)?);
        }

        entries.push(DirectoryEntry {
            at: pos,
            persist_id,
            count,
            offsets,
        });
        // A run of no identifiers still takes up its four bytes, so the walk moves on rather
        // than standing still. Another tool that removed an object may well have left one.
        pos += 4 + count as usize * 4;
    }

    Ok(entries)
}

/// The persist object directory: every persist identifier in the file with the offset of the
/// object it names.
///
/// The chain is walked newest first, so the atoms are applied oldest first here: where two saves
/// name the same identifier, the newer save is the one that counts.
fn persist_object_directory(
    document: &[u8],
    edits: &[UserEdit],
) -> Result<(BTreeMap<u32, u32>, Vec<DirectoryEntry>), DecryptError> {
    let mut directory = BTreeMap::new();
    let mut all_entries = Vec::new();

    for edit in edits.iter().rev() {
        let entries = parse_persist_directory(document, edit.offset_persist_directory as usize)?;
        for entry in &entries {
            for (index, offset) in entry.offsets.iter().enumerate() {
                directory.insert(entry.persist_id + index as u32, *offset);
            }
        }
        all_entries.extend(entries);
    }

    Ok((directory, all_entries))
}

/// Read the encryption header out of the CryptSession10Container.
/// <https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/b0963334-4408-4621-879a-ef9c54551fd8>
fn parse_crypt_session(document: &[u8], at: usize) -> Result<RC4CryptoAPIHeader, DecryptError> {
    let rh = RecordHeader::parse(document, at)?;
    validate!(
        rh.rec_type == RT_CRYPT_SESSION_10_CONTAINER,
        InvalidStructure
    )?;

    let data = document
        .get(at + RECORD_HEADER_LENGTH..rh.end(at))
        .ok_or(InvalidStructure)?;

    validate!(data.len() >= 4, InvalidStructure)?;
    let v_major = u16::from_le_bytes([data[0], data[1]]);
    let v_minor = u16::from_le_bytes([data[2], data[3]]);
    validate!(
        matches!(v_major, 0x0002..=0x0004) && v_minor == 0x0002,
        Unimplemented(format!("PowerPoint encryption version {v_major}.{v_minor}"))
    )?;

    parse_rc4_cryptoapi_header(data)
}

/// Where each persist object ends: at whatever comes next in the stream.
///
/// An object does not say how long it is. Its record header is encrypted along with the rest of
/// it, so the length in that header cannot be read until the object has been decrypted, and the
/// object cannot be decrypted without knowing how long it is. What is known is where everything
/// else starts, so an object runs to the next thing along.
fn object_end(boundaries: &[usize], offset: usize, stream_len: usize) -> usize {
    boundaries
        .iter()
        .copied()
        .find(|boundary| *boundary > offset)
        .unwrap_or(stream_len)
}

/// PowerPoint 97-2004 (.ppt)
pub fn decrypt_ppt97(olefile: &mut OleFile, password: &str) -> Result<Vec<u8>, DecryptError> {
    let current_user = olefile
        .open_stream(&[CURRENT_USER_STREAM.to_owned()])?
        .stream;
    let document = olefile
        .open_stream(&[POWERPOINT_DOCUMENT_STREAM.to_owned()])?
        .stream;

    // CurrentUserAtom: whether the file is encrypted, and where the most recent save left its
    // UserEditAtom.
    let rh = RecordHeader::parse(&current_user, 0)?;
    validate!(rh.rec_type == RT_CURRENT_USER_ATOM, InvalidStructure)?;
    let header_token = read_u32(&current_user, HEADER_TOKEN_OFFSET)?;
    validate!(header_token == HEADER_TOKEN_ENCRYPTED, NotEncrypted)?;
    let offset_to_current_edit = read_u32(&current_user, HEADER_TOKEN_OFFSET + 4)?;

    let edits = user_edit_chain(&document, offset_to_current_edit)?;
    let (directory, entries) = persist_object_directory(&document, &edits)?;

    let current_edit = edits.first().ok_or(InvalidStructure)?;
    let encrypt_session_ref = current_edit.encrypt_session_ref.ok_or(NotEncrypted)?;
    let crypt_session_offset = *directory
        .get(&encrypt_session_ref)
        .ok_or(InvalidStructure)? as usize;

    let header = parse_crypt_session(&document, crypt_session_offset)?;
    validate!(
        DocumentRC4CryptoAPI::verify_password(
            password,
            &header.salt,
            header.key_size,
            &header.encrypted_verifier,
            &header.encrypted_verifier_hash,
        ),
        InvalidStructure
    )?;

    // Everything that is not a persist object still marks where one ends.
    let mut boundaries: Vec<usize> = directory.values().map(|offset| *offset as usize).collect();
    for edit in &edits {
        boundaries.push(edit.offset);
        boundaries.push(edit.offset_persist_directory as usize);
    }
    boundaries.sort_unstable();
    boundaries.dedup();

    let mut decrypted = document.clone();

    for (persist_id, offset) in &directory {
        let offset = *offset as usize;
        let rh = RecordHeader::parse(&document, offset)?;

        // The three records that are left in the clear. Their headers can be read as they stand,
        // which is how they are recognised here.
        match rh.rec_type {
            RT_CRYPT_SESSION_10_CONTAINER => {
                // The encryption header describes a file that is no longer encrypted. Zero it
                // rather than remove it, so that every offset in the file still lands where it
                // did.
                let end = rh.end(offset).min(decrypted.len());
                decrypted
                    .get_mut(offset..end)
                    .ok_or(InvalidStructure)?
                    .fill(0);
                continue;
            }
            RT_USER_EDIT_ATOM | RT_PERSIST_DIRECTORY_ATOM => continue,
            _ => {}
        }

        let end = object_end(&boundaries, offset, document.len());
        let object = document.get(offset..end).ok_or(InvalidStructure)?;
        // A persist object is one RC4 block, keyed by its own persist identifier rather than by
        // its position in the stream.
        let plain = DocumentRC4CryptoAPI::decrypt_block(
            password,
            &header.salt,
            header.key_size,
            object,
            *persist_id,
        );
        decrypted
            .get_mut(offset..end)
            .ok_or(InvalidStructure)?
            .copy_from_slice(&plain);
    }

    // The UserEditAtom of the current save loses the reference to the encryption header, and
    // shrinks by the four bytes that reference took up.
    write_u32(
        &mut decrypted,
        current_edit.offset + 4,
        USER_EDIT_ATOM_LEN_PLAIN,
    )?;
    write_u32(
        &mut decrypted,
        current_edit.offset + ENCRYPT_SESSION_REF_AT,
        0,
    )?;

    // The directory loses the CryptSession10Container from its count, so that nothing counts an
    // object that is no longer there.
    //
    // Only the entry whose run *ends* on that identifier can lose it, since a run is contiguous
    // and dropping one from the middle would renumber everything after it. A run holding nothing
    // else is left alone as well: emptying it would leave a run of no identifiers where a reader
    // expects at least one. Either way the identifier is merely stale, and nothing looks it up
    // once the UserEditAtom has stopped pointing at it.
    if let Some(entry) = entries
        .iter()
        .find(|entry| entry.count > 1 && entry.persist_id + entry.count - 1 == encrypt_session_ref)
    {
        let word = (entry.persist_id & 0x000F_FFFF) | ((entry.count - 1) << 20);
        write_u32(&mut decrypted, entry.at, word)?;
    }

    let mut current_user = current_user.clone();
    write_u32(&mut current_user, HEADER_TOKEN_OFFSET, HEADER_TOKEN_PLAIN)?;

    olefile.write_stream(&[CURRENT_USER_STREAM.to_owned()], &current_user)?;
    olefile.write_stream(&[POWERPOINT_DOCUMENT_STREAM.to_owned()], &decrypted)?;

    olefile.to_bytes()
}
