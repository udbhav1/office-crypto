use crate::validate;
use crate::DecryptError::{self, InvalidHeader, InvalidStructure, IoError, Unimplemented, Unknown};

use bytemuck::cast_slice;
use derivative::Derivative;
use packed_struct::prelude::*;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

// https://github.com/decalage2/olefile/blob/master/olefile/olefile.py#L207
const MAGIC: [u8; 8] = [208, 207, 17, 224, 161, 177, 26, 225];
const ZERO_CLSID: [u8; 16] = [0; 16];
const BYTE_ORDER: u16 = 65534;

const DIFSECT: u32 = 0xFFFF_FFFC;
const FATSECT: u32 = 0xFFFF_FFFD;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;

const _MAXREGSID: u32 = 0xFFFF_FFFA;
const NOSTREAM: u32 = 0xFFFF_FFFF;

const STGTY_EMPTY: u8 = 0;
const STGTY_STORAGE: u8 = 1;
const STGTY_STREAM: u8 = 2;
const _STGTY_LOCKBYTES: u8 = 3;
const _STGTY_PROPERTY: u8 = 4;
const STGTY_ROOT: u8 = 5;

const UNKNOWN_SIZE: u32 = 0x7FFF_FFFF;

// little-endian
#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "lsb", bit_numbering = "msb0")]
pub struct OleHeader {
    #[packed_field(bytes = "0..=7")]
    magic: [u8; 8],
    #[packed_field(bytes = "8..=23")]
    clsid: [u8; 16],
    #[packed_field(bytes = "24..=25")]
    minor_version: u16,
    #[packed_field(bytes = "26..=27")]
    dll_version: u16,
    #[packed_field(bytes = "28..=29")]
    byte_order: u16,
    #[packed_field(bytes = "30..=31")]
    sector_shift: u16,
    #[packed_field(bytes = "32..=33")]
    mini_sector_shift: u16,
    #[packed_field(bytes = "34..=35")]
    reserved1: u16,
    #[packed_field(bytes = "36..=39")]
    reserved2: u32,
    #[packed_field(bytes = "40..=43")]
    num_dir_sectors: u32,
    #[packed_field(bytes = "44..=47")]
    num_fat_sectors: u32,
    #[packed_field(bytes = "48..=51")]
    first_dir_sector: u32,
    #[packed_field(bytes = "52..=55")]
    transaction_signature_number: u32,
    #[packed_field(bytes = "56..=59")]
    mini_stream_cutoff_size: u32,
    #[packed_field(bytes = "60..=63")]
    first_mini_fat_sector: u32,
    #[packed_field(bytes = "64..=67")]
    num_mini_fat_sectors: u32,
    #[packed_field(bytes = "68..=71")]
    first_difat_sector: u32,
    #[packed_field(bytes = "72..=75")]
    num_difat_sectors: u32,
}

impl OleHeader {
    fn validate_header(&mut self) -> Result<(), DecryptError> {
        validate!(self.magic == MAGIC, InvalidHeader)?;
        validate!(self.clsid == ZERO_CLSID, InvalidHeader)?;
        validate!(
            self.dll_version == 3 || self.dll_version == 4,
            InvalidHeader
        )?;
        validate!(self.byte_order == BYTE_ORDER, InvalidHeader)?;
        validate!(
            self.sector_shift == 9 || self.sector_shift == 12,
            InvalidHeader
        )?;
        validate!(
            (self.dll_version == 3 && self.sector_shift == 9)
                || (self.dll_version == 4 && self.sector_shift == 12),
            InvalidHeader
        )?;
        validate!(self.mini_sector_shift == 6, InvalidHeader)?;
        validate!(self.reserved1 == 0, InvalidHeader)?;
        validate!(self.reserved2 == 0, InvalidHeader)?;
        validate!(
            self.dll_version == 4 || self.num_dir_sectors == 0,
            InvalidHeader
        )?;
        validate!(self.transaction_signature_number == 0, InvalidHeader)?;
        // TODO set to 4096 if not already
        validate!(self.mini_stream_cutoff_size == 4096, InvalidHeader)?;

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct OleFile {
    raw: Vec<u8>,
    header: OleHeader,
    sector_size: u32,
    mini_sector_size: u32,
    nb_sect: u32,
    used_streams_fat: Vec<u32>,
    used_streams_minifat: Vec<u32>,
    // TODO should these be i32 not u32??
    fat: Vec<u32>,
    minifat: Vec<u32>,
    directory_fp: OleStream,
    direntries: Vec<OleDirentry>,
    ministream: Option<OleStream>,
    root_sid: usize,
}

impl OleFile {
    pub fn new(raw: Vec<u8>) -> Result<Self, DecryptError> {
        // u32::MAX bytes = ~4.2GB which i can live with
        let filesize = raw.len() as u32;
        validate!(filesize > 76, InvalidHeader)?;

        let header: [u8; 76] = raw[..76].try_into().unwrap();
        let mut header = OleHeader::unpack(&header).map_err(|_| InvalidHeader)?;
        header.validate_header()?;

        let sector_size = u32::pow(2, header.sector_shift as u32);
        let mini_sector_size = u32::pow(2, header.mini_sector_shift as u32);
        let nb_sect = ((filesize + sector_size - 1) / sector_size) - 1;

        Ok(Self {
            raw,
            header,
            sector_size,
            mini_sector_size,
            nb_sect,
            used_streams_fat: Vec::new(),
            used_streams_minifat: Vec::new(),
            fat: Vec::new(),
            minifat: Vec::new(),
            directory_fp: OleStream::default(),
            direntries: Vec::new(),
            ministream: None,
            root_sid: 0,
        })
    }

    pub fn from_file<P: AsRef<Path>>(filename: P) -> Result<Self, DecryptError> {
        let mut file = File::open(filename).map_err(IoError)?;
        let mut raw: Vec<u8> = Vec::new();
        file.read_to_end(&mut raw).map_err(IoError)?;

        OleFile::new(raw)
    }

    pub fn init(&mut self) -> Result<(), DecryptError> {
        self.check_duplicate_stream(self.header.first_dir_sector, false)?;
        if self.header.num_mini_fat_sectors > 0 {
            // [minifat: false] is not a mistake here
            self.check_duplicate_stream(self.header.first_mini_fat_sector, false)?;
        }
        if self.header.num_difat_sectors > 0 {
            self.check_duplicate_stream(self.header.first_difat_sector, false)?;
        }

        self.load_fat()?;
        self.load_directory(self.header.first_dir_sector)
    }

    // takes a path (e.g. [storage_1, storage_1.2, stream])
    pub fn open_stream(&mut self, path: &[String]) -> Result<OleStream, DecryptError> {
        // walk direntries red/black tree to find the right stream
        let mut node_sid = self.root_sid;
        for name in path {
            node_sid = self
                .direntries
                .iter()
                .position(|item| item.name.to_lowercase() == name.to_lowercase())
                .ok_or(InvalidStructure)?;
        }

        validate!(
            self.direntries[node_sid].packed.entry_type == STGTY_STREAM,
            InvalidStructure
        )?;

        self.open_helper(
            self.direntries[node_sid].packed.isect_start,
            self.direntries[node_sid].size,
            false,
        )
    }

    fn check_duplicate_stream(
        &mut self,
        first_sect: u32,
        minifat: bool,
    ) -> Result<(), DecryptError> {
        if minifat {
            validate!(
                !self.used_streams_minifat.contains(&first_sect),
                InvalidStructure
            )?;
            self.used_streams_minifat.push(first_sect);
        } else {
            if [DIFSECT, FATSECT, ENDOFCHAIN, FREESECT].contains(&first_sect) {
                return Ok(());
            }
            validate!(
                !self.used_streams_fat.contains(&first_sect),
                InvalidStructure
            )?;
            self.used_streams_fat.push(first_sect);
        }

        Ok(())
    }

    fn load_fat_sect(&mut self, sect: &[u32]) {
        for isect in sect {
            // labeled as JYTHON-WORKAROUND in the olefile code
            // let isect = isect & 0xFFFFFFFF;
            let isect = *isect;
            if isect == ENDOFCHAIN || isect == FREESECT {
                break;
            }
            let start = (self.sector_size * (isect + 1)) as usize;
            let s = &self.raw[start..(start + self.sector_size as usize)];
            let next_fat = sect_to_array(s);
            self.fat.extend_from_slice(next_fat);
        }
    }

    fn load_fat_sect_range(&mut self, sect_start: usize, sect_end: usize) {
        let sect = &self.raw[sect_start..sect_end].to_owned();
        let fat1: &[u32] = sect_to_array(sect);
        self.load_fat_sect(fat1);
    }

    fn load_fat(&mut self) -> Result<(), DecryptError> {
        self.load_fat_sect_range(76, 512);
        // "There's a DIFAT because file is larger than 6.8MB"
        if self.header.num_difat_sectors > 0 {
            validate!(self.header.num_fat_sectors > 109, InvalidStructure)?;
            validate!(
                self.header.first_difat_sector < self.nb_sect,
                InvalidStructure
            )?;
            // "We compute the necessary number of DIFAT sectors :
            // Number of pointers per DIFAT sector = (sectorsize/4)-1
            // (-1 because the last pointer is the next DIFAT sector number)"
            let nb_difat_sectors = (self.sector_size / 4) - 1;
            // "(if 512 bytes: each DIFAT sector = 127 pointers + 1 towards next DIFAT sector)"
            let nb_difat =
                (self.header.num_fat_sectors - 109 + nb_difat_sectors - 1) / nb_difat_sectors;
            validate!(self.header.num_difat_sectors == nb_difat, InvalidStructure)?;

            let mut isect_difat = self.header.first_difat_sector;

            for _ in 0..nb_difat {
                let start = ((self.sector_size) * (isect_difat + 1)) as usize;
                let sector_difat = self.raw[start..(start + self.sector_size as usize)].to_owned();
                let difat = sect_to_array(&sector_difat);

                self.load_fat_sect(&difat[..(nb_difat_sectors as usize)]);
                isect_difat = difat[nb_difat_sectors as usize];
            }

            validate!(
                [ENDOFCHAIN, FREESECT].contains(&isect_difat),
                InvalidStructure
            )?;
        }

        if self.fat.len() as u32 > self.nb_sect {
            self.fat = self.fat[..self.nb_sect as usize].to_vec();
        }

        Ok(())
    }

    fn load_directory(&mut self, sect: u32) -> Result<(), DecryptError> {
        self.directory_fp = self.open_helper(sect, UNKNOWN_SIZE as u64, true)?;
        let max_entries = self.directory_fp.size / 128;
        // build direntries and figure out what struct type each is
        self.direntries = vec![OleDirentry::default(); max_entries as usize];
        self.load_direntry(0)?;
        self.build_storage_tree(self.root_sid)
    }

    fn load_direntry(&mut self, sid: usize) -> Result<usize, DecryptError> {
        validate!(sid < self.direntries.len(), InvalidStructure)?;
        // double reference for OLE stream/storage
        validate!(!self.direntries[sid].used, Unknown)?;

        let start = sid * 128;
        let entry = &self.directory_fp.stream[start..(start + 128)];
        let direntry = OleDirentry::new(entry.try_into().map_err(|_| Unknown)?, sid, self)?;
        self.direntries[sid] = direntry;

        Ok(sid)
    }

    fn load_minifat(&mut self) -> Result<(), DecryptError> {
        // "MiniFAT is stored in a standard  sub-stream, pointed to by a header
        // field.
        // NOTE: there are two sizes to take into account for this stream:
        // 1) Stream size is calculated according to the number of sectors
        //    declared in the OLE header. This allocated stream may be more than
        //    needed to store the actual sector indexes.
        // (self.num_mini_fat_sectors is the number of sectors of size self.sector_size)
        // 2) Actually used size is calculated by dividing the MiniStream size
        //    (given by root entry size) by the size of mini sectors, *4 for
        //    32 bits indexes:"
        let stream_size = (self.header.num_mini_fat_sectors * self.sector_size) as u64;
        let nb_minisectors = (self.direntries[self.root_sid].size + self.mini_sector_size as u64
            - 1)
            / self.mini_sector_size as u64;

        // "This is not really a problem, but may indicate a wrong implementation:"
        // let _used_size = nb_minisectors * 4;
        // assert!(used_size <= stream_size);

        let s = self.open_helper(self.header.first_mini_fat_sector, stream_size, true)?;
        self.minifat = sect_to_array(&s.stream).to_vec();
        self.minifat = self.minifat[..nb_minisectors as usize].to_vec();

        Ok(())
    }

    fn open_helper(
        &mut self,
        start: u32,
        size: u64,
        force_fat: bool,
    ) -> Result<OleStream, DecryptError> {
        if size < self.header.mini_stream_cutoff_size as u64 && !force_fat {
            if self.ministream.is_none() {
                self.load_minifat()?;
                let size_ministream = self.direntries[self.root_sid].size;

                self.ministream = Some(self.open_helper(
                    self.direntries[self.root_sid].packed.isect_start,
                    size_ministream,
                    true,
                )?);
            }

            let mut olestream = OleStream::new(start, size, 0, self.mini_sector_size);
            olestream.init(&self.ministream.as_ref().unwrap().stream, &self.minifat)?;

            Ok(olestream)
        } else {
            let mut olestream = OleStream::new(start, size, self.sector_size, self.sector_size);
            olestream.init(&self.raw, &self.fat)?;

            Ok(olestream)
        }
    }

    fn build_storage_tree(&mut self, direntry_ind: usize) -> Result<(), DecryptError> {
        let sid_child = self.direntries[direntry_ind].packed.sid_child;
        if sid_child != NOSTREAM {
            // "Note from OpenOffice documentation: the safest way is to
            // recreate the tree because some implementations may store broken
            // red-black trees..."
            self.append_children(direntry_ind, sid_child as usize)?;
        }

        Ok(())
    }

    fn append_children(&mut self, parent_sid: usize, child_sid: usize) -> Result<(), DecryptError> {
        if child_sid as u32 == NOSTREAM {
            return Ok(());
        }
        validate!(child_sid < self.direntries.len(), InvalidStructure)?;

        self.load_direntry(child_sid)?;
        // now child is an OleDirentry at self.direntries[child_sid]
        // refer by index so borrow checker stays happy
        validate!(!self.direntries[child_sid].used, InvalidStructure)?;

        self.direntries[child_sid].used = true;
        self.append_children(
            parent_sid,
            self.direntries[child_sid].packed.sid_left as usize,
        )?;
        let name_lower = self.direntries[child_sid].name.to_lowercase();

        validate!(
            !self.direntries[parent_sid]
                .children_map
                .contains_key(&name_lower),
            InvalidStructure
        )?;

        self.direntries[parent_sid].children.push(child_sid);
        self.direntries[parent_sid]
            .children_map
            .insert(name_lower, child_sid);

        self.append_children(
            parent_sid,
            self.direntries[child_sid].packed.sid_right as usize,
        )?;

        self.build_storage_tree(child_sid)
    }
}

impl fmt::Display for OleFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "-----HEADER FIELDS-----")?;
        writeln!(f, "magic: {:?}", self.header.magic)?;
        writeln!(f, "clsid: {:?}", self.header.clsid)?;
        writeln!(f, "minor_version: {:?}", self.header.minor_version)?;
        writeln!(f, "dll_version: {:?}", self.header.dll_version)?;
        writeln!(f, "byte_order: {:?}", self.header.byte_order)?;
        writeln!(f, "sector_shift: {:?}", self.header.sector_shift)?;
        writeln!(f, "mini_sector_shift: {:?}", self.header.mini_sector_shift)?;
        writeln!(f, "reserved1: {:?}", self.header.reserved1)?;
        writeln!(f, "reserved2: {:?}", self.header.reserved2)?;
        writeln!(f, "num_dir_sectors: {:?}", self.header.num_dir_sectors)?;
        writeln!(f, "num_fat_sectors: {:?}", self.header.num_fat_sectors)?;
        writeln!(f, "first_dir_sector: {:?}", self.header.first_dir_sector)?;
        writeln!(
            f,
            "transaction_signature_number: {:?}",
            self.header.transaction_signature_number
        )?;
        writeln!(
            f,
            "mini_stream_cutoff_size: {:?}",
            self.header.mini_stream_cutoff_size
        )?;
        writeln!(
            f,
            "first_mini_fat_sector: {:?}",
            self.header.first_mini_fat_sector
        )?;
        writeln!(
            f,
            "num_mini_fat_sectors: {:?}",
            self.header.num_mini_fat_sectors
        )?;
        writeln!(
            f,
            "first_difat_sector: {:?}",
            self.header.first_difat_sector
        )?;
        writeln!(f, "num_difat_sectors: {:?}", self.header.num_difat_sectors)?;

        writeln!(f, "-----NON-HEADER FIELDS-----")?;
        writeln!(f, "sector_size: {:?}", self.sector_size)?;
        writeln!(f, "mini_sector_size: {:?}", self.mini_sector_size)?;
        writeln!(f, "nb_sect: {:?}", self.nb_sect)?;
        writeln!(f, "used_streams_fat: {:?}", self.used_streams_fat)?;
        writeln!(f, "used_streams_minifat: {:?}", self.used_streams_minifat)
    }
}

#[derive(Default, Debug)]
pub(crate) struct OleStream {
    pub stream: Vec<u8>,
    start: u32,
    size: u64,
    offset: u32,
    sector_size: u32,
}

impl OleStream {
    pub fn new(start: u32, size: u64, offset: u32, sector_size: u32) -> Self {
        OleStream {
            stream: Vec::new(),
            start,
            size,
            offset,
            sector_size,
        }
    }

    fn init(&mut self, raw: &[u8], fat: &Vec<u32>) -> Result<(), DecryptError> {
        let mut unknown_size = false;
        let fat_len = fat.len() as u32;

        if self.size == UNKNOWN_SIZE as u64 {
            self.size = fat_len as u64 * self.sector_size as u64;
            unknown_size = true;
        }

        let nb_sectors = (self.size + (self.sector_size as u64 - 1)) / self.sector_size as u64;
        validate!(nb_sectors <= fat_len as u64, InvalidStructure)?;
        let mut sect = self.start;
        validate!(self.size != 0 || sect == ENDOFCHAIN, InvalidStructure)?;

        let mut data: Vec<u8> = Vec::new();
        for _ in 0..nb_sectors {
            if sect == ENDOFCHAIN {
                validate!(unknown_size, InvalidStructure)?;
                break;
            }
            validate!(sect < fat_len, InvalidStructure)?;
            let start = (self.offset + self.sector_size * sect) as usize;
            let sector_data = &raw[start..(start + self.sector_size as usize)];
            // TODO last sector might have less than 512/4k, so read less on index
            validate!(
                sector_data.len() == self.sector_size as usize || sect == (fat_len - 1),
                InvalidStructure
            )?;
            data.extend_from_slice(sector_data);

            // labeled as JYTHON_WORKAROUND in the olefile code
            // sect = fat[sect as usize] & 0xFFFFFFFF;
            sect = fat[sect as usize];
        }

        if data.len() >= self.size as usize {
            data = data[..self.size as usize].to_vec();
        } else if unknown_size {
            self.size = data.len() as u64;
        } else {
            return Err(InvalidStructure);
        }

        self.stream = data;

        Ok(())
    }
}

#[derive(PackedStruct, Derivative, Debug, Clone)]
#[packed_struct(endian = "lsb", bit_numbering = "msb0")]
#[derivative(Default)]
pub struct OleDirentryPacked {
    #[packed_field(bytes = "0..=63")]
    // workaround since Default isnt implemented for [T; >32]
    #[derivative(Default(value = "[0; 64]"))]
    name_raw: [u8; 64],
    #[packed_field(bytes = "64..=65")]
    name_length: u16,
    #[packed_field(bytes = "66..=66")]
    entry_type: u8,
    #[packed_field(bytes = "67..=67")]
    color: u8,
    #[packed_field(bytes = "68..=71")]
    sid_left: u32,
    #[packed_field(bytes = "72..=75")]
    sid_right: u32,
    #[packed_field(bytes = "76..=79")]
    sid_child: u32,
    #[packed_field(bytes = "80..=95")]
    clsid: [u8; 16],
    #[packed_field(bytes = "96..=99")]
    dw_user_flags: u32,
    #[packed_field(bytes = "100..=107")]
    create_time: u64,
    #[packed_field(bytes = "108..=115")]
    modify_time: u64,
    #[packed_field(bytes = "116..=119")]
    isect_start: u32,
    #[packed_field(bytes = "120..=123")]
    size_low: u32,
    #[packed_field(bytes = "124..=127")]
    size_high: u32,
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone)]
pub(crate) struct OleDirentry {
    packed: OleDirentryPacked,
    name: String,
    clsid: String,
    sid: usize,
    size: u64,
    children: Vec<usize>,
    children_map: HashMap<String, usize>,
    sect_chain: Option<Vec<u32>>,
    used: bool,
    minifat: bool,
}

impl OleDirentry {
    pub fn new(
        entry: [u8; 128],
        sid: usize,
        // sector_size: u32,
        // mini_sector_cutoff: u32,
        olefile: &mut OleFile,
    ) -> Result<Self, DecryptError> {
        let packed = OleDirentryPacked::unpack(&entry).map_err(|_| InvalidStructure)?;

        validate!(
            [STGTY_ROOT, STGTY_STORAGE, STGTY_STREAM, STGTY_EMPTY].contains(&packed.entry_type),
            InvalidStructure
        )?;
        validate!(
            packed.entry_type != STGTY_ROOT || sid == 0,
            InvalidStructure
        )?;
        validate!(
            packed.entry_type == STGTY_ROOT || sid != 0,
            InvalidStructure
        )?;
        validate!(packed.name_length <= 64, InvalidStructure)?;

        let name_utf16 = &packed.name_raw[..(packed.name_length as usize - 2)];
        let name_utf16: &[u16] = cast_slice(name_utf16);
        let name = String::from_utf16(name_utf16).map_err(|_| InvalidStructure)?;

        let size = if olefile.sector_size == 512 {
            packed.size_low as u64
        } else {
            packed.size_low as u64 + ((packed.size_high as u64) << 32)
        };

        let clsid = convert_clsid(packed.clsid)?;
        validate!(
            packed.entry_type != STGTY_STORAGE || size == 0,
            InvalidStructure
        )?;

        let mut minifat = false;
        if [STGTY_ROOT, STGTY_STREAM].contains(&packed.entry_type) && size > 0 {
            if size < olefile.header.mini_stream_cutoff_size as u64
                && packed.entry_type == STGTY_STREAM
            {
                minifat = true;
            }
            olefile.check_duplicate_stream(packed.isect_start, minifat)?;
        }

        Ok(OleDirentry {
            packed,
            name,
            clsid,
            sid,
            size,
            children: Vec::new(),
            children_map: HashMap::new(),
            sect_chain: None,
            used: false,
            minifat,
        })
    }
}

fn convert_clsid(clsid: [u8; 16]) -> Result<String, DecryptError> {
    if clsid == ZERO_CLSID {
        return Ok(String::new());
    }
    // return (("%08X-%04X-%04X-%02X%02X-" + "%02X" * 6) % ((i32(clsid, 0), i16(clsid, 4), i16(clsid, 6)) + tuple(map(i8, clsid[8:16]))))
    Err(Unimplemented("Non-zero CLSID".to_owned()))
}

fn sect_to_array(sect: &[u8]) -> &[u32] {
    cast_slice(sect)
}
