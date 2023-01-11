use bytemuck::cast_slice;
use derivative::Derivative;
use packed_struct::prelude::*;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::*;

// https://github.com/decalage2/olefile/blob/master/olefile/olefile.py#L207
const MAGIC: [u8; 8] = [208, 207, 17, 224, 161, 177, 26, 225];
const ZERO_CLSID: [u8; 16] = [0; 16];
const BYTE_ORDER: u16 = 65534;

const DIFSECT: u32 = 0xFFFF_FFFC;
const FATSECT: u32 = 0xFFFF_FFFD;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;

// const MAXREGSID: u32 = 0xFFFF_FFFA;
const NOSTREAM: u32 = 0xFFFF_FFFF;

const STGTY_EMPTY: u8 = 0;
const STGTY_STORAGE: u8 = 1;
const STGTY_STREAM: u8 = 2;
// const STGTY_LOCKBYTES: u8 = 3;
// const STGTY_PROPERTY: u8 = 4;
const STGTY_ROOT: u8 = 5;

const UNKNOWN_SIZE: u32 = 0x7FFF_FFFF;

// little-endian
#[derive(PackedStruct)]
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
    fn validate_header(&mut self) {
        assert_eq!(self.magic, MAGIC);
        assert_eq!(self.clsid, ZERO_CLSID);
        assert!(self.dll_version == 3 || self.dll_version == 4);
        assert_eq!(self.byte_order, BYTE_ORDER);
        assert!(self.sector_shift == 9 || self.sector_shift == 12);
        assert!(
            (self.dll_version == 3 && self.sector_shift == 9)
                || (self.dll_version == 4 && self.sector_shift == 12)
        );
        assert_eq!(self.mini_sector_shift, 6);
        assert_eq!(self.reserved1, 0);
        assert_eq!(self.reserved2, 0);
        assert!(self.dll_version == 4 || self.num_dir_sectors == 0);
        assert_eq!(self.transaction_signature_number, 0);
        // TODO set to 4096 if not already
        assert_eq!(self.mini_stream_cutoff_size, 4096);
    }
}

#[allow(dead_code)]
pub struct OleFile {
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
    pub fn new(raw: Vec<u8>) -> Self {
        // u32::MAX bytes = ~4.2GB which i can live with
        let filesize = raw.len() as u32;
        assert!(filesize > 76);

        let header: [u8; 76] = raw[..76].try_into().unwrap();
        let mut header = OleHeader::unpack(&header).unwrap();
        header.validate_header();

        let sector_size = u32::pow(2, header.sector_shift as u32);
        let mini_sector_size = u32::pow(2, header.mini_sector_shift as u32);
        let nb_sect = ((filesize + sector_size - 1) / sector_size) - 1;

        Self {
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
        }
    }

    pub fn from_file(filename: String) -> Self {
        let mut file = File::open(filename).unwrap();
        let mut raw: Vec<u8> = Vec::new();
        file.read_to_end(&mut raw).unwrap();

        return OleFile::new(raw);
    }

    pub fn init(&mut self) {
        self.check_duplicate_stream(self.header.first_dir_sector, false);
        if self.header.num_mini_fat_sectors > 0 {
            // [minifat: false] is not a mistake here
            self.check_duplicate_stream(self.header.first_mini_fat_sector, false);
        }
        if self.header.num_difat_sectors > 0 {
            self.check_duplicate_stream(self.header.first_difat_sector, false);
        }

        self.load_fat();
        self.load_directory(self.header.first_dir_sector);
    }

    fn check_duplicate_stream(&mut self, first_sect: u32, minifat: bool) {
        if minifat {
            assert!(!self.used_streams_minifat.contains(&first_sect));
            self.used_streams_minifat.push(first_sect);
        } else {
            if [DIFSECT, FATSECT, ENDOFCHAIN, FREESECT].contains(&first_sect) {
                return;
            }
            assert!(!self.used_streams_fat.contains(&first_sect));
            self.used_streams_fat.push(first_sect);
        }
    }

    fn load_fat_sect(&mut self, sect_start: usize, sect_end: usize) {
        let sect = &self.raw[sect_start..sect_end];
        let fat1: &[u32] = sect_to_array(sect);

        for isect in fat1 {
            // labeled as JYTHON-WORKAROUND in the olefile code
            // let isect = isect & 0xFFFFFFFF;
            let isect = *isect;
            if isect == ENDOFCHAIN || isect == FREESECT {
                break;
            }
            let start = (self.sector_size * (isect + 1)) as usize;
            let s = &self.raw[start..(start + self.sector_size as usize)];
            assert_eq!(s.len(), self.sector_size as usize);
            let next_fat = sect_to_array(s);
            self.fat.extend_from_slice(next_fat);
        }
    }

    fn load_fat(&mut self) {
        self.load_fat_sect(76, 512);
        if self.header.num_difat_sectors > 0 {
            assert!(self.header.num_fat_sectors > 109);
            assert!(self.header.first_difat_sector < self.nb_sect);
            // TODO finish
            panic!("unimplemented num_difat_sectors > 0");
        }

        if self.fat.len() as u32 > self.nb_sect {
            self.fat = self.fat[..self.nb_sect as usize].to_vec();
        }
    }

    fn load_directory(&mut self, sect: u32) {
        self.directory_fp = self.open_helper(sect, UNKNOWN_SIZE as u64, true);
        let max_entries = self.directory_fp.size / 128;
        // build direntries and figure out what struct type each is
        self.direntries = vec![OleDirentry::default(); max_entries as usize];
        self.load_direntry(0);
        self.build_storage_tree(self.root_sid);
    }

    fn load_direntry(&mut self, sid: usize) -> usize {
        assert!(sid < self.direntries.len());
        if self.direntries[sid].used {
            panic!("double reference for OLE stream/storage");
        } else {
            let start = sid * 128;
            let entry = &self.directory_fp.stream[start..(start + 128)];
            let direntry = OleDirentry::new(entry.try_into().unwrap(), sid, self);
            self.direntries[sid] = direntry;
            return sid;
        }
    }

    fn load_minifat(&mut self) {
        // MiniFAT is stored in a standard  sub-stream, pointed to by a header
        // field.
        // NOTE: there are two sizes to take into account for this stream:
        // 1) Stream size is calculated according to the number of sectors
        //    declared in the OLE header. This allocated stream may be more than
        //    needed to store the actual sector indexes.
        // (self.num_mini_fat_sectors is the number of sectors of size self.sector_size)
        let stream_size = (self.header.num_mini_fat_sectors * self.sector_size) as u64;
        // 2) Actually used size is calculated by dividing the MiniStream size
        //    (given by root entry size) by the size of mini sectors, *4 for
        //    32 bits indexes:
        let nb_minisectors = (self.direntries[self.root_sid].size + self.mini_sector_size as u64
            - 1)
            / self.mini_sector_size as u64;
        let _used_size = nb_minisectors * 4;

        // This is not really a problem, but may indicate a wrong implementation:
        // assert!(used_size <= stream_size);

        let s = self.open_helper(self.header.first_mini_fat_sector, stream_size, true);
        self.minifat = sect_to_array(&s.stream).to_vec();
        self.minifat = self.minifat[..nb_minisectors as usize].to_vec();
    }

    fn open_helper(&mut self, start: u32, size: u64, force_fat: bool) -> OleStream {
        if size < self.header.mini_stream_cutoff_size as u64 && !force_fat {
            if self.ministream.is_none() {
                self.load_minifat();
                let size_ministream = self.direntries[self.root_sid].size;

                self.ministream = Some(self.open_helper(
                    self.direntries[self.root_sid].packed.isect_start,
                    size_ministream,
                    true,
                ));
            }

            let mut olestream = OleStream::new(start, size, 0, self.mini_sector_size);
            olestream.init(&self.ministream.as_ref().unwrap().stream, &self.minifat);
            olestream
        } else {
            let mut olestream = OleStream::new(start, size, self.sector_size, self.sector_size);
            olestream.init(&self.raw, &self.fat);
            olestream
        }
    }

    fn build_storage_tree(&mut self, direntry_ind: usize) {
        let sid_child = self.direntries[direntry_ind].packed.sid_child;
        if sid_child != NOSTREAM {
            // Note from OpenOffice documentation: the safest way is to
            // recreate the tree because some implementations may store broken
            // red-black trees...
            self.append_children(direntry_ind, sid_child as usize);
        }
    }

    fn append_children(&mut self, parent_sid: usize, child_sid: usize) {
        if child_sid as u32 == NOSTREAM {
            return;
        }
        assert!(child_sid < self.direntries.len());

        self.load_direntry(child_sid);
        // now child is an OleDirentry at self.direntries[child_sid]
        // refer by index so borrow checker isnt mad
        assert!(!self.direntries[child_sid].used);

        self.direntries[child_sid].used = true;
        self.append_children(
            parent_sid,
            self.direntries[child_sid].packed.sid_left as usize,
        );
        let name_lower = self.direntries[child_sid].name.to_lowercase();

        assert!(!self.direntries[parent_sid]
            .children_map
            .contains_key(&name_lower));

        self.direntries[parent_sid].children.push(child_sid);
        self.direntries[parent_sid]
            .children_map
            .insert(name_lower, child_sid);

        self.append_children(
            parent_sid,
            self.direntries[child_sid].packed.sid_right as usize,
        );

        // println!(
        //     "{:?} children: {:?}",
        //     self.direntries[parent_sid].name, self.direntries[parent_sid].children_map
        // );

        self.build_storage_tree(child_sid);
    }

    // takes a path (e.g. [storage_1, storage_1.2, stream])
    fn open_stream(&mut self, path: Vec<String>) -> OleStream {
        // walk direntries red/black tree to find the right stream
        let mut node_sid = self.root_sid;
        for name in path {
            node_sid = self
                .direntries
                .iter()
                .position(|item| item.name.to_lowercase() == name.to_lowercase())
                .unwrap();
        }

        assert_eq!(self.direntries[node_sid].packed.entry_type, STGTY_STREAM);

        return self.open_helper(
            self.direntries[node_sid].packed.isect_start,
            self.direntries[node_sid].size,
            false,
        );
    }

    fn print(&self) {
        println!("--------------------------");
        println!("magic: {:?}", self.header.magic);
        println!("clsid: {:?}", self.header.clsid);
        println!("minor_version: {:?}", self.header.minor_version);
        println!("dll_version: {:?}", self.header.dll_version);
        println!("byte_order: {:?}", self.header.byte_order);
        println!("sector_shift: {:?}", self.header.sector_shift);
        println!("mini_sector_shift: {:?}", self.header.mini_sector_shift);
        println!("reserved1: {:?}", self.header.reserved1);
        println!("reserved2: {:?}", self.header.reserved2);
        println!("num_dir_sectors: {:?}", self.header.num_dir_sectors);
        println!("num_fat_sectors: {:?}", self.header.num_fat_sectors);
        println!("first_dir_sector: {:?}", self.header.first_dir_sector);
        println!(
            "transaction_signature_number: {:?}",
            self.header.transaction_signature_number
        );
        println!(
            "mini_stream_cutoff_size: {:?}",
            self.header.mini_stream_cutoff_size
        );
        println!(
            "first_mini_fat_sector: {:?}",
            self.header.first_mini_fat_sector
        );
        println!(
            "num_mini_fat_sectors: {:?}",
            self.header.num_mini_fat_sectors
        );
        println!("first_difat_sector: {:?}", self.header.first_difat_sector);
        println!("num_difat_sectors: {:?}", self.header.num_difat_sectors);

        println!();
        println!("sector_size: {:?}", self.sector_size);
        println!("mini_sector_size: {:?}", self.mini_sector_size);
        println!("nb_sect: {:?}", self.nb_sect);
        println!("used_streams_fat: {:?}", self.used_streams_fat);
        println!("used_streams_minifat: {:?}", self.used_streams_minifat);
        println!("--------------------------");
    }
}

#[derive(Default, Debug)]
pub struct OleStream {
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

    fn init(&mut self, raw: &[u8], fat: &Vec<u32>) {
        let mut unknown_size = false;
        let fat_len = fat.len() as u32;

        if self.size == UNKNOWN_SIZE as u64 {
            self.size = fat_len as u64 * self.sector_size as u64;
            unknown_size = true;
        }

        let nb_sectors = (self.size + (self.sector_size as u64 - 1)) / self.sector_size as u64;
        assert!(nb_sectors <= fat_len as u64);
        let mut sect = self.start;
        assert!(self.size != 0 || sect == ENDOFCHAIN);

        let mut data: Vec<u8> = Vec::new();
        for _ in 0..nb_sectors {
            if sect == ENDOFCHAIN {
                assert!(unknown_size);
                break;
            }
            assert!(sect < fat_len);
            let start = (self.offset + self.sector_size * sect) as usize;
            let sector_data = &raw[start..(start + self.sector_size as usize)];
            // TODO last sector might have less than 512/4k, so read less on index
            assert!(sector_data.len() == self.sector_size as usize || sect == (fat_len - 1));
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
            panic!("read less than expected");
        }

        self.stream = data;
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
pub struct OleDirentry {
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
    ) -> Self {
        let packed = OleDirentryPacked::unpack(&entry).unwrap();

        assert!([STGTY_ROOT, STGTY_STORAGE, STGTY_STREAM, STGTY_EMPTY].contains(&packed.entry_type));
        assert!(packed.entry_type != STGTY_ROOT || sid == 0);
        assert!(packed.entry_type == STGTY_ROOT || sid != 0);
        assert!(packed.name_length <= 64);

        let name_utf16 = &packed.name_raw[..(packed.name_length as usize - 2)];
        let name_utf16: &[u16] = cast_slice(name_utf16);
        let name = String::from_utf16(name_utf16).unwrap();

        let size = if olefile.sector_size == 512 {
            packed.size_low as u64
        } else {
            packed.size_low as u64 + ((packed.size_high as u64) << 32)
        };

        let clsid = convert_clsid(packed.clsid);

        println!(
            "Direntry name: {:?}, CLSID: {:?}, size: {:?}",
            name, clsid, size
        );
        println!(
            "size_low: {:?}, size_high: {:?}",
            packed.size_low, packed.size_high
        );

        assert!(packed.entry_type != STGTY_STORAGE || size == 0);

        let mut minifat = false;
        if [STGTY_ROOT, STGTY_STREAM].contains(&packed.entry_type) && size > 0 {
            if size < olefile.header.mini_stream_cutoff_size as u64
                && packed.entry_type == STGTY_STREAM
            {
                minifat = true;
            }
            olefile.check_duplicate_stream(packed.isect_start, minifat);
        }

        OleDirentry {
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
        }
    }
}

fn convert_clsid(clsid: [u8; 16]) -> String {
    if clsid == ZERO_CLSID {
        return String::new();
    }
    // return (("%08X-%04X-%04X-%02X%02X-" + "%02X" * 6) % ((i32(clsid, 0), i16(clsid, 4), i16(clsid, 6)) + tuple(map(i8, clsid[8:16]))))
    panic!("unimplemented convert_clsid");
}

fn sect_to_array(sect: &[u8]) -> &[u32] {
    cast_slice(sect)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let mut file = File::open(filename).unwrap();
    let mut raw: Vec<u8> = Vec::new();

    file.read_to_end(&mut raw).unwrap();
    println!("bytes read from {}: {:?}", filename, raw.len());

    let mut olefile = OleFile::new(raw);
    olefile.init();
    olefile.print();

    let encryption_info = olefile.open_stream(vec!["EncryptionInfo".to_owned()]);

    println!("EncryptionInfo len: {:?}", encryption_info.stream.len());
    for i in 0..100 {
        print!("{} ", encryption_info.stream[i]);
    }

    // impl _parseinfo and _parseagile to get crypto values and type
}
