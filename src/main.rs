use bytemuck::cast_slice;
use packed_struct::prelude::*;
use std::fs::File;
use std::io::prelude::*;

// https://github.com/decalage2/olefile/blob/master/olefile/olefile.py#L207
const MAGIC: [u8; 8] = [208, 207, 17, 224, 161, 177, 26, 225];
const CLSID: [u8; 16] = [0; 16];
const BYTE_ORDER: u16 = 65534;
const DIFSECT: u32 = 0xFFFFFFFC;
const FATSECT: u32 = 0xFFFFFFFD;
const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FREESECT: u32 = 0xFFFFFFFF;

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

#[allow(dead_code)]
pub struct OleFile {
    raw: Vec<u8>,
    header: OleHeader,
    sector_size: u32,
    mini_sector_size: u32,
    nb_sect: u32,
    used_streams_fat: Vec<u32>,
    used_streams_minifat: Vec<u32>,
    fat: Vec<u32>,
}

fn validate_header(header: &OleHeader) {
    assert_eq!(header.magic, MAGIC);
    assert_eq!(header.clsid, CLSID);
    assert!(header.dll_version == 3 || header.dll_version == 4);
    assert_eq!(header.byte_order, BYTE_ORDER);
    assert!(header.sector_shift == 9 || header.sector_shift == 12);
    assert!(
        (header.dll_version == 3 && header.sector_shift == 9)
            || (header.dll_version == 4 && header.sector_shift == 12)
    );
    assert_eq!(header.mini_sector_shift, 6);
    assert_eq!(header.reserved1, 0);
    assert_eq!(header.reserved2, 0);
    assert!(header.dll_version == 4 || header.num_dir_sectors == 0);
    assert_eq!(header.transaction_signature_number, 0);
    // TODO set to 4096 if not already
    assert_eq!(header.mini_stream_cutoff_size, 4096);
}

fn check_duplicate_stream(file: &mut OleFile, first_sect: u32, minifat: bool) {
    if minifat {
        assert!(!file.used_streams_minifat.contains(&first_sect));
        file.used_streams_minifat.push(first_sect);
    } else {
        if [DIFSECT, FATSECT, ENDOFCHAIN, FREESECT].contains(&first_sect) {
            return;
        }
        assert!(!file.used_streams_fat.contains(&first_sect));
        file.used_streams_fat.push(first_sect);
    }
}

fn sect_to_array(sect: &[u8]) -> &[u32] {
    cast_slice(sect)
}

fn load_fat_sect(file: &mut OleFile, sect_start: usize, sect_end: usize) {
    let sect = &file.raw[sect_start..sect_end];
    let fat1: &[u32] = sect_to_array(sect);

    for isect in fat1 {
        let isect = isect & 0xFFFFFFFF;
        if isect == ENDOFCHAIN || isect == FREESECT {
            break;
        }
        let start = (file.sector_size * (isect + 1)) as usize;
        let s = &file.raw[start..(start + file.sector_size as usize)];
        assert_eq!(s.len(), file.sector_size as usize);
        let next_fat = sect_to_array(s);
        file.fat.extend_from_slice(&next_fat);
    }
}

fn load_fat(file: &mut OleFile) {
    load_fat_sect(file, 76, 512);
    println!("loaded fat len: {:?}", file.fat.len());
    if file.header.num_difat_sectors != 0 {
        assert!(file.header.num_fat_sectors > 109);
        assert!(file.header.first_difat_sector < file.nb_sect);
        // TODO finish
        assert!(1 == 0);
    }
}

// fn open_stream_help(file: &mut OleFile, sect: u32, force_fat: bool) -> OleStream {}

// fn load_directory(file: &mut OleFile, sect: u32) {
//     let directory_fp = open_stream_help(file, sect, true);
// }

fn main() {
    let filename = "testFile.docx";
    // let filename = "../../roml/22_8_august.docx";
    let mut file = File::open(filename).unwrap();
    let mut raw: Vec<u8> = Vec::new();

    file.read_to_end(&mut raw).unwrap();
    let filesize: u64 = raw.len() as u64;
    println!("bytes read from {}: {:?}", filename, filesize);
    println!("{:?}...", &raw[..100]);

    let header: [u8; 76] = raw[..76].try_into().unwrap();
    let header = OleHeader::unpack(&header).unwrap();

    println!("magic: {:?}", header.magic);
    println!("clsid: {:?}", header.clsid);
    println!("minor_version: {:?}", header.minor_version);
    println!("dll_version: {:?}", header.dll_version);
    println!("byte_order: {:?}", header.byte_order);
    println!("sector_shift: {:?}", header.sector_shift);
    println!("mini_sector_shift: {:?}", header.mini_sector_shift);
    println!("reserved1: {:?}", header.reserved1);
    println!("reserved2: {:?}", header.reserved2);
    println!("num_dir_sectors: {:?}", header.num_dir_sectors);
    println!("num_fat_sectors: {:?}", header.num_fat_sectors);
    println!("first_dir_sector: {:?}", header.first_dir_sector);
    println!(
        "transaction_signature_number: {:?}",
        header.transaction_signature_number
    );
    println!(
        "mini_stream_cutoff_size: {:?}",
        header.mini_stream_cutoff_size
    );
    println!("first_mini_fat_sector: {:?}", header.first_mini_fat_sector);
    println!("num_mini_fat_sectors: {:?}", header.num_mini_fat_sectors);
    println!("first_difat_sector: {:?}", header.first_difat_sector);
    println!("num_difat_sectors: {:?}", header.num_difat_sectors);

    validate_header(&header);

    let sector_size = u32::pow(2, header.sector_shift as u32);
    let mini_sector_size = u32::pow(2, header.mini_sector_shift as u32);
    let nb_sect = ((filesize as u32 + sector_size - 1) / sector_size) - 1;

    let mut olefile = OleFile {
        raw,
        header,
        sector_size,
        mini_sector_size,
        nb_sect,
        used_streams_fat: Vec::new(),
        used_streams_minifat: Vec::new(),
        fat: Vec::new(),
    };

    let first_dir_sector = olefile.header.first_dir_sector;
    check_duplicate_stream(&mut olefile, first_dir_sector, false);
    if olefile.header.num_mini_fat_sectors > 0 {
        let first_mini_fat_sector = olefile.header.first_mini_fat_sector;
        check_duplicate_stream(&mut olefile, first_mini_fat_sector, false);
    }
    if olefile.header.num_difat_sectors > 0 {
        let first_difat_sector = olefile.header.first_difat_sector;
        check_duplicate_stream(&mut olefile, first_difat_sector, false);
    }

    println!();
    println!("sector_size: {:?}", olefile.sector_size);
    println!("mini_sector_size: {:?}", olefile.mini_sector_size);
    println!("nb_sect: {:?}", olefile.nb_sect);
    println!("used_streams_fat: {:?}", olefile.used_streams_fat);
    println!("used_streams_minifat: {:?}", olefile.used_streams_minifat);

    load_fat(&mut olefile);
    // load_directory(&mut olefile, first_dir_sector);

    // impl _parseinfo and _parseagile to get crypto values and type
}
