use std::fs::File;
use std::io::*;
use std::path::PathBuf;

pub fn read_test_file(name: &str) -> Vec<u8> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests");
    dir.push("files");
    dir.push(name);
    let mut f = File::open(dir).unwrap();
    let mut data: Vec<u8> = Vec::new();
    f.read_to_end(&mut data).unwrap();

    data
}
