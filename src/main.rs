use docx::*;
use std::env;
use std::io::Cursor;

use office_crypto::decrypt_from_file;

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let decrypted = decrypt_from_file(filename, "testPassword");
    println!("decrypted len: {}", decrypted.len());

    let docx = DocxFile::from_reader(Cursor::new(decrypted)).unwrap();
    let docx = docx.parse().unwrap();
    for field in docx.document.body.content {
        match field {
            docx::document::BodyContent::Paragraph(para) => {
                for item in para.content {
                    match item {
                        document::ParagraphContent::Run(run) => {
                            for cont in run.content {
                                match cont {
                                    document::RunContent::Text(txt) => {
                                        println!("{}", txt.text);
                                    }
                                    _ => (),
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
}
