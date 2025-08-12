use std::fs;
mod parser;


#[derive(Debug)]
enum ImageFormat {
    JPEG,
    PNG,
    GIF,
    BMP,
    Unknown,
}

fn detect_format(data: &[u8]) -> ImageFormat {
    if data.starts_with(&[0xFF, 0xD8]) {
        ImageFormat::JPEG
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        ImageFormat::PNG
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        ImageFormat::GIF
    } else if data.starts_with(b"BM") {
        ImageFormat::BMP
    } else {
        ImageFormat::Unknown
    }
}

fn main() {

    if std::env::args().len() < 2 {
        eprintln!("Usage: {} <image_file1> <image_file2> ...", std::env::args().next().unwrap());
        return;
    }

    println!("Scorpion - Image Metadata Parser");
    println!("=============================");
    println!("Processing files...");
    println!();

    for filename in std::env::args().skip(1) {
        if let Err(e) = parser::print_file_info(&filename) {
            eprintln!("{}", e);
            continue;
        }

        match fs::read(&filename) {
            Ok(data) => {
                match detect_format(&data) {
                    ImageFormat::JPEG => { if let Err(e) = parser::parse_jpeg(&data) { eprintln!("{}", e); } }
                    ImageFormat::PNG => { if let Err(e) = parser::parse_png(&data) { eprintln!("{}", e); } }
                    ImageFormat::GIF => { if let Err(e) = parser::parse_gif(&data) { eprintln!("{}", e); } }
                    ImageFormat::BMP => { if let Err(e) = parser::parse_bmp(&data) { eprintln!("{}", e); } }
                    ImageFormat::Unknown => println!("Format not handled: {}", filename),
                }
            }
            Err(e) => eprintln!("Error reading file {}: {}", filename, e),
        }
        println!();
    }
}
