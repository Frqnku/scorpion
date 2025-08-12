use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time::{UNIX_EPOCH, SystemTime};

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} o", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} Ko", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} Mo", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn print_file_info(path: &str) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Error getting metadata: {}", e))?;

    let size = metadata.len();
    let created = metadata.created().unwrap_or(SystemTime::UNIX_EPOCH);
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    let created_fmt = match created.duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let dt = chrono::DateTime::from_timestamp(dur.as_secs() as i64, 0).unwrap();
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        Err(_) => "Unknown".to_string(),
    };

    let modified_fmt = match modified.duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let dt = chrono::DateTime::from_timestamp(dur.as_secs() as i64, 0).unwrap();
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        Err(_) => "Unknown".to_string(),
    };

    println!("File : {}", path);
    println!("File size: {} bytes ({})", size, format_size(size));
    println!("Created on : {}", created_fmt);
    println!("Modified on : {}", modified_fmt);
    Ok(())
}

pub fn parse_jpeg(data: &[u8]) -> Result<(), String> {
    let mut cursor = Cursor::new(data);

    let mut soi = [0u8; 2];
    cursor.read_exact(&mut soi).map_err(|_| "Unable to read SOI")?;
    if soi != [0xFF, 0xD8] {
        return Err("Not a valid JPEG file".into());
    }

    loop {
        let mut byte = [0u8; 1];
        if cursor.read_exact(&mut byte).is_err() {
            break;
        }
        if byte[0] != 0xFF {
            continue;
        }

        let mut marker_byte = [0u8; 1];
        cursor.read_exact(&mut marker_byte).unwrap();
        let marker = marker_byte[0];

        if marker == 0xD9 {
            break;
        }

        let mut size_bytes = [0u8; 2];
        cursor.read_exact(&mut size_bytes).unwrap();
        let segment_size = u16::from_be_bytes(size_bytes);

        if marker == 0xE1 {
            let mut exif_data = vec![0u8; (segment_size - 2) as usize];
            cursor.read_exact(&mut exif_data).unwrap();

            if exif_data.starts_with(b"Exif\0\0") {
                println!("--- EXIF segment found ---");
                println!("Size segment EXIF : {} octets", segment_size);
                println!("EXIF header (hex) : {:02X?}", &exif_data[..16.min(exif_data.len())]);
                println!("--------------------------");
            } else {
                println!("Segment APP1 found, but no EXIF data");
            }
        } else if marker == 0xC0 || marker == 0xC2 {
            let mut sof_data = vec![0u8; (segment_size - 2) as usize];
            cursor.read_exact(&mut sof_data).unwrap();

            let precision = sof_data[0];
            let height = u16::from_be_bytes([sof_data[1], sof_data[2]]);
            let width = u16::from_be_bytes([sof_data[3], sof_data[4]]);
            let components = sof_data[5];

            println!("Precision: {} bits", precision);
            println!("Dimensions: {} x {} px", width, height);
            println!("Components: {}", components);
            println!("Compression: {}", if marker == 0xC0 { "Baseline DCT" } else { "Progressive DCT" });
            println!();
        
            println!("--------------------------");
            break;
        } else {
            cursor.seek(SeekFrom::Current((segment_size - 2) as i64)).unwrap();
        }
    }

    Ok(())
}

pub fn parse_png(data: &[u8]) -> Result<(), String> {
    if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("Not a valid PNG file".into());
    }

    let mut cursor = Cursor::new(data);
    cursor.seek(SeekFrom::Start(8)).unwrap(); // sauter signature

    loop {
        let mut length_bytes = [0u8; 4];
        if cursor.read_exact(&mut length_bytes).is_err() {
            break; // EOF
        }
        let length = u32::from_be_bytes(length_bytes);

        let mut chunk_type_bytes = [0u8; 4];
        cursor.read_exact(&mut chunk_type_bytes).unwrap();
        let chunk_type = std::str::from_utf8(&chunk_type_bytes).map_err(|_| "Invalid chunk type")?;

        let mut chunk_data = vec![0u8; length as usize];
        cursor.read_exact(&mut chunk_data).unwrap();

        // Lire CRC mais on ne vérifie pas ici
        let mut crc_bytes = [0u8; 4];
        cursor.read_exact(&mut crc_bytes).unwrap();

        if chunk_type == "IHDR" {
            if length != 13 {
                return Err("Invalid IHDR length".into());
            }
            let width = u32::from_be_bytes(chunk_data[0..4].try_into().unwrap());
            let height = u32::from_be_bytes(chunk_data[4..8].try_into().unwrap());
            let bit_depth = chunk_data[8];
            let color_type = chunk_data[9];
            let compression = chunk_data[10];
            let filter = chunk_data[11];
            let interlace = chunk_data[12];

            println!("Width: {}", width);
            println!("Height: {}", height);
            println!("Bit depth: {}", bit_depth);
            println!("Color type: {}", color_type);
            println!("Compression method: {}", compression);
            println!("Filter method: {}", filter);
            println!("Interlace method: {}", interlace);
            println!();
        
            println!("-----------------------------");
        }

        if chunk_type == "IEND" {
            break;
        }
    }

    Ok(())
}

pub fn parse_gif(data: &[u8]) -> Result<(), String> {
    if data.len() < 13 {
        return Err("Data too short to be a valid GIF".into());
    }

    if data.starts_with(b"GIF87a") {
        println!("Version: GIF87a");
    } else if data.starts_with(b"GIF89a") {
        println!("Version: GIF89a");
    } else {
        return Err("Not a valid GIF file".into());
    }

    let width = u16::from_le_bytes([data[6], data[7]]);
    let height = u16::from_le_bytes([data[8], data[9]]);

    let packed_fields = data[10];
    let global_color_table_flag = (packed_fields & 0b1000_0000) != 0;
    let color_resolution = ((packed_fields & 0b0111_0000) >> 4) + 1;
    let sort_flag = (packed_fields & 0b0000_1000) != 0;
    let size_of_global_color_table = 2u32.pow(((packed_fields & 0b0000_0111) + 1) as u32);

    let background_color_index = data[11];
    let pixel_aspect_ratio = data[12];

    println!("Dimensions: {} x {} px", width, height);
    println!("Global Color Table Flag: {}", global_color_table_flag);
    println!("Color Resolution: {} bits per primary color", color_resolution);
    println!("Sort Flag: {}", sort_flag);
    println!("Size of Global Color Table: {}", size_of_global_color_table);
    println!("Background Color Index: {}", background_color_index);
    println!("Pixel Aspect Ratio: {}", pixel_aspect_ratio);
    println!();
    println!("-----------------------");

    Ok(())
}


pub fn parse_bmp(data: &[u8]) -> Result<(), String> {
    if data.len() < 54 {
        return Err("Data too short to be a valid BMP".into());
    }
    if &data[0..2] != b"BM" {
        return Err("Not a valid BMP file".into());
    }

    let pixel_data_offset = u32::from_le_bytes(data[10..14].try_into().unwrap());

    let dib_header_size = u32::from_le_bytes(data[14..18].try_into().unwrap());
    if dib_header_size < 40 {
        return Err("Unsupported BMP DIB header size".into());
    }

    let width = i32::from_le_bytes(data[18..22].try_into().unwrap());

    let height = i32::from_le_bytes(data[22..26].try_into().unwrap());

    let planes = u16::from_le_bytes(data[26..28].try_into().unwrap());
    if planes != 1 {
        return Err("Invalid number of planes".into());
    }

    let bits_per_pixel = u16::from_le_bytes(data[28..30].try_into().unwrap());

    println!("Pixel data offset: {}", pixel_data_offset);
    println!("DIB header size: {}", dib_header_size);
    println!("Dimensions: {} x {} px", width, height);
    println!("Planes: {}", planes);
    println!("Bits per pixel: {}", bits_per_pixel);
    println!("Compression: {}", if dib_header_size == 40 { "BI_RGB" } else { "Unknown" });
    println!("Color table size: {}", if dib_header_size == 40 { "0" } else { "Unknown" });
    println!();
    println!("-----------------------");

    Ok(())
}