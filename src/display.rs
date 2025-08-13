use std::{
    fs,
    io::{Cursor, Read},
    time::{SystemTime, UNIX_EPOCH},
};

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} o", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} Ko", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} Mo", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn display_file_info(path: &str) -> Result<(), String> {
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

    println!("File: {}", path);
    println!("File size: {} bytes ({})", size, format_size(size));
    println!("Created on: {}", created_fmt);
    println!("Modified on: {}", modified_fmt);
    Ok(())
}

fn print_ascii(
    name: &str,
    field_type: u16,
    count: u32,
    entry_offset: usize,
    value_offset: usize,
    tiff_data: &[u8],
) {
    let pos = if field_type == 2 && count <= 4 {
        entry_offset + 8
    } else {
        value_offset
    };
    if pos + count as usize <= tiff_data.len() {
        if let Ok(s) = std::str::from_utf8(&tiff_data[pos..pos + count as usize - 1]) {
            println!("{}: {}", name, s);
        }
    }
}

pub fn display_exif(cursor: &mut Cursor<&[u8]>, segment_size: u16) -> Result<(), String> {
    let mut exif_data = vec![0u8; (segment_size - 2) as usize];
    cursor.read_exact(&mut exif_data).unwrap();

    if exif_data.starts_with(b"Exif\0\0") {
        let tiff_data = &exif_data[6..];

        let le = &tiff_data[0..2] == b"II";
        let be = &tiff_data[0..2] == b"MM";
        if !le && !be {
            return Err("Invalid TIFF header".into());
        } else {
            let is_le = le;
            let read_u16 = |bytes: &[u8]| -> u16 {
                if is_le {
                    u16::from_le_bytes([bytes[0], bytes[1]])
                } else {
                    u16::from_be_bytes([bytes[0], bytes[1]])
                }
            };
            let read_u32 = |bytes: &[u8]| -> u32 {
                if is_le {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                }
            };

            let ifd0_offset = read_u32(&tiff_data[4..8]) as usize;

            let num_entries = read_u16(&tiff_data[ifd0_offset..ifd0_offset + 2]) as usize;

            for i in 0..num_entries {
                let entry_offset = ifd0_offset + 2 + i * 12;
                let tag = read_u16(&tiff_data[entry_offset..entry_offset + 2]);
                let field_type = read_u16(&tiff_data[entry_offset + 2..entry_offset + 4]);
                let count = read_u32(&tiff_data[entry_offset + 4..entry_offset + 8]);
                let value_or_offset = &tiff_data[entry_offset + 8..entry_offset + 12];

                let value_offset = read_u32(value_or_offset) as usize;

                match tag {
                    0x010F => print_ascii(
                        "Make",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    0x0110 => print_ascii(
                        "Model",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    0x0131 => print_ascii(
                        "Software",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    0x0132 => print_ascii(
                        "DateTime",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    0x013B => print_ascii(
                        "Artist",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    0x9003 => print_ascii(
                        "DateTimeOriginal",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    0x9004 => print_ascii(
                        "DateTimeDigitized",
                        field_type,
                        count,
                        entry_offset,
                        value_offset,
                        tiff_data,
                    ),
                    _ => {}
                }
            }
        }
    } else {
        return Err("Not a valid EXIF segment".into());
    }
    Ok(())
}

pub struct JPEGFormat {
    pub precision: u8,
    pub width: u16,
    pub height: u16,
    pub color_space: String,
    pub components: u8,
}

pub fn display_sof(jpeg_format: JPEGFormat, marker: u8) -> Result<(), String> {
    println!("Precision: {} bits", jpeg_format.precision);
    println!(
        "Dimensions: {} x {} px",
        jpeg_format.width, jpeg_format.height
    );
    println!("Color space: {}", jpeg_format.color_space);
    println!("Components: {}", jpeg_format.components);
    println!(
        "Compression: {}",
        if marker == 0xC0 {
            "Baseline DCT"
        } else {
            "Progressive DCT"
        }
    );
    Ok(())
}

pub struct PNGFormat {
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub color_type: u8,
    pub compression: u8,
    pub filter: u8,
    pub interlace: u8,
}

pub fn display_png(png_format: PNGFormat) -> Result<(), String> {
    println!("Width: {}", png_format.width);
    println!("Height: {}", png_format.height);
    println!("Bit depth: {}", png_format.bit_depth);
    println!("Color type: {}", png_format.color_type);
    println!("Compression method: {}", png_format.compression);
    println!("Filter method: {}", png_format.filter);
    println!("Interlace method: {}", png_format.interlace);

    Ok(())
}

pub struct GIFFormat {
    pub width: u16,
    pub height: u16,
    pub color_resolution: u8,
    pub background_color_index: u8,
    pub pixel_aspect_ratio: u8,
    pub global_color_table_flag: bool,
    pub sort_flag: bool,
    pub size_of_global_color_table: u32,
}

pub fn display_gif(gif_format: GIFFormat) -> Result<(), String> {
    println!(
        "Dimensions: {} x {} px",
        gif_format.width, gif_format.height
    );
    println!(
        "Global Color Table Flag: {}",
        gif_format.global_color_table_flag
    );
    println!(
        "Color Resolution: {} bits per primary color",
        gif_format.color_resolution
    );
    println!("Sort Flag: {}", gif_format.sort_flag);
    println!(
        "Size of Global Color Table: {}",
        gif_format.size_of_global_color_table
    );
    println!(
        "Background Color Index: {}",
        gif_format.background_color_index
    );
    println!("Pixel Aspect Ratio: {}", gif_format.pixel_aspect_ratio);

    Ok(())
}

pub struct BMPFormat {
    pub pixel_data_offset: u32,
    pub dib_header_size: u32,
    pub width: i32,
    pub height: i32,
    pub planes: u16,
    pub bits_per_pixel: u16,
}

pub fn display_bmp(bmp_format: BMPFormat) -> Result<(), String> {
    println!("Pixel data offset: {}", bmp_format.pixel_data_offset);
    println!("DIB header size: {}", bmp_format.dib_header_size);
    println!(
        "Dimensions: {} x {} px",
        bmp_format.width, bmp_format.height
    );
    println!("Planes: {}", bmp_format.planes);
    println!("Bits per pixel: {}", bmp_format.bits_per_pixel);
    println!(
        "Compression: {}",
        if bmp_format.dib_header_size == 40 {
            "BI_RGB"
        } else {
            "Unknown"
        }
    );
    println!(
        "Color table size: {}",
        if bmp_format.dib_header_size == 40 {
            "0"
        } else {
            "Unknown"
        }
    );
    Ok(())
}
