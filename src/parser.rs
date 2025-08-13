use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::display::{
    BMPFormat, GIFFormat, JPEGFormat, PNGFormat, display_bmp, display_exif, display_gif,
    display_png, display_sof,
};

pub fn parse_jpeg(data: &[u8]) -> Result<(), String> {
    let mut cursor = Cursor::new(data);

    let mut soi = [0u8; 2];
    cursor
        .read_exact(&mut soi)
        .map_err(|_| "Unable to read SOI")?;
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
            if let Err(err) = display_exif(&mut cursor, segment_size) {
                return Err(err);
            }
        } else if marker == 0xC0 || marker == 0xC2 {
            let jpeg_format = {
                let mut precision = [0u8; 1];
                cursor.read_exact(&mut precision).unwrap();
                let precision = precision[0];

                let mut dimensions = [0u8; 4];
                cursor.read_exact(&mut dimensions).unwrap();
                let height = u16::from_be_bytes([dimensions[0], dimensions[1]]);
                let width = u16::from_be_bytes([dimensions[2], dimensions[3]]);

                let mut components_count = [0u8; 1];
                cursor.read_exact(&mut components_count).unwrap();
                let components = components_count[0];

                let color_space: String;
                if marker == 0xC0 {
                    color_space = "YUV".to_string();
                } else {
                    color_space = "YCCK".to_string();
                }

                JPEGFormat {
                    precision,
                    width,
                    height,
                    color_space,
                    components,
                }
            };
            if let Err(err) = display_sof(jpeg_format, marker) {
                return Err(err);
            }
            break;
        } else {
            cursor
                .seek(SeekFrom::Current((segment_size - 2) as i64))
                .unwrap();
        }
    }

    Ok(())
}

pub fn parse_png(data: &[u8]) -> Result<(), String> {
    if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("Not a valid PNG file".into());
    }

    let mut cursor = Cursor::new(data);
    cursor.seek(SeekFrom::Start(8)).unwrap();

    loop {
        let mut length_bytes = [0u8; 4];
        if cursor.read_exact(&mut length_bytes).is_err() {
            break;
        }
        let length = u32::from_be_bytes(length_bytes);

        let mut chunk_type_bytes = [0u8; 4];
        cursor.read_exact(&mut chunk_type_bytes).unwrap();
        let chunk_type =
            std::str::from_utf8(&chunk_type_bytes).map_err(|_| "Invalid chunk type")?;

        let mut chunk_data = vec![0u8; length as usize];
        cursor.read_exact(&mut chunk_data).unwrap();

        let mut crc_bytes = [0u8; 4];
        cursor.read_exact(&mut crc_bytes).unwrap();

        if chunk_type == "IHDR" {
            if length != 13 {
                return Err("Invalid IHDR length".into());
            }

            let png_info = PNGFormat {
                width: u32::from_be_bytes(chunk_data[0..4].try_into().unwrap()),
                height: u32::from_be_bytes(chunk_data[4..8].try_into().unwrap()),
                bit_depth: chunk_data[8],
                color_type: chunk_data[9],
                compression: chunk_data[10],
                filter: chunk_data[11],
                interlace: chunk_data[12],
            };

            let _ = display_png(png_info);
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

    let gif_format = GIFFormat {
        width,
        height,
        global_color_table_flag,
        color_resolution,
        sort_flag,
        size_of_global_color_table,
        background_color_index,
        pixel_aspect_ratio,
    };

    let _ = display_gif(gif_format)?;

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

    let bmp_format = BMPFormat {
        pixel_data_offset,
        dib_header_size,
        width,
        height,
        planes,
        bits_per_pixel,
    };

    let _ = display_bmp(bmp_format)?;

    Ok(())
}
