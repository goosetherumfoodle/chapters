use std::env;
use std::fs;
use std::char;
use std::slice::Iter;
use memmap2::Mmap;
use crate::Frame::{StandardTextFrame, UserDefinedTextFrame, TableOfContentsFrame, ChapterFrame, SkipFrame};
use crate::Encoding::{ISO_8859_1, UTF_16};
use crate::TagParseErr::InvalidHeader;
use crate::ByteOrder::{LittleEndian, BigEndian};

const FRAME_HEADER_SIZE: usize = 10;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
}

#[derive(Debug)]
#[derive(PartialEq)]
enum TagParseErr {
    InvalidHeader(usize, [u8; 4]),
}

#[derive(PartialEq)]
#[derive(Debug)]
pub enum Encoding {
    ISO_8859_1,
    UTF_16(Option<ByteOrder>),
}

/*
  <Header for 'User defined text information frame', ID: "TXXX">
     Text encoding     $xx
     Description       <text string according to encoding> $00 (00)
     Value             <text string according to encoding>

<ID3v2.3 or ID3v2.4 frame header, ID: "CTOC"> (10 bytes)
    Element ID <text string> $00
    Flags %000000ab
    Entry count $xx (8-bit unsigned int)
    <Child Element ID list>
    <Optional embedded sub-frames>
*/

#[derive(Debug)]
#[derive(PartialEq)]
pub enum Frame {
    StandardTextFrame  {
        id: String,
        encoding: Encoding,
        size: usize,
        flags: [u8; 2],
        content: String,
    },
    UserDefinedTextFrame {
        id: String,
        size: usize,
        encoding: Encoding,
        content: String,
        field: String,
    },
    // https://id3.org/id3v2-chapters-1.0
    TableOfContentsFrame {
        elem_id: String,
        size: usize,
        flags: [u8; 2],
        table_of_content_flags: u8,
        children: Vec<String>,
        subframes: Vec<Frame>,
    },
    ChapterFrame {
        elem_id: String,
        millis_to_start: usize,
        millis_to_end: usize,
        start_byte_offset: usize,
        trailing_byte_offset: usize,
        subframes: Vec<Frame>,
    },
    SkipFrame {
        id: String,
        size: usize,
    },
}

fn get_synchsafe_32(big_endian: [u8; 4]) -> u32 {
    let first = (big_endian[0] as u32) << 21;
    let second = (big_endian[1] as u32) << 14;
    let third = (big_endian[2] as u32) << 7;
    let fourth = big_endian[3] as u32;
    first | second | third | fourth
}

fn get_standard_32(big_endian: [u8; 4]) -> u32 {
    let first = (big_endian[0] as u32) << 24;
    let second = (big_endian[1] as u32) << 16;
    let third = (big_endian[2] as u32) << 8;
    let fourth = big_endian[3] as u32;
    first | second | third | fourth
}


/*
  <Header for 'User defined text information frame', ID: "TXXX">
     Text encoding     $xx
     Description       <text string according to encoding> $00 (00)
     Value             <text string according to encoding>
*/
fn user_defined_text_frame(offset: usize, id: String, bytes: &Mmap) -> (usize, Frame) {
    let encoding = encoding((offset+FRAME_HEADER_SIZE) as usize, &bytes);
// TODO: use logic from std frame?
    let mut encountered_stop = false;
    let mut reading_field = true;
    let mut i = offset + FRAME_HEADER_SIZE;
    let mut content_8: Vec<u8> = Vec::new();
    let mut field_8: Vec<u8> = Vec::new();
    let mut content_16: Vec<u16> = Vec::new();
    let mut field_16: Vec<u16> = Vec::new();
    let field: String;
    let content: String;

    match encoding {
        ISO_8859_1 => {
            i += 1;
            while !encountered_stop {
                if *bytes.get(i).unwrap() == 0 && !reading_field {
                    encountered_stop = true;
                } else if *bytes.get(i).unwrap() == 0 {
                    reading_field = false;
                } else if reading_field {
                    field_8.push(*bytes.get(i).unwrap());
                } else {
                    content_8.push(*bytes.get(i).unwrap());
                }
                i += 1;
            }
            field = stringify(field_8.iter());
            content = stringify(content_8.iter());
        },
        UTF_16(ref byte_order) => {
            i += 3;
            // print_bytes(offset, bytes, 0, 40);
            while !encountered_stop {
                let is_null = (*bytes.get(i).unwrap() | *bytes.get(i+1).unwrap()) == 0;
                if is_null && !reading_field {
                    encountered_stop = true;
                } else if is_null {
                    if decode_bom(*bytes.get(i+2).unwrap(), *bytes.get(i+3).unwrap()).is_some() {
                        //skip BOM
                        i += 2;
                    }
                    reading_field = false;
                } else if reading_field {
                    field_16.push(join_bytes(&byte_order, *bytes.get(i).unwrap(), *bytes.get(i+1).unwrap()));
                } else {
                    content_16.push(join_bytes(&byte_order, *bytes.get(i).unwrap(), *bytes.get(i+1).unwrap()));
                }
                i += 2;
            }
            field = char::decode_utf16(field_16).map(|c| c.unwrap() ).collect();
            content = char::decode_utf16(content_16).map(|c| c.unwrap() ).collect();
        },
    }

    // FRAME SIZE
    let size = get_frame_size(offset, bytes);

    let new_offset = offset + FRAME_HEADER_SIZE + size;
    (
        new_offset,
        UserDefinedTextFrame {
            id: id,
            size: size,
            encoding: encoding,
            field: field.to_string(),
            content: content.to_string(),
        }
    )
}

fn get_frame_size(offset: usize, bytes: &Mmap) -> usize {
    let mut size_bytes: [u8; 4] = [0; 4];
    for i in (offset + 4)..=(offset + 7) {
        size_bytes[(i - (offset + 4)) as usize] = *bytes.get(i as usize).unwrap();
    }
    let size = get_standard_32(size_bytes);
    if size > 1_000_000 {
        println!("WARNING: frame size is suspiciously large: {size}");
        print_bytes(offset, bytes, 50, 100);
    }
    size as usize
}

fn get_frame_flags(offset: usize, bytes: &Mmap) -> [u8; 2] {
    let mut flags: [u8; 2] = [0; 2];
    for i in (offset + 8)..=(offset + 9) {
        flags[(i - (offset+8)) as usize] = *bytes.get(i as usize).unwrap();
    }
    flags
}

fn get_8(at: usize, bytes: &Mmap) -> u8 {
    *bytes.get(at).expect("ERROR: Requested bytes beyond file size")
}

fn get_16(order: &Option<ByteOrder>, at: usize, bytes: &Mmap) -> u16 {
    join_bytes(order, get_8(at, bytes), get_8(at + 1, bytes))
}

fn get_32(order: &Option<ByteOrder>, at: usize, bytes: &Mmap) -> u32 {
    join_bytes(order, get_8(at, bytes), get_8(at + 1, bytes)) as u32 +
        join_bytes(order, get_8(at + 3, bytes), get_8(at + 4, bytes)) as u32
}

fn encoding(enc_offset: usize, bytes: &Mmap) -> Encoding {
    match get_8(enc_offset, bytes) {
        0 => ISO_8859_1,
        _ => UTF_16(decode_bom(get_8(enc_offset+1, bytes), get_8(enc_offset+2, bytes))),
    }
}

    /* see https://en.wikipedia.org/wiki/Byte_order_mark#UTF-16 */
fn decode_bom(fst: u8, snd: u8) -> Option<ByteOrder> {
    if fst == 0xFE && snd == 0xFF {
        Some(BigEndian)
    } else if fst == 0xFF && snd == 0xFE {
        Some(LittleEndian)
    } else {
        None
    }
}

fn join_bytes(order: &Option<ByteOrder>, fst: u8, snd: u8) -> u16 {
    match order {
        Some(LittleEndian) => {
            fst as u16 + ((snd as u16) << 8)
        },
        _ => {
            snd as u16 + ((fst as u16) << 8)
        },
    }
}

// TODO: use size to stop
fn get_frame_text_content(frame_start_offset: usize, size: usize, bytes: &Mmap) -> (Encoding, String) {
    let encoding = encoding((frame_start_offset + FRAME_HEADER_SIZE) as usize, bytes);
    let mut i: usize = (frame_start_offset + FRAME_HEADER_SIZE) as usize;
    let mut encountered_stop = false;
    let mut content_8: Vec<u8> = Vec::new();
    let mut content_16: Vec<u16> = Vec::new();
    let content: String;

    match encoding {
        ISO_8859_1 => {
            i += 1;
            while !encountered_stop {
                let byte = get_8(i, bytes);
                if byte == 0 {
                    encountered_stop = true;
                } else {
                    content_8.push(byte);
                }
                i += 1;
            }
            content = stringify(content_8.iter());
        },

        UTF_16(ref byte_order) =>{
            i += 3;
            while !encountered_stop {
                let word = get_16(byte_order, i, bytes);
                let is_null = word == 0;
                if is_null {
                    encountered_stop = true;
                }  else {
                    content_16.push(word);
                }
                i += 2;
            }
            content = char::decode_utf16(content_16).map(|c| c.unwrap() ).collect();
        },
    }

    (encoding, content)
}

fn standard_text_frame(offset: usize, id: String, bytes: &Mmap) -> (usize, Frame) {
    let flags = get_frame_flags(offset, bytes);
    let size = get_frame_size(offset, bytes);
    let (encoding, content) = get_frame_text_content(offset, size, bytes);
    let new_offset = offset + FRAME_HEADER_SIZE + size;

    (
        new_offset,
        StandardTextFrame {
            id,
            encoding,
            size,
            flags,
            content,
        }
    )
}

fn skip_frame(init_offset: usize, id: String, bytes: &Mmap) -> (usize, Frame) {
    let size = get_frame_size(init_offset, bytes);
    let new_offset = init_offset + FRAME_HEADER_SIZE + size;
    if size > 1_000_000 {
        print_bytes(init_offset, bytes, 17, 30);
        println!("size {:032b}", size);
        println!("id: {id}");
        panic!("SKIP FRAME SIZE IS SUSPICIOUSLY LARGE");
    }

    (
        new_offset,
        SkipFrame {
            id: id,
            size: size,
        }
    )
}

fn stringify(bytes: Iter<u8>) -> String {
    bytes.map(|n| char::from(*n)).collect()
}

fn is_user_defined_text_frame_id(id: &str) -> bool {
    match id {
        "TXXX" => true,
        _ => false,
    }
}

fn is_text_frame_id(id: &str) -> bool {
    if id.starts_with("T") {
        true
    } else {
        false
    }
}

fn is_table_of_contents_id(id: &str) -> bool {
    match id {
        "CTOC" => true,
        _      => false,
    }
}

fn frame_end_offset(init_offset: usize, frame_size: usize) -> usize {
    init_offset + frame_size + FRAME_HEADER_SIZE
}

fn table_of_contents_frame(init_offset: usize, id: String, bytes: &Mmap) -> (usize, Frame) {
    let flags = get_frame_flags(init_offset, bytes);
    let size = get_frame_size(init_offset, bytes);
    let end_of_frame = frame_end_offset(init_offset, size);

    // ELEMENT ID
    let mut offset: usize = init_offset + FRAME_HEADER_SIZE as usize;
    let mut elem_id_bytes: Vec<u8> = Vec::new();
    let mut id_terminated = false;
    while !id_terminated {
        let byte = get_8(offset, bytes);
        if byte == 0 {
            id_terminated = true;
        } else {
            elem_id_bytes.push(byte);
        }
        offset += 1;
    }

    let ctoc_flags = get_8(offset, bytes);
    offset += 1;

    let child_entries = get_8(offset, bytes);
    offset += 1;

    let mut children = Vec::with_capacity(child_entries as usize);
    while offset < end_of_frame {
        let mut children_found = 0;
        while children_found < child_entries {
            // N CHILD ELEMENTS
            let mut child_terminated = false;
            let mut child_bytes: Vec<u8> = Vec::new();
            while !child_terminated {
                let byte = get_8(offset, bytes);
                if byte == 0 {
                    child_terminated = true;
                } else {
                    child_bytes.push(byte);
                }
                offset += 1;
            }
            children.push(String::from_utf8(child_bytes).expect("UNABLED TO PARSE CTOC BYTES"));
            children_found += 1;
        }

    // TODO: SUBFRAMES
    }

    if offset < end_of_frame  {
        print_bytes(offset, &bytes, 100, 100);
        panic!("CTOC CHILDREN FINISHED BEFORE END OF FRAME");
    }

    (
        offset,
        TableOfContentsFrame {
            elem_id: stringify(elem_id_bytes.iter()),
            size: size,
            flags: flags,
            table_of_content_flags: ctoc_flags,
            children: children,
            subframes: Vec::new(),

        }
    )
}

fn chapter_frame(init_offset: usize, id: String, bytes: &Mmap) -> (usize, Frame) {
    let flags = get_frame_flags(init_offset, bytes);
    let size = get_frame_size(init_offset, bytes);
    if size > 1_000_000 {
        print_bytes(init_offset, bytes, 17, 30);
        println!("size {:?}", size);
        println!("flags {:?}", flags);
        println!("id: {id}");
        panic!("CHAPTER FRAME SIZE IS SUSPICIOUSLY LARGE");
    }
    let end_of_frame = init_offset + FRAME_HEADER_SIZE + size;

    // ELEMENT ID
    let mut offset = init_offset + FRAME_HEADER_SIZE;
    let mut elem_id_bytes: Vec<u8> = Vec::new();
    let mut id_terminated = false;
    while !id_terminated {
        let byte = get_8(offset, bytes);
        if byte == 0 {
            id_terminated = true;
        } else {
            elem_id_bytes.push(byte);
        }
        offset += 1;
    }

    let millis_to_start = get_32(&Some(BigEndian), offset, bytes);
    offset += 4;

    let millis_to_end = get_32(&Some(BigEndian), offset, bytes);
    offset += 4;

    let start_byte_offset = get_32(&Some(BigEndian), offset, bytes);
    offset += 4;

    let trailing_byte_offset = get_32(&Some(BigEndian), offset, bytes);
    offset += 4;

    let mut subframes = Vec::new();
    while offset < (end_of_frame as usize) {
        let (new_offset, frame) = get_next_frame(offset, bytes).expect("Subframe expected");
        offset = new_offset;
        subframes.push(frame);
    }

    (
        offset,
        ChapterFrame {
            elem_id: stringify(elem_id_bytes.iter()),
            millis_to_start: millis_to_start as usize,
            millis_to_end: millis_to_end as usize,
            start_byte_offset: start_byte_offset as usize,
            trailing_byte_offset: trailing_byte_offset as usize,
            subframes: subframes,
        }
    )
}

fn is_chap_frame(id: &str) -> bool {
    match id {
        "CHAP" => true,
        _      => false,
    }
}

fn get_next_frame(offset: usize, bytes: &Mmap) -> Result<(usize, Frame), TagParseErr> {
    let mut bid: [u8; 4] = [0; 4];
    for i in offset..=offset + 3 {
        bid[(i - offset) as usize] = get_8(i as usize, bytes);
    }
    let id: String = bid.iter().map(|n| {
        let c = char::from(*n);
        if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return Err(InvalidHeader(offset, bid));
        }
        Ok(char::from(*n))
    }).collect::<Result<String, TagParseErr>>()?;

    if is_user_defined_text_frame_id(&id[..]) {
        Ok(user_defined_text_frame(offset, id, bytes))
    } else if is_text_frame_id(&id[..]) {
        Ok(standard_text_frame(offset, id, bytes))
    } else if is_table_of_contents_id(&id[..]) {
        Ok(table_of_contents_frame(offset, id, bytes))
    } else if is_chap_frame(&id[..]) {
        Ok(chapter_frame(offset, id, bytes))
    } else {
        Ok(skip_frame(offset, id, bytes))
    }
}

fn print_bytes(offset: usize, bytes: &Mmap, top: usize, bottom: usize) {
    for i in offset-top..=offset+bottom {
        if i == offset {
            println!("{i}: {:08b};\t{} <===============================", get_8(i as usize, bytes), char::from(get_8(i as usize, bytes)));
        } else {
            println!("{i}: {:08b};\t{}", get_8(i as usize, bytes), char::from(get_8(i as usize, bytes)));
        }
    }
    println!("OFFSET: {offset}");
}

fn try_skip_invalids(init_offset: usize, bytes: &Mmap, tag_size: u32) -> Option<usize> {
    let mut offset = init_offset;
    while offset < (tag_size - 4) as usize {
        let byte: u8 = get_8(offset as usize, bytes);
        if byte == 0 {
            offset += 4;
        } else {
            let c = char::from(byte);
            if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
                return None;
            } else {
                let mut first_valid = None;
                let offset = offset - 3;
                for i in 0..=3_usize {
                    let byte: u8 = get_8(offset+i as usize, bytes);
                    let c = char::from(byte);
                    if first_valid.is_none() && (c.is_ascii_uppercase() || c.is_ascii_digit()) {
                        first_valid = Some(offset+i);
                    }
                }

                let mut valid_id = true;
                for i in 0..=4 {
                    let byte: u8 = *bytes.get(first_valid.unwrap() as usize+i).unwrap();
                    let c = char::from(byte);
                    if valid_id && !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
                        valid_id = false;
                    }
                }
                if valid_id {
                    return Some(first_valid.unwrap().try_into().unwrap());
                } else {
                    return None
                }
            }
        }
    }
    return None
}

fn main() {
    let file_location = env::args().nth(1).expect("REQUIRES 1 ARGUMENT: MP3 FILE PATH");
    let bytes = fs::File::open(file_location.clone())
        .and_then(|f| unsafe { Mmap::map(&f) } )
        .expect(&format!("couldn't find file {file_location}")[..]);

    let mut tag_name = Vec::new();
    for i in 0..=2 {
        tag_name.push(get_8(i, &bytes));
    }
    println!("VERSION: {}.{}", get_8(3, &bytes), get_8(4, &bytes));
    if get_8(3, &bytes) != 3 || get_8(4, &bytes) != 0 {
        panic!("THIS PROGRAM CURRENTLY ONLY HANDLES ID3V2.3.0");
    }
    println!("TAG FLAGS: {:?}", get_8(5, &bytes));

    /*
    $49      44       33       yy       yy
    01001001 01000100 00110011 00000011 00000000

    xx       zz       zz       zz       zz
    00000000 00000000 00011000 01101100 01001101
     */

    let tag_size: u32 = get_synchsafe_32([*bytes.get(6).unwrap(), *bytes.get(7).unwrap(), *bytes.get(8).unwrap(), *bytes.get(9).unwrap()]);
    println!("tag_size:\t{} bytes", tag_size);

    let mut frames: Vec<Frame> = Vec::new();
    let mut off = FRAME_HEADER_SIZE;
    while off < tag_size as usize {
        match get_next_frame(off, &bytes) {
            Err(InvalidHeader(bad_off, bad_id)) => {
                println!("WARNING: expected a valid header at offset: {bad_off}, found: {:?}", bad_id);
                match try_skip_invalids(bad_off as usize, &bytes, tag_size) {
                    Some(good_off) => {off = good_off},
                    None => {
                        off = tag_size as usize;
                        println!("WARNING: FRAMES DIDN'T FILL OUT TAG LENGTH" );
                    },
                }
            },
            Ok((next_off, frame)) => {
                if next_off == off {
                    print_bytes(off, &bytes, 100, 200);
                    panic!("CYCLE");
                }
                off = next_off as usize;
                frames.push(frame);
            },
        }
    }

    for frame in frames {
        match frame {
            StandardTextFrame{id, size, flags, content, encoding, ..} => {
                println!("STANDARD TEXT FRAME: {id}");
                println!("frame size:\t{:?}", size);
                println!("encoding: {:?}", encoding);
                println!("flag1: {:08b}", flags[0]);
                println!("flag2: {:08b}", flags[1]);
                println!("content: {:?}", content);
            },
            UserDefinedTextFrame {id, encoding, field, content, size, ..} => {
                println!("USER DEFINED TEXT FRAME: {id}");
                println!("frame size:\t{:?}", size);
                println!("encoding: {:?}", encoding);
                println!("field: {field}");
                println!("content: {content}");
            },
            TableOfContentsFrame {elem_id, size, flags, table_of_content_flags, children, subframes, ..} => {
                println!("TABLE OF CONTENTS FRAME: {elem_id}");
                println!("frame size:\t{:?}", size);
                println!("flags: {:?}", flags);
                println!("TOC flags: {:?}", table_of_content_flags);
                println!("children: {:?}", children);
                println!("subframes: {:?}", subframes);
            },
            ChapterFrame {elem_id, millis_to_end, millis_to_start, start_byte_offset, trailing_byte_offset, subframes} => {
                println!("CHAPTER FRAME: {elem_id}");
                println!("millis to start: {:?}", millis_to_start);
                println!("millis to end: {:?}", millis_to_end);
                println!("start offset: {:?}", start_byte_offset);
                println!("trailing offset: {:?}", trailing_byte_offset);
                println!("subframes: {:?}", subframes);
            },
            SkipFrame {id, size} => println!("SKIP FRAME: {id}: {size} bytes"),
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memmap2::{Mmap, MmapMut};
    use std::io::Write;

    #[test]
    fn text_frame_utf16_le() {
        let input = mem_map(vec![
            0b01010100, 0b01000001, 0b01001100, 0b01000010, 0b00000000, 0b00000000,
            0b00000000, 0b00111001, 0b00000000, 0b00000000, 0b00000001, 0b11111111,
            0b11111110, 0b01010010, 0b00000000, 0b01100001, 0b00000000, 0b01101110,
            0b00000000, 0b01100100, 0b00000000, 0b01101111, 0b00000000, 0b01101101,
            0b00000000, 0b00100000, 0b00000000, 0b01001101, 0b00000000, 0b01101111,
            0b00000000, 0b01110100, 0b00000000, 0b01101001, 0b00000000, 0b01101111,
            0b00000000, 0b01101110, 0b00000000, 0b00100000, 0b00000000, 0b01001111,
            0b00000000, 0b01100110, 0b00000000, 0b00100000, 0b00000000, 0b01010000,
            0b00000000, 0b01100001, 0b00000000, 0b01110010, 0b00000000, 0b01110100,
            0b00000000, 0b01101001, 0b00000000, 0b01100011, 0b00000000, 0b01101100,
            0b00000000, 0b01100101, 0b00000000, 0b01110011, 0b00000000, 0b00000000,
            0b00000000,
        ]);

        let result = get_next_frame(0, &input);

        let expected = StandardTextFrame {
            id: "TALB".to_string(),
            encoding: UTF_16(Some(LittleEndian)),
            size: 57,
            flags: [0, 0],
            content: "Random Motion Of Particles".to_string(),
        };
        assert_eq!(result, Ok((67, expected)));
    }

    #[test]
    fn custom_text_ascii() {
        let input = mem_map(vec![
            0b01010100, 0b01011000, 0b01011000, 0b01011000, 0b00000000,
            0b00000000, 0b00000000, 0b00010001, 0b00000000, 0b00000000, 0b00000000,
            0b01111001, 0b01100101, 0b01100001, 0b01110010, 0b00000000, 0b00110010,
            0b00110000, 0b00110010, 0b00110000, 0b00101101, 0b00110000, 0b00111000,
            0b00101101, 0b00110001, 0b00111000, 0b00000000, 0b01010100, 0b01011000,
        ]);

        let result = get_next_frame(0, &input);

        let expected = UserDefinedTextFrame {
            id: "TXXX".to_string(),
            encoding: ISO_8859_1,
            size: 17,
            content: "2020-08-18".to_string(),
            field: "year".to_string(),
        };
        assert_eq!(result, Ok((27, expected)));
    }

    #[test]
    fn custom_text_utf16() {
        let input = mem_map(vec![
            0b01010100, 0b01011000, 0b01011000, 0b01011000, 0b00000000,
            0b00000000, 0b00010001, 0b10010001, 0b00000000, 0b00000000, 0b00000001,
            0b11111111, 0b11111110, 0b01100100, 0b00000000, 0b01100101, 0b00000000,
            0b01110011, 0b00000000, 0b01100011, 0b00000000, 0b01110010, 0b00000000,
            0b01101001, 0b00000000, 0b01110000, 0b00000000, 0b01110100, 0b00000000,
            0b01101001, 0b00000000, 0b01101111, 0b00000000, 0b01101110, 0b00000000,
            0b00000000, 0b00000000, 0b11111111, 0b11111110, 0b01010100, 0b00000000,
            0b01101000, 0b00000000, 0b01100101, 0b00000000, 0b00100000, 0b00000000,
            0b01100010, 0b00000000, 0b01101111, 0b00000000, 0b01101100, 0b00000000,
            0b01100100, 0b00000000, 0b00100000, 0b00000000, 0b01100001, 0b00000000,
            0b01101110, 0b00000000, 0b01100100, 0b00000000, 0b00100000, 0b00000000,
            0b01100010, 0b00000000, 0b01101111, 0b00000000, 0b01110101, 0b00000000,
            0b01101110, 0b00000000, 0b01100100, 0b00000000, 0b01101100, 0b00000000,
            0b01100101, 0b00000000, 0b01110011, 0b00000000, 0b01110011, 0b00000000,
            0b01101100, 0b00000000, 0b01111001, 0b00000000, 0b00100000, 0b00000000,
            0b01101111, 0b00000000, 0b01110010, 0b00000000, 0b01101001, 0b00000000,
            0b01100111, 0b00000000, 0b01101001, 0b00000000, 0b01101110, 0b00000000,
            0b01100001, 0b00000000, 0b01101100, 0b00000000, 0b00100000, 0b00000000,
            0b01100100, 0b00000000, 0b01100101, 0b00000000, 0b01100010, 0b00000000,
            0b01110101, 0b00000000, 0b01110100, 0b00000000, 0b00000000, 0b00000000,
        ]);

        let result = get_next_frame(0, &input);

        let expected = UserDefinedTextFrame {
            id: "TXXX".to_string(),
            encoding: UTF_16(Some(LittleEndian)),
            size: 4497,
            content: "The bold and boundlessly original debut".to_string(),
            field: "description".to_string(),
        };
        assert_eq!(result, Ok((4507, expected)));
    }


    #[test]
    fn text_frame_ascii() {
        let input = mem_map(vec![
                0b01010100, 0b01000011, 0b01001111, 0b01001110, 0b00000000,
                0b00000000, 0b00000000, 0b00001011, 0b00000000, 0b00000000,
                0b00000000, 0b01000001, 0b01110101, 0b01100100, 0b01101001,
                0b01101111, 0b01100010, 0b01101111, 0b01101111, 0b01101011,
                0b00000000,
        ]);

        let result = get_next_frame(0, &input);

        let expected = StandardTextFrame {
            id: "TCON".to_string(),
            flags: [0,0],
            encoding: ISO_8859_1,
            size: 11,
            content: "Audiobook".to_string(),
        };
        assert_eq!(result, Ok((21, expected)));
    }

    fn mem_map(bytes: Vec<u8>) -> Mmap {
        let mut mmap = MmapMut::map_anon(bytes.len()).unwrap();
        (&mut mmap[..]).write(&bytes[..]).unwrap();
        mmap.make_read_only().unwrap()
    }
}
