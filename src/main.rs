use std::env;
use std::fs;
use std::char;
use std::slice::Iter;
use memmap2::Mmap;
use crate::Frame::{StandardTextFrame, UserDefinedTextFrame, TableOfContentsFrame, ChapterFrame, SkipFrame};
use crate::Encoding::{ISO_8859_1, UTF_16_BOM};

// TODO: just read in id3 tag bytes, not whole file

const FILE_LOCATION: &str = "./Antkind.mp3";

#[derive(PartialEq)]
#[derive(Debug)]
pub enum Encoding {
    ISO_8859_1,
    UTF_16_BOM,
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
pub enum Frame {
    StandardTextFrame  {
        id: String,
        size: u32,
        flags: [u8; 2],
        content: String,
    },
    UserDefinedTextFrame {
        id: String,
        size: u32,
        encoding: Encoding,
        content: String,
        field: String,
    },
    // https://id3.org/id3v2-chapters-1.0
    TableOfContentsFrame {
        elem_id: String,
        size: u32,
        flags: [u8; 2],
        table_of_content_flags: u8,
        children: Vec<String>,
        subframes: Vec<Frame>,
    },
    ChapterFrame {
        elem_id: String,
        millis_to_start: u32,
        millis_to_end: u32,
        start_byte_offset: u32,
        trailing_byte_offset: u32,
        subframes: Vec<Frame>,
    },
    SkipFrame {
        id: String,
        size: u32,
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
fn user_defined_text_frame(offset: u32, id: String, bytes: &Mmap) -> (u32, Frame) {
    let encoding_byte = *bytes.get((offset+10) as usize).unwrap();

    let encoding = match encoding_byte {
        0 => ISO_8859_1,
        1 => UTF_16_BOM,
        _ => panic!("unhandled encoding byte"),
    };
    // let groups: Vec<&[u8]> = bytes.get((offset+5) as usize..).unwrap().splitn(3, |n| *n == 0_u8).collect();
    let mut encountered_stop = false;
    let mut reading_field = true;
    let mut i: usize = (offset+11) as usize;
    let mut content_8: Vec<u8> = Vec::new();
    let mut field_8: Vec<u8> = Vec::new();
    let mut content_16: Vec<u16> = Vec::new();
    let mut field_16: Vec<u16> = Vec::new();
    let mut field_str = "".to_string();
    let mut content_str = "".to_string();

    if encoding == ISO_8859_1 {
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
        field_str = stringify(field_8.iter());
        content_str = stringify(content_8.iter());
    } else if encoding == UTF_16_BOM {
        // TODO check bom
        i += 2;
        while !encountered_stop {
            let is_null = (*bytes.get(i).unwrap() | *bytes.get(i+1).unwrap()) == 0;
            if is_null && !reading_field {
                encountered_stop = true;
            } else if is_null {
                reading_field = false;
            } else if reading_field {
                field_16.push(*bytes.get(i).unwrap() as u16 | ((*bytes.get(i+1).unwrap() as u16) << 8));
            } else {
                content_16.push(*bytes.get(i).unwrap() as u16 | ((*bytes.get(i+1).unwrap() as u16) << 8));
            }
            i += 2;
        }
        field_str = char::decode_utf16(field_16).map(|c| c.unwrap() ).collect();
        content_str = char::decode_utf16(content_16).map(|c| c.unwrap() ).collect();
    }

    // FRAME SIZE
    let mut bsize: [u8; 4] = [0; 4];
    for i in (offset + 4)..=(offset + 7) {
        bsize[(i - (offset+4)) as usize] = *bytes.get(i as usize).unwrap();
    }

    let size = get_standard_32(bsize);

    let new_offset = offset + 10 + (size as u32);
    (
        new_offset,
        UserDefinedTextFrame {
            id: id,
            size: size,
            encoding: encoding,
            field: field_str.to_string(),
            content: content_str.to_string(),
        }
    )
}

fn standard_text_frame(offset: u32, id: String, bytes: &Mmap) -> (u32, Frame) {
    let mut bsize: [u8; 4] = [0; 4];
    let mut flags: [u8; 2] = [0; 2];
    for i in (offset + 4)..=(offset + 7) {
        bsize[(i - (offset+4)) as usize] = *bytes.get(i as usize).unwrap();
    }

    for i in (offset + 8)..=(offset + 9) {
        flags[(i - (offset+8)) as usize] = *bytes.get(i as usize).unwrap();
    }

    let size = get_standard_32(bsize);
    if size > 1_000_000 {
        print_bytes(offset, bytes, 17, 30);
        println!("size {:?}", size);
        println!("flags {:?}", flags);
        println!("id: {id}");
        panic!("STANDARD TEXT FRAME SIZE IS SUSPICIOUSLY LARGE");
    }

    let mut content: Vec<u8> = Vec::new();
    for i in (offset + 10)..(offset + 10 + (size as u32)) {
        content.push(*bytes.get(i as usize).unwrap());
    }

    let new_offset = offset + 10 + (size as u32);

    (
        new_offset,
        StandardTextFrame {
            id: id,
            size: size,
            flags: flags,
            content: stringify(content.iter()),
        }
    )
}

fn skip_frame(init_offset: u32, id: String, bytes: &Mmap) -> (u32, Frame) {
    let mut bsize: [u8; 4] = [0; 4];
    for i in (init_offset + 4)..=(init_offset + 7) {
        bsize[(i - (init_offset+4)) as usize] = *bytes.get(i as usize).unwrap();
    }

    let size = get_standard_32(bsize);
    let new_offset = init_offset + 10 + (size as u32);
    if size > 1_000_000 {
        print_bytes(init_offset, bytes, 17, 30);
        println!("bsize: {:?}", bsize.iter().map(|b| format!("{:08b}", b)).collect::<Vec<String>>());
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

fn table_of_contents_frame(init_offset: u32, id: String, bytes: &Mmap) -> (u32, Frame) {
    let offset: usize = init_offset as usize;
    let mut bsize: [u8; 4] = [0; 4];
    let mut flags: [u8; 2] = [0; 2];
    for i in (offset + 4)..=(offset + 7) {
        bsize[(i - (offset+4)) as usize] = *bytes.get(i as usize).unwrap();
    }

    for i in (offset + 8)..=(offset + 9) {
        flags[(i - (offset+8)) as usize] = *bytes.get(i as usize).unwrap();
    }

    let size = get_standard_32(bsize);
    if size > 1_000_000 {
        print_bytes(offset as u32, bytes, 17, 30);
        println!("size {:?}", size);
        println!("flags {:?}", flags);
        println!("id: {id}");
        panic!("STANDARD TEXT FRAME SIZE IS SUSPICIOUSLY LARGE");
    }
    let end_of_frame = init_offset + 10 + size;

    // ELEMENT ID
    let mut offset: usize = offset + 10;
    let mut elem_id_bytes: Vec<u8> = Vec::new();
    let mut id_terminated = false;
    while !id_terminated {
        let byte = &bytes.get(offset).unwrap();
        if **byte == 0 {
            id_terminated = true;
        } else {
            elem_id_bytes.push(*bytes.get(offset).unwrap());
        }
        offset += 1;
    }

    // CTOC FLAGS
    let ctoc_flags = *bytes.get(offset).unwrap();
    offset += 1;

    // ENTRY COUNT
    let child_entries = *bytes.get(offset).unwrap();
    offset += 1;

    let mut children = Vec::with_capacity(child_entries as usize);
    while offset < end_of_frame as usize{
        let mut children_found = 0;
        while children_found < child_entries {
            // N CHILD ELEMENTS
            let mut child_terminated = false;
            let mut child_bytes: Vec<u8> = Vec::new();
            while !child_terminated {
                let b = &bytes.get(offset).unwrap();
                if **b == 0 {
                    child_terminated = true;
                } else {
                    child_bytes.push(*bytes.get(offset).unwrap());
                }
                offset += 1;
            }
            children.push(String::from_utf8(child_bytes).expect("UNABLED TO PARSE CTOC BYTES"));
            children_found += 1;
        }

    // TODO: SUBFRAMES
    }

    if init_offset + 10 + size > offset as u32 {
        print_bytes(offset as u32, &bytes, 100, 100);
        panic!("CTOC CHILDREN FINISHED BEFORE END OF FRAME");
    }

    (
        offset as u32,
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

fn chapter_frame(init_offset: u32, id: String, bytes: &Mmap) -> (u32, Frame) {
    let offset: usize = init_offset as usize;
    let mut bsize: [u8; 4] = [0; 4];
    let mut flags: [u8; 2] = [0; 2];
    for i in (offset + 4)..=(offset + 7) {
        bsize[(i - (offset+4)) as usize] = *bytes.get(i as usize).unwrap();
    }

    for i in (offset + 8)..=(offset + 9) {
        flags[(i - (offset+8)) as usize] = *bytes.get(i as usize).unwrap();
    }

    let size = get_standard_32(bsize);
    if size > 1_000_000 {
        print_bytes(offset as u32, bytes, 17, 30);
        println!("size {:?}", size);
        println!("flags {:?}", flags);
        println!("id: {id}");
        panic!("CHAPTER FRAME SIZE IS SUSPICIOUSLY LARGE");
    }
    let end_of_frame = init_offset + 10 + size;

    // ELEMENT ID
    let mut offset: usize = offset + 10;
    let mut elem_id_bytes: Vec<u8> = Vec::new();
    let mut id_terminated = false;
    while !id_terminated {
        let byte = &bytes.get(offset).unwrap();
        if **byte == 0 {
            id_terminated = true;
        } else {
            elem_id_bytes.push(*bytes.get(offset).unwrap());
        }
        offset += 1;
    }

    // START TIME
    let millis_to_start: u32 = get_standard_32([
        *bytes.get(offset).unwrap(),
        *bytes.get(offset+1).unwrap(),
        *bytes.get(offset+2).unwrap(),
        *bytes.get(offset+3).unwrap(),
    ]);
    offset += 4;

    // END TIME
    let millis_to_end: u32 = get_standard_32([
        *bytes.get(offset).unwrap(),
        *bytes.get(offset+1).unwrap(),
        *bytes.get(offset+2).unwrap(),
        *bytes.get(offset+3).unwrap(),
    ]);
    offset += 4;

    // START OFFSET
    let start_byte_offset: u32 = get_standard_32([
        *bytes.get(offset).unwrap(),
        *bytes.get(offset+1).unwrap(),
        *bytes.get(offset+2).unwrap(),
        *bytes.get(offset+3).unwrap(),
    ]);
    offset += 4;

    // END OFFSET
    let trailing_byte_offset: u32 = get_standard_32([
        *bytes.get(offset).unwrap(),
        *bytes.get(offset+1).unwrap(),
        *bytes.get(offset+2).unwrap(),
        *bytes.get(offset+3).unwrap(),
    ]);
    offset += 4;

    let mut subframes = Vec::new();
    while offset < (end_of_frame as usize) {
        let (new_offset, frame) = get_next_frame(offset as u32, bytes);
        offset = new_offset as usize;
        subframes.push(frame);
    }

    (
        offset as u32,
        ChapterFrame {
            elem_id: stringify(elem_id_bytes.iter()),
            millis_to_start: millis_to_start,
            millis_to_end: millis_to_end,
            start_byte_offset: start_byte_offset,
            trailing_byte_offset: trailing_byte_offset,
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



fn get_next_frame(offset: u32, bytes: &Mmap) -> (u32, Frame) {
    let mut bid: [u8; 4] = [0; 4];
    for i in offset..=offset + 3 {
        bid[(i - offset) as usize] = *bytes.get(i as usize).unwrap();
    }
    let id: String = bid.iter().map(|n| {
        let c = char::from(*n);
        if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
            print_bytes(offset, bytes, 100, 197_740);
            println!("bad char: {:?}", c);
            println!("id: {:?}", bid);
            panic!("INVALID ID");
        }
        char::from(*n)
    }).collect();
    if is_user_defined_text_frame_id(&id[..]) {
        user_defined_text_frame(offset, id, bytes)
    } else if is_text_frame_id(&id[..]) {
        standard_text_frame(offset, id, bytes)
    } else if is_table_of_contents_id(&id[..]) {
        table_of_contents_frame(offset, id, bytes)
    } else if is_chap_frame(&id[..]) {
        chapter_frame(offset, id, bytes)
    } else {
        skip_frame(offset, id, bytes)
    }
}

fn print_bytes(offset: u32, bytes: &Mmap, top: usize, bottom: usize) {
    let offset = offset as usize;
    for i in offset-top..=offset+bottom {
        if i == offset {
            // println!("{i}: {:08b};\t{} <===============================", bytes.get(i as usize).unwrap(), char::from(bytes.get(i as usize).unwrap())); TODO: FIX
        } else {
            // println!("{i}: {:08b};\t{}", bytes.get(i as usize).unwrap(), char::from(bytes.get(i as usize).unwrap())); TODO: FIX
        }
    }
    println!("OFFSET: {offset}");
}


fn main() {
    let file_location = env::args().nth(1).expect("REQUIRES 1 ARGUMENT: MP3 FILE PATH");
    let bytes = fs::File::open(file_location)
        .and_then(|f| unsafe { Mmap::map(&f) } )
        .expect(&format!("couldn't find file {FILE_LOCATION}")[..]);

    let mut tag_name = Vec::new();
    for i in 0..=2 {
        tag_name.push(*bytes.get(i).unwrap());
    }
    // println!("TAG: {:?}", String::from_utf8(tag_name)); TODO: fix
    println!("VERSION: {}.{}", *bytes.get(3).unwrap(), *bytes.get(4).unwrap());
    if *bytes.get(3).unwrap() != 3 || *bytes.get(4).unwrap() != 0 {
        panic!("THIS PROGRAM CURRENTLY ONLY HANDLES ID3V2.3.0");
    }
    println!("TAG FLAGS: {:?}", *bytes.get(5).unwrap());

    /*
    $49      44       33       yy       yy
    01001001 01000100 00110011 00000011 00000000

    xx       zz       zz       zz       zz
    00000000 00000000 00011000 01101100 01001101
     */

    let tag_size = get_synchsafe_32([*bytes.get(6).unwrap(), *bytes.get(7).unwrap(), *bytes.get(8).unwrap(), *bytes.get(9).unwrap()]);

    println!("tag_size:\t{:#032b}", tag_size);
    println!("tag_size:\t{} bytes", tag_size);

    let mut frames: Vec<Frame> = Vec::new();
    let mut off = 10;
    while off < tag_size {
        let (next_off, frame) = get_next_frame(off, &bytes);
        if next_off == off {
            print_bytes(off, &bytes, 100, 200);
            panic!("CYCLE");
        }
        off = next_off;
        frames.push(frame);
    }

    for frame in frames {
        match frame {
            StandardTextFrame{id, size, flags, content} => {
                println!("STANDARD TEXT FRAME");
                println!("id:\t{:?}", id);
                println!("frame size:\t{:?}", size);
                println!("flag1: {:08b}", flags[0]);
                println!("flag2: {:08b}", flags[1]);
                println!("content: {:?}", content);
            },
            UserDefinedTextFrame {id, encoding, field, content, size, ..} => {
                println!("USER DEFINED TEXT FRAME");
                println!("id: {id}");
                println!("frame size:\t{:?}", size);
                println!("encoding: {:?}", encoding);
                println!("field: {field}");
                println!("content: {content}");
            },
            TableOfContentsFrame {elem_id, size, flags, table_of_content_flags, children, subframes, ..} => {
                println!("TABLE OF CONTENTS FRAME");
                println!("id: {elem_id}");
                println!("frame size:\t{:?}", size);
                println!("flags: {:?}", flags);
                println!("TOC flags: {:?}", table_of_content_flags);
                println!("children: {:?}", children);
                println!("subframes: {:?}", subframes);
            },
            ChapterFrame {elem_id, millis_to_end, millis_to_start, start_byte_offset, trailing_byte_offset, subframes} => {
                println!("CHAPTER FRAME");
                println!("id: {elem_id}");
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
