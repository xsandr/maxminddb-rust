use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::str::from_utf8;

pub struct Metadata {
    pub node_count: u64,
    pub record_size: u64,
    pub ip_version: u64,
    pub metadata_start: usize,
}

// metadata section delimiter - xABxCDxEFMaxMind.com
const METADATA_DELIMETER: [u8; 14] = [
    0xAB, 0xCD, 0xEF, 0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D,
];

enum Type {
    Extended,
    Pointer,
    String,
    Double,
    Bytes,
    Uint16,
    Uint32,
    Map,
    Int32,
    Uint64,
    Uint128,
    Array,
    Container,
    EndMarker,
    Boolean,
    Float,
}

struct Decoder<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn move_caret(&mut self, n: usize) -> () {
        self.cursor += n
    }

    fn current_byte(&mut self) -> u8 {
        let current_byte = self.buffer[self.cursor];
        self.move_caret(1);
        current_byte
    }

    fn next_bytes(&mut self, size: usize) -> &[u8] {
        self.move_caret(size);
        &self.buffer[self.cursor - size..self.cursor]
    }

    fn decode_ctrl_byte(&mut self) -> (Type, usize) {
        let byte = self.current_byte();
        let data_type = match byte >> 5 {
            1 => Type::Pointer,
            2 => Type::String,
            3 => Type::Double,
            4 => Type::Bytes,
            5 => Type::Uint16,
            6 => Type::Uint32,
            7 => Type::Map,
            _ => panic!(""),
        };
        let size = (byte & 0x1F) as usize;
        (data_type, size)
    }

    fn decode_uint(&mut self) -> u64 {
        let (_, size) = self.decode_ctrl_byte();
        self.next_bytes(size)
            .as_ref()
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    }

    fn skip_value(&mut self) {
        let (data_type, size) = self.decode_ctrl_byte();
        match data_type {
            Type::String | Type::Double | Type::Bytes | Type::Uint16 | Type::Uint32 => {
                self.move_caret(size)
            }
            _ => {}
        }
    }

    pub fn decode_map(&mut self, fields: &Vec<&str>) -> HashMap<String, u64> {
        let mut result: HashMap<String, u64> = HashMap::with_capacity(fields.len());

        let (_, size) = self.decode_ctrl_byte();
        for _ in 0..size {
            let key = self.decode_string();
            if fields.contains(&key) {
                result.insert(String::from(key), self.decode_uint());
            } else {
                self.skip_value()
            }
        }
        result
    }

    fn decode_string(&mut self) -> &str {
        let (_data_type, size) = self.decode_ctrl_byte();
        let data = self.next_bytes(size);
        from_utf8(data).unwrap()
    }
}

impl Metadata {
    pub fn parse_metadata(buffer: &Vec<u8>) -> Metadata {
        let index = Metadata::get_metadata_block_offset(&buffer);

        let fields = vec!["node_count", "record_size", "ip_version"];
        let mut decoder = Decoder {
            buffer: &buffer[index..],
            cursor: 0,
        };
        let hm = decoder.decode_map(&fields);

        Metadata {
            node_count: hm["node_count"],
            record_size: hm["record_size"],
            ip_version: hm["ip_version"],
            metadata_start: index,
        }
    }

    fn get_metadata_block_offset(buffer: &Vec<u8>) -> usize {
        let mut cur = 13;
        let mut index = 0;
        for (i, &item) in buffer.iter().rev().enumerate() {
            if METADATA_DELIMETER[cur] != item {
                cur = 13;
            } else {
                cur -= 1;
            }
            if cur == 0 {
                index = buffer.len() - i - 2 + METADATA_DELIMETER.len();
                break;
            }
        }
        index
    }
}

pub struct Reader {
    pub metadata: Metadata,
    buffer: Vec<u8>,
}

impl Reader {
    pub fn open(filename: &str) -> io::Result<Reader> {
        let path = Path::new(filename);
        let buffer: Vec<u8> = fs::read(&path)?;
        let metadata = Metadata::parse_metadata(&buffer);

        Ok(Reader {
            metadata: metadata,
            buffer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_parsing() {
        let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        assert_eq!(reader.metadata.ip_version, 6);
        assert_eq!(reader.metadata.record_size, 28);
        assert_eq!(reader.metadata.metadata_start, 20560);
    }
}
