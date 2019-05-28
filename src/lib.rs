use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::str::from_utf8;

pub struct Metadata {
    pub node_count: u64,
    pub record_size: u64,
    pub ip_version: u64,
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
        let mut type_bits = byte >> 5;
        if type_bits == 0 {
            type_bits = 7 + self.current_byte();
        }
        let data_type = match type_bits {
            1 => Type::Pointer,
            2 => Type::String,
            3 => Type::Double,
            4 => Type::Bytes,
            5 => Type::Uint16,
            6 => Type::Uint32,
            7 => Type::Map,
            8 => Type::Int32,
            9 => Type::Uint64,
            10 => Type::Uint128,
            11 => Type::Array,
            12 => Type::Container,
            13 => Type::EndMarker,
            14 => Type::Boolean,
            15 => Type::Float,
            _ => panic!("Unknown type"),
        };
        let mut size = (byte & 0x1F) as usize;
        if size >= 29 {
            if size == 29 {
                size = 29 + self.decode_n_bytes_as_uint(1) as usize; // TODO extract it to the separate method
            } else if size == 30 {
                size = 285 + self.decode_n_bytes_as_uint(2) as usize;
            } else if size == 31 {
                size = 65821 + self.decode_n_bytes_as_uint(3) as usize;
            }
        }
        (data_type, size)
    }

    fn decode_n_bytes_as_uint(&mut self, n: usize) -> u64 {
        self.next_bytes(n)
            .iter()
            .fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
    }

    fn decode_uint(&mut self) -> u64 {
        let (_, size) = self.decode_ctrl_byte();
        self.decode_n_bytes_as_uint(size)
    }

    fn skip_value(&mut self) {
        let (data_type, size) = self.decode_ctrl_byte();
        match data_type {
            Type::Pointer
            | Type::String
            | Type::Double
            | Type::Bytes
            | Type::Int32
            | Type::Uint16
            | Type::Uint32
            | Type::Uint64
            | Type::Uint128 => {
                self.move_caret(size);
            }
            Type::Array => {
                for _ in 0..size {
                    self.skip_value();
                }
            }
            Type::Map => {
                for _ in 0..size {
                    self.skip_value();
                    self.skip_value();
                }
            }
            _ => panic!("Couldn't skip unknown datatype"),
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

    fn ip_to_bitmask(ip_address: IpAddr) -> (u32, usize) {
        let closure = |acc, &x| (acc << 8) | u32::from(x);
        let (bitmask, size) = match ip_address {
            IpAddr::V4(ip) => (ip.octets().iter().fold(0, closure), 32),
            IpAddr::V6(ip) => (ip.octets().iter().fold(0, closure), 128),
        };
        (bitmask, size)
    }

    fn find_ip_offset(&self, ip: IpAddr) -> u64 {
        let closure = |acc, &x| (acc << 8) | u64::from(x);
        let node_size_in_bytes = (self.metadata.record_size / 4) as usize;

        let (bitmask, size) = Reader::ip_to_bitmask(ip);
        let mut offset = match ip {
            IpAddr::V4(_) => 96 * node_size_in_bytes,
            IpAddr::V6(_) => 0,
        };

        let mut i = size - 1;
        while i >= 0 {
            let is_left = (bitmask >> i) & 1 == 0;
            let node = &self.buffer[offset..offset + node_size_in_bytes];

            // TODO let's make record_size enum
            let calculated_value = match self.metadata.record_size {
                28 => {
                    let middle_byte = self.buffer[offset + 3] as u64;
                    match is_left {
                        true => node[..3].iter().fold(middle_byte, closure),
                        false => node[4..].iter().fold(middle_byte, closure),
                    }
                }
                _ => {
                    let half: usize = node_size_in_bytes / 2;
                    match is_left {
                        true => node[..half].iter().fold(0, closure),
                        false => node[half..].iter().fold(0, closure),
                    }
                }
            };

            if calculated_value == self.metadata.node_count {
                // we didn't find the address for given IP address
                break;
            } else if calculated_value < self.metadata.node_count {
                offset = calculated_value as usize * node_size_in_bytes;
                i -= 1;
                continue;
            } else {
                return calculated_value;
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_parsing() {
        let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        assert_eq!(reader.metadata.node_count, 1431);
        assert_eq!(reader.metadata.ip_version, 6);
        assert_eq!(reader.metadata.record_size, 28);
    }

    #[test]
    fn find_ip_offset() {
        let ip: IpAddr = "81.2.69.160".parse().unwrap();
        let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let offset = reader.find_ip_offset(ip);
        assert_eq!(offset, 2589);
    }


    #[test]
    fn ip_bitmask() {
        let ip: IpAddr = "81.2.69.160".parse().unwrap();
        let (bitmask, size) = Reader::ip_to_bitmask(ip);
        assert_eq!(bitmask, 1359103392);
        assert_eq!(size, 32);
        // and ipv6
        let ip: IpAddr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
        let (bitmask, size) = Reader::ip_to_bitmask(ip);
        assert_eq!(bitmask, 57701172);
        assert_eq!(size, 128);
    }
}
