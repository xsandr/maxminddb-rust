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

impl Metadata {
    pub fn parse_metadata(buffer: &Vec<u8>) -> Metadata {
        let index = Metadata::get_metadata_block_offset(&buffer);

        let fields = vec!["node_count", "record_size", "ip_version"];
        let mut decoder = Decoder::new(&buffer[index..], 0);
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


// metadata section delimiter - xABxCDxEFMaxMind.com
const METADATA_DELIMETER: [u8; 14] = [
    0xAB, 0xCD, 0xEF, 0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D,
];

#[derive(Clone, Debug, PartialEq)]
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

// we use it as a HashMap values in our lookup results
pub enum ResultValue {
    StringValue(String),
    UintValue(u64),
    BooleanValue(bool),
}

struct Decoder<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(buffer: &'a [u8], cursor: usize) -> Self {
        Decoder { buffer, cursor }
    }

    fn move_caret(&mut self, n: usize) -> () {
        self.cursor += n
    }

    fn current_byte(&mut self) -> u8 {
        let current_byte = self.buffer[self.cursor];
        self.move_caret(1);
        current_byte
    }

    fn current_byte_u64(&mut self) -> u64 {
        let current_byte = self.buffer[self.cursor];
        self.move_caret(1);
        current_byte as u64
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
            0 => Type::Extended,
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
            _ => unreachable!(),
        };
        let size = match byte & 0x1F {
            size if size < 29 => size as u64,
            29 => 29 + self.decode_n_bytes_as_uint(1),
            30 => 285 + self.decode_n_bytes_as_uint(2),
            31 => 65821 + self.decode_n_bytes_as_uint(3),
            _ => unreachable!(),
        } as usize;
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
            Type::String
            | Type::Double
            | Type::Bytes
            | Type::Int32
            | Type::Uint16
            | Type::Uint32
            | Type::Uint64
            | Type::Uint128 => {
                self.move_caret(size);
            }
            Type::Pointer => {
                // as a side effect of pointer resolving we'll move the carret
                self.get_pointer_address();
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
            Type::Boolean => return,
            _ => unreachable!(),
        }
    }

    fn decode_map_recursively(
        &mut self,
        fields: &Vec<&str>,
        result: &mut HashMap<String, ResultValue>,
    ) -> () {
        let initial_offset = self.cursor;
        for &field in fields.iter() {
            self.cursor = initial_offset;
            self.find_field(field, field, result);
        }
    }

    fn find_field(
        &mut self,
        field: &str,
        parts: &str,
        result: &mut HashMap<String, ResultValue>,
    ) -> () {
        if parts.is_empty() {
            result.insert(String::from(field), self.decode_value());
            return;
        }
        let dot_index = match parts.find('.') {
            Some(value) => value,
            None => parts.len(),
        };
        let search_for = &parts[..dot_index];
        let next_parts = if dot_index == parts.len() {
            &parts[0..0]
        } else {
            &parts[dot_index + 1..]
        };

        let size = match self.decode_ctrl_byte() {
            (Type::Pointer, _) => {
                self.cursor = self.get_pointer_address();
                let (_, size) = self.decode_ctrl_byte();
                size
            }
            (_, size) => size,
        };

        for _ in 0..size {
            let key = self.decode_string();
            if key == search_for {
                return self.find_field(field, next_parts, result);
            } else {
                self.skip_value()
            }
        }
    }

    fn decode_value(&mut self) -> ResultValue {
        let (data_type, size) = self.decode_ctrl_byte();
        match data_type {
            Type::String => {
                let value = from_utf8(self.next_bytes(size)).unwrap();
                ResultValue::StringValue(String::from(value))
            }
            Type::Pointer => {
                self.cursor = self.get_pointer_address();
                self.decode_value()
            }
            Type::Boolean => ResultValue::BooleanValue(size == 1),
            _ => panic!("finish bloody decoding {:?}", data_type),
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
        let (data_type, size) = self.decode_ctrl_byte();
        match data_type {
            Type::String => {
                let data = self.next_bytes(size);
                from_utf8(data).unwrap()
            }
            Type::Pointer => {
                let pointer_offset = self.get_pointer_address();
                let byte = &self.buffer[pointer_offset];
                let size = match byte & 0x1F {
                    size if size < 29 => size as u64,
                    29 => 29 + self.decode_n_bytes_as_uint(1),
                    30 => 285 + self.decode_n_bytes_as_uint(2),
                    31 => 65821 + self.decode_n_bytes_as_uint(3),
                    _ => panic!("unreachable"),
                } as usize;

                let data = &self.buffer[pointer_offset + 1..pointer_offset + 1 + size];
                let parsed = from_utf8(data);
                parsed.expect("some result")
            }
            _ => panic!("tried to decode a string"),
        }
    }

    fn get_pointer_address(&mut self) -> usize {
        let current_byte = self.buffer[self.cursor - 1] as u64;
        let size = match current_byte & 0x18 >> 3 {
            1 => {
                2048 + (current_byte & 0x7) << 16
                    | self.current_byte_u64() << 8
                    | self.current_byte_u64()
            }
            2 => {
                526336 + (current_byte & 0x7) << 24
                    | self.current_byte_u64() << 16
                    | self.current_byte_u64() << 8
                    | self.current_byte_u64()
            }
            3 => {
                (self.current_byte_u64()) << 24
                    | self.current_byte_u64() << 16
                    | self.current_byte_u64() << 8
                    | self.current_byte_u64()
            }

            _ => ((current_byte & 0x7) << 8) + self.current_byte_u64(),
        };
        size as usize
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

    pub fn lookup(
        &self,
        ip: IpAddr,
        fields: &Vec<&str>,
        result: &mut HashMap<String, ResultValue>,
    ) -> () {
        let search_tree_size = (self.metadata.record_size / 4) * self.metadata.node_count + 16;
        let offset = self.find_ip_offset(ip);

        let mut decoder = Decoder::new(
            &self.buffer[search_tree_size as usize..],
            (offset - self.metadata.node_count - 16) as usize,
        );
        decoder.decode_map_recursively(fields, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup() {
        let ip: IpAddr = "81.2.69.160".parse().unwrap();
        let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
        let fields: Vec<&str> = vec![
            "city.names.en",
            "country.names.en",
            "country.is_in_european_union",
        ];
        let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());
        reader.lookup(ip, &fields, &mut result);

        let v = &result["country.names.en"];
        if let ResultValue::StringValue(value) = v {
            assert_eq!(value, &String::from("United Kingdom"));
        }

        let v = &result["city.names.en"];
        if let ResultValue::StringValue(value) = v {
            assert_eq!(value, &String::from("London"));
        }

    }

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
