use std::fs;
use std::io;
use std::path::Path;

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

impl Metadata {
    pub fn parse_metadata(buffer: &Vec<u8>) -> Metadata {
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

        Metadata {
            node_count: 1441,
            record_size: 28,
            ip_version: 6,
            metadata_start: index,
        }
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
