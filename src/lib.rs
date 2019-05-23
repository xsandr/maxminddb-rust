use std::path::Path;
use std::fs;
use std::io;

struct Metadata {
    NodeCount: u64,
    RecordSize: u64,
    IPVersion: u64,
}

impl Metadata {
    pub fn ParseMetadata(buffer: &Vec<u8>) -> Metadata {
        Metadata{NodeCount:1441, RecordSize:28, IPVersion:6}
    }
}

struct Reader {
    Metadata: Metadata,
    buffer: Vec<u8>,
}

impl Reader{
    pub fn Open(filename: &str) -> io::Result<Reader> {
        let path = Path::new(filename);
        let buffer: Vec<u8> = fs::read(&path)?;
        let metadata = Metadata::ParseMetadata(&buffer);

        Ok(Reader{Metadata: metadata, buffer})
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
