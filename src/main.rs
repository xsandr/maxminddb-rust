use maxminddb::*;

fn main() {
    let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    println!("Hello")
}