#[macro_use]
extern crate bencher;

use bencher::Bencher;

use maxminddb::{Reader, ResultValue};
use std::collections::HashMap;
use std::net::IpAddr;

fn lookup_benchmark(b: &mut Bencher) {
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let fields: Vec<&str> = vec!["country.iso_code", "country.names.en", "city.names.en"];
    let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());

    b.iter(|| reader.lookup(ip, &fields, &mut result))
}

fn lookup_benchmark_region(b: &mut Bencher) {
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let fields: Vec<&str> = vec![
        "city.names.en",
        "country.names.en",
        "subdivisions.0.names.en",
    ];
    let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());

    b.iter(|| reader.lookup(ip, &fields, &mut result))
}

benchmark_group!(benches, lookup_benchmark, lookup_benchmark_region);
benchmark_main!(benches);
