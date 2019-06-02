#[macro_use]
extern crate criterion;

use criterion::Criterion;

use maxminddb::{Reader, ResultValue};
use std::collections::HashMap;
use std::net::IpAddr;

fn lookup_benchmark(c: &mut Criterion) {
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let fields: Vec<&str> = vec![
        "city.names.en",
        "country.names.en",
        "country.is_in_european_union",
    ];
    let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());

    c.bench_function("lookup city and country information", move |b| {
        b.iter(|| reader.lookup(ip, &fields, &mut result))
    });
}

fn lookup_benchmark_region(c: &mut Criterion) {
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let fields: Vec<&str> = vec![
        "city.names.en",
        "country.names.en",
        "subdivisions.0.names.en",
    ];
    let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());

    c.bench_function("lookup subdivisions", move |b| {
        b.iter(|| reader.lookup(ip, &fields, &mut result))
    });
}

criterion_group!(benches, lookup_benchmark, lookup_benchmark_region);
criterion_main!(benches);
