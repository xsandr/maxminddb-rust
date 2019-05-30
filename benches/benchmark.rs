#[macro_use]
extern crate criterion;

use criterion::Criterion;
use std::net::IpAddr;
use std::collections::HashMap;
use maxminddb::{Reader, ResultValue};


fn lookup_benchmark(c: &mut Criterion) {
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let reader = Reader::open("test_data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    let fields: Vec<&str> = vec!["city.names.en" , "country.names.en", "country.is_in_european_union"];
    let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());

    c.bench_function("lookup 3", move |b| b.iter(|| reader.lookup(ip, &fields, &mut result)));
}

criterion_group!(benches, lookup_benchmark);
criterion_main!(benches);
