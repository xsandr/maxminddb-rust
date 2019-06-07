# MaxMindDB Reader

The package provides a reader that can make a lookup into maxmind db file and fetch only requested fields using special dotted syntax(like a css selector)

## Example of usage
```rust
extern crate maxminddb;
use maxminddb::Reader;
use maxminddb::ResultValue;

use std::net::IpAddr;
use std::collections::HashMap;

fn main() {
    let ip: IpAddr = "81.2.69.160".parse().unwrap();
    let reader = Reader::open("path-to-maxmindb-file.mmdb").unwrap();

    let fields: Vec<&str> = vec![
        "city.names.en",
        "country.names.en",
        "subdivisions.0.names.en",
    ];
    let mut result: HashMap<String, ResultValue> = HashMap::with_capacity(fields.len());
    reader.lookup(ip, &fields, &mut result);
    if let ResultValue::String(v) = &result["subdivisions.0.names.en"] {
        println!("{}", v);
    }
}
```