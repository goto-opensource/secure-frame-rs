#![allow(unused_imports)]
use std::fs::{read_to_string, File};
use std::io::Write;

use toml_edit::{value, Document};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(crate_dir) = std::env::args().nth(1) {
        let cargo_toml_path = std::path::Path::new(&crate_dir).join("Cargo.toml");

        let cargo_toml = read_to_string(&cargo_toml_path)?;
        let mut doc = cargo_toml.parse::<Document>().expect("invalid doc");

        let next_version = std::env::var("NEXT_VERSION").expect("Env NEXT_VERSION not set");
        doc["package"]["version"] = value(next_version);
        println!("# updating cargo toml to");
        println!("{doc}");

        let mut file = File::create(&cargo_toml_path)?;
        file.write_all(doc.to_string().as_bytes())?;
    } else {
        println!("error: no crate path provided");
    }

    Ok(())
}
