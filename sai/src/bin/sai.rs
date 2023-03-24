const VERSION: &'static str = env!("CARGO_PKG_VERSION");

use cesrox::primitives::CesrPrimitive;
use clap::{App, Arg};
use sai::derivation::SelfAddressingCode;
use std::{fs, str::FromStr};

fn main() {
    let matches = App::new("SAI")
        .version(VERSION)
        .subcommand(
            App::new("gen")
                .about("Generate Self-Addressing Identifier")
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .takes_value(true)
                        .required_unless_present("file")
                        .help("Source data against which we would like to calculate digest"),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .required_unless_present("data")
                        .takes_value(true)
                        .help(
                            "File from which we would like to read data against which we would like to calculate digest"),
                )
                .arg(
                    Arg::new("type")
                        .short('t')
                        .long("type")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "Derevation code for the digest, algorithm used for digest.
Supported codes:
   E - Blake3_256
   F - Blake2B256
   G - Blake2S256
   H - SHA3_256
   I - SHA2_256
   0D - Blake3_512
   0E - SHA3_512
   0F - Blake2B512
   0G - SHA2_512",
                        ),
                ),
        )
        .subcommand(
            App::new("verify")
                .about("Verify SAI with provided data")
                .arg(
                    Arg::new("sai")
                        .short('s')
                        .long("sai")
                        .takes_value(true)
                        .required(true)
                        .help("Digest against which we would like to verify the content"),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .takes_value(true)
                        .required(true)
                        .help("Source data against which we would like to verify given digest"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("gen") {
        let mut data = Vec::new();

        if matches.contains_id("data") {
            data.extend_from_slice(matches.value_of("data").unwrap().as_bytes());
        }

        if matches.contains_id("file") {
            let file_path = matches.value_of("file").unwrap();
            let file_data =
                fs::read_to_string(file_path).expect("Something went wrong reading the file");
            data.extend_from_slice(file_data.as_bytes())
        }
        let prefix_code = matches.value_of("type").unwrap();
        let sai = SelfAddressingCode::from_str(prefix_code).unwrap();
        let calculated_sai = sai.derive(&data).to_str();
        println!("{}", calculated_sai);
    }
    if let Some(matches) = matches.subcommand_matches("verify") {
        let data = matches.value_of("data").unwrap().as_bytes();
        let sai = matches.value_of("sai").unwrap();
        let prefix = SelfAddressingCode::from_str(sai).unwrap();
        let calculated_sai = prefix.derive(data).to_str();
        println!("{:?}", calculated_sai.eq(sai));
    }
}