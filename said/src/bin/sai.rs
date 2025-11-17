const VERSION: &str = env!("CARGO_PKG_VERSION");

use cesrox::primitives::CesrPrimitive;
use clap::{Command, Arg};
use said::{derivation::HashFunction, SelfAddressingIdentifier};
use std::{fs::File, io::BufReader, str::FromStr};

fn main() {
    let matches = Command::new("SAI")
        .version(VERSION)
        .subcommand(
            Command::new("gen")
                .about("Generate Self-Addressing Identifier")
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .num_args(1)
                        .required_unless_present("file")
                        .help("Source data against which we would like to calculate digest"),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .required_unless_present("data")
                        .num_args(1)
                        .help(
                            "File from which we would like to read data against which we would like to calculate digest"),
                )
                .arg(
                    Arg::new("type")
                        .short('t')
                        .long("type")
                        .num_args(1)
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
            Command::new("verify")
                .about("Verify SAI with provided data")
                .arg(
                    Arg::new("sai")
                        .short('s')
                        .long("sai")
                        .num_args(1)
                        .required(true)
                        .help("Digest against which we would like to verify the content"),
                )
                .arg(
                    Arg::new("data")
                        .short('d')
                        .long("data")
                        .num_args(1)
                        .required(true)
                        .help("Source data against which we would like to verify given digest"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("gen") {
        let mut data = Vec::new();

        let code = matches.get_one::<String>("type").unwrap();
        let hash_algorithm = HashFunction::from_str(code).unwrap();

        if matches.contains_id("data") {
            data.extend_from_slice(matches.get_one::<String>("data").unwrap().as_bytes());
            let _calculated_sai = hash_algorithm.derive(&data).to_str();
            println!("Calculated SAI: {}", _calculated_sai);
        }

        if matches.contains_id("file") {
            let file_path = matches.get_one::<String>("file").unwrap();
            let file = File::open(file_path).expect("Unable to open file");
            let reader = BufReader::new(file);

            let calculated_sai = hash_algorithm.derive_from_stream(reader);
            match calculated_sai {
                Ok(sai) => println!("Calculated SAI: {}", sai.to_str()),
                Err(e) => eprintln!("Error calculating SAI: {}", e),
            }
        }
    }
    if let Some(matches) = matches.subcommand_matches("verify") {
        let _data = matches.get_one::<String>("data").unwrap().as_bytes();
        let sai_str = matches.get_one::<String>("sai").unwrap();
        let _sai: SelfAddressingIdentifier = sai_str
            .parse()
            .expect("Can't parse Self Addressing Identifier");
    }
}
