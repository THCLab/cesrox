//! `sai`: computes and verifies self-addressing identifiers of data given
//! on the command line or in a file.

const VERSION: &str = env!("CARGO_PKG_VERSION");

use cesrox::primitives::CesrPrimitive;
use clap::{Arg, ArgMatches, Command};
use said::{derivation::HashFunction, SelfAddressingIdentifier};
use std::{fs::File, io::BufReader, process::ExitCode, str::FromStr};

fn main() -> ExitCode {
    let matches = Command::new("SAI")
        .subcommand_required(true)
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
                        .conflicts_with("file")
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
                        .required_unless_present("file")
                        .conflicts_with("file")
                        .help("Source data against which we would like to verify given digest"),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .num_args(1)
                        .required_unless_present("data")
                        .help("File whose content we would like to verify the given digest against"),
                ),
        )
        .get_matches();

    let result = match matches.subcommand() {
        Some(("gen", args)) => generate(args).map(|sai| {
            println!("Calculated SAI: {sai}");
            true
        }),
        Some(("verify", args)) => verify(args),
        _ => Ok(false),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The SAI of the `--data` text or `--file` content with `algorithm`.
fn digest_input(
    args: &ArgMatches,
    algorithm: &HashFunction,
) -> Result<SelfAddressingIdentifier, String> {
    match (
        args.get_one::<String>("data"),
        args.get_one::<String>("file"),
    ) {
        (Some(data), _) => Ok(algorithm.derive(data.as_bytes())),
        (None, Some(path)) => {
            let file = File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
            algorithm
                .derive_from_stream(BufReader::new(file))
                .map_err(|e| format!("cannot read {path}: {e}"))
        }
        (None, None) => Err("give --data or --file".into()),
    }
}

fn generate(args: &ArgMatches) -> Result<String, String> {
    let code = args.get_one::<String>("type").ok_or("give --type")?;
    let algorithm =
        HashFunction::from_str(code).map_err(|_| format!("unknown derivation code {code}"))?;
    Ok(digest_input(args, &algorithm)?.to_str())
}

/// Whether the SAI given with `--sai` is the digest of the input.
fn verify(args: &ArgMatches) -> Result<bool, String> {
    let sai_str = args.get_one::<String>("sai").ok_or("give --sai")?;
    let sai: SelfAddressingIdentifier = sai_str
        .parse()
        .map_err(|e| format!("invalid SAI {sai_str}: {e}"))?;
    let computed = digest_input(args, &sai.derivation)?;
    if computed == sai {
        println!("Valid SAI");
        Ok(true)
    } else {
        println!("Invalid SAI: the data's SAI is {}", computed.to_str());
        Ok(false)
    }
}
