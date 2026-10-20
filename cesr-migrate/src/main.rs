//! Converts CESR stored in the format of cesrox before 2.0 to CESR V2.
//!
//! Reads a file or standard input and writes the converted stream to a file
//! or standard output. Message bodies are not changed, so SAIDs,
//! identifiers and signatures stay valid.
//!
//! Exit status: 0 on success (with `--check`: already V2), 1 with `--check`
//! when the input needs migrating, 2 on errors.

use std::{
    fs,
    io::{self, Read, Write},
    process::ExitCode,
};

use cesrox::{
    migrate::{migrate, Options},
    Counting,
};
use clap::{Arg, ArgAction, ArgMatches, Command};

fn main() -> ExitCode {
    let args = Command::new("cesr-migrate")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Converts CESR in the format of cesrox before 2.0 to CESR V2")
        .arg(
            Arg::new("input")
                .help("File to convert; standard input if omitted"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("File to write; standard output if omitted"),
        )
        .arg(
            Arg::new("auto")
                .long("auto")
                .action(ArgAction::SetTrue)
                .help("Accept input that is partly CESR V2 already"),
        )
        .arg(
            Arg::new("no-wrap")
                .long("no-wrap")
                .action(ArgAction::SetTrue)
                .help("Keep attachment groups bare instead of wrapping them in an attachment group (-C)"),
        )
        .arg(
            Arg::new("check")
                .long("check")
                .action(ArgAction::SetTrue)
                .help("Only report whether the input needs migrating"),
        )
        .get_matches();

    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &ArgMatches) -> Result<ExitCode, String> {
    let input = match args.get_one::<String>("input") {
        Some(path) => fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?,
        None => {
            let mut input = vec![];
            io::stdin()
                .read_to_end(&mut input)
                .map_err(|e| format!("cannot read standard input: {e}"))?;
            input
        }
    };
    let options = Options {
        counting: if args.get_flag("auto") {
            Counting::Auto
        } else {
            Counting::LegacyItems
        },
        wrap_attachments: !args.get_flag("no-wrap"),
    };
    let migration = migrate(&input, &options).map_err(|e| e.to_string())?;

    if args.get_flag("check") {
        return Ok(if migration.changed {
            println!("needs migration");
            ExitCode::from(1)
        } else {
            println!("already CESR V2");
            ExitCode::SUCCESS
        });
    }
    match args.get_one::<String>("output") {
        Some(path) => {
            fs::write(path, &migration.output).map_err(|e| format!("cannot write {path}: {e}"))?
        }
        None => io::stdout()
            .write_all(&migration.output)
            .map_err(|e| format!("cannot write standard output: {e}"))?,
    }
    Ok(ExitCode::SUCCESS)
}
