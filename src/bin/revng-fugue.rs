use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use revng_fugue::{Address, Architecture, Decompiler};

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Decompile(#[from] revng_fugue::Error),
    #[error("reading {path}: {source}")]
    Read { path: String, source: io::Error },
}

fn parse_address(value: &str) -> Result<u64, String> {
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hexadecimal) => u64::from_str_radix(hexadecimal, 16),
        None => value.parse(),
    };
    parsed.map_err(|error| format!("invalid address '{value}': {error}"))
}

fn parse_architecture(value: &str) -> Result<Architecture, String> {
    match value {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::AArch64),
        other => Err(format!(
            "unknown architecture '{other}' (expected x86_64 or aarch64)"
        )),
    }
}

fn command() -> Command {
    Command::new("revng-fugue")
        .about("Decompile a function through the fugue-driven revng pipeline")
        .arg(
            Arg::new("binary")
                .required(true)
                .value_parser(value_parser!(PathBuf))
                .help("Binary to load (ELF/PE, or raw bytes with --raw)"),
        )
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_parser(parse_address)
                .help("Address of the function to decompile; omit to list functions"),
        )
        .arg(
            Arg::new("abi")
                .long("abi")
                .help("Override the default ABI (e.g. SystemV_x86_64, AAPCS64)"),
        )
        .arg(
            Arg::new("emit")
                .long("emit")
                .value_parser(["c", "llvm", "both"])
                .default_value("c")
                .help("Which artefact to print"),
        )
        .arg(
            Arg::new("raw")
                .long("raw")
                .action(ArgAction::SetTrue)
                .requires("base")
                .requires("arch")
                .help("Treat the binary as raw bytes at --base for --arch"),
        )
        .arg(
            Arg::new("base")
                .long("base")
                .value_parser(parse_address)
                .help("Base address for --raw input"),
        )
        .arg(
            Arg::new("arch")
                .long("arch")
                .value_parser(parse_architecture)
                .help("Guest architecture for --raw input (x86_64 or aarch64)"),
        )
}

fn load(matches: &ArgMatches) -> Result<Decompiler, CliError> {
    let path = matches
        .get_one::<PathBuf>("binary")
        .expect("binary is required");
    let decompiler = if matches.get_flag("raw") {
        let bytes = std::fs::read(path).map_err(|source| CliError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let base = *matches
            .get_one::<u64>("base")
            .expect("base required by --raw");
        let arch = *matches
            .get_one::<Architecture>("arch")
            .expect("arch required by --raw");
        Decompiler::from_raw(bytes, Address::new(base), arch)?
    } else {
        Decompiler::open(path)?
    };
    Ok(match matches.get_one::<String>("abi") {
        Some(abi) => decompiler.with_abi(abi),
        None => decompiler,
    })
}

fn list(decompiler: &Decompiler) {
    if let Some(entry) = decompiler.entry() {
        println!("entry {entry}");
    }
    for symbol in decompiler.symbols() {
        println!("{} {}", symbol.address(), symbol.name());
    }
}

fn run() -> Result<(), CliError> {
    let matches = command().get_matches();
    let decompiler = load(&matches)?;

    let Some(address) = matches.get_one::<u64>("address").copied() else {
        list(&decompiler);
        return Ok(());
    };

    let output = decompiler.decompile_function(Address::new(address))?;
    match matches.get_one::<String>("emit").map(String::as_str) {
        Some("llvm") => println!("{}", output.llvm_ir()),
        Some("both") => println!("{}\n{}", output.llvm_ir(), output.c()),
        _ => println!("{}", output.c()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
