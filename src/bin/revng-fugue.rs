use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use revng_fugue::{Address, Architecture, CodeFormat, Decompiler, Session, Untranslated};

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Decompile(#[from] revng_fugue::Error),
    #[error("reading {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("writing the output: {0}")]
    Write(#[from] io::Error),
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
        "x86" => Ok(Architecture::X86),
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::AArch64),
        other => Err(format!(
            "unknown architecture '{other}' (expected x86, x86_64 or aarch64)"
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
                .action(ArgAction::Append)
                .value_parser(parse_address)
                .help(
                    "Address of a function to decompile; repeat to decompile several from one \
                     analysis. Omit to list functions",
                ),
        )
        .arg(
            Arg::new("assume-returns")
                .long("assume-returns")
                .action(ArgAction::Append)
                .value_parser(parse_address)
                .help(
                    "Treat the function at this address as an ordinary returning function \
                     rather than letting `detect-abi` classify it. Use on return \
                     trampolines that jump through a register, which are otherwise taken \
                     for `NoReturn` and truncate every caller",
                ),
        )
        .arg(
            Arg::new("depth")
                .long("depth")
                .value_parser(value_parser!(u32))
                .help(
                    "Stop following calls this many levels below each requested function. \
                     Bounds how much of the binary is lifted and analysed; omit to follow \
                     every call",
                ),
        )
        .arg(
            Arg::new("abi")
                .long("abi")
                .help("Override the default ABI (e.g. SystemV_x86_64, AAPCS64)"),
        )
        .arg(
            Arg::new("stage")
                .long("stage")
                .help("Savepoint to take the module from instead of decompiling"),
        )
        .arg(
            Arg::new("container")
                .long("container")
                .default_value("llvm-functions")
                .help("Container to read at --stage"),
        )
        .arg(
            Arg::new("passes")
                .long("passes")
                .help("Pass pipeline to run over the module, for instance 'default<O3>'"),
        )
        .arg(
            Arg::new("triple")
                .long("triple")
                .help("Emit machine code for this target triple instead of bitcode"),
        )
        .arg(
            Arg::new("emit")
                .long("emit")
                .value_parser(["c", "llvm", "both", "asm"])
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
                .help("Guest architecture for --raw input (x86, x86_64 or aarch64)"),
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
    let decompiler = matches
        .get_many::<u64>("assume-returns")
        .into_iter()
        .flatten()
        .copied()
        .fold(decompiler, |decompiler, address| {
            decompiler.with_returning_function(Address::new(address))
        });
    let decompiler = match matches.get_one::<u32>("depth") {
        Some(depth) => decompiler.with_max_depth(*depth),
        None => decompiler,
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

    let addresses = matches
        .get_many::<u64>("address")
        .into_iter()
        .flatten()
        .copied()
        .map(Address::new)
        .collect::<Vec<Address>>();
    if addresses.is_empty() {
        list(&decompiler);
        return Ok(());
    }

    let emit = matches.get_one::<String>("emit").map(String::as_str);
    let session = decompiler.into_session();
    if matches.contains_id("stage") {
        return emit_modules(&session, &addresses, &matches);
    }
    for address in addresses {
        let output = session.function(address)?;
        match emit {
            Some("llvm") => println!("{}", output.llvm_ir()),
            Some("both") => println!("{}\n{}", output.llvm_ir(), output.c()),
            _ => println!("{}", output.c()),
        }
        report_untranslated(output.untranslated());
    }
    Ok(())
}

fn emit_modules(
    session: &Session,
    addresses: &[Address],
    matches: &ArgMatches,
) -> Result<(), CliError> {
    let stage = matches
        .get_one::<String>("stage")
        .expect("stage is present");
    let container = matches
        .get_one::<String>("container")
        .expect("container has a default");
    let triple = matches.get_one::<String>("triple").map(String::as_str);
    let passes = matches.get_one::<String>("passes").map(String::as_str);
    let host = revng_fugue::host_triple();
    let target = triple.unwrap_or(&host);
    let assembly = matches.get_one::<String>("emit").map(String::as_str) == Some("asm");

    for address in addresses {
        let module = session.module(*address, stage, container)?;
        let bytes = match triple {
            Some(triple) => {
                let format = if assembly {
                    CodeFormat::Assembly
                } else {
                    CodeFormat::Object
                };
                revng_fugue::compile(&module, triple, passes, format)?
            }
            None => match passes {
                Some(passes) => revng_fugue::optimise(&module, target, passes)?,
                None => module,
            },
        };
        io::stdout().write_all(&bytes)?;
    }
    Ok(())
}

fn report_untranslated(untranslated: &[Untranslated]) {
    let mut reasons = BTreeMap::new();
    for instruction in untranslated {
        let entry = reasons
            .entry(instruction.reason())
            .or_insert((0usize, instruction.address()));
        entry.0 += 1;
    }
    let mut counted = reasons.into_iter().collect::<Vec<_>>();
    counted.sort_by_key(|(_, (count, _))| Reverse(*count));
    for (reason, (count, first)) in counted {
        eprintln!("warning: {count} instruction(s) not translated, first at {first}: {reason}");
    }
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
