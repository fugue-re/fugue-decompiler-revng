use std::sync::Once;

use inkwell::OptimizationLevel;
use inkwell::context::Context;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::module::Module;
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{
    CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetMachine, TargetTriple,
};

use crate::error::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeFormat {
    Assembly,
    Object,
}

impl CodeFormat {
    fn to_file_type(self) -> FileType {
        match self {
            Self::Assembly => FileType::Assembly,
            Self::Object => FileType::Object,
        }
    }
}

pub fn host_triple() -> String {
    TargetMachine::get_default_triple()
        .as_str()
        .to_string_lossy()
        .into_owned()
}

fn initialise_targets() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let configuration = InitializationConfig::default();
        Target::initialize_x86(&configuration);
        Target::initialize_aarch64(&configuration);
        Target::initialize_arm(&configuration);
        Target::initialize_mips(&configuration);
        Target::initialize_system_z(&configuration);
    });
}

fn machine(triple: &str) -> Result<TargetMachine, Error> {
    initialise_targets();
    let triple = TargetTriple::create(triple);
    let target = Target::from_triple(&triple)
        .map_err(|error| Error::codegen(format!("unknown target triple: {error}")))?;
    target
        .create_target_machine(
            &triple,
            "generic",
            "",
            OptimizationLevel::Default,
            RelocMode::PIC,
            CodeModel::Default,
        )
        .ok_or_else(|| Error::codegen("the triple has no target machine"))
}

fn parse<'ctx>(bitcode: &[u8], context: &'ctx Context) -> Result<Module<'ctx>, Error> {
    let mut terminated = Vec::with_capacity(bitcode.len() + 1);
    terminated.extend_from_slice(bitcode);
    terminated.push(0);
    let buffer = MemoryBuffer::create_from_memory_range(&terminated, "module");
    Module::parse_bitcode_from_buffer(&buffer, context)
        .map_err(|error| Error::codegen(format!("the module does not parse: {error}")))
}

pub fn optimise(bitcode: &[u8], triple: &str, passes: &str) -> Result<Vec<u8>, Error> {
    let machine = machine(triple)?;
    let context = Context::create();
    let module = parse(bitcode, &context)?;
    let original = module.get_triple();
    run(&module, &machine, passes)?;
    module.set_triple(&original);
    let buffer = module.write_bitcode_to_memory();
    let bytes = buffer.as_slice();
    Ok(bytes[..bytes.len().saturating_sub(1)].to_vec())
}

pub fn compile(
    bitcode: &[u8],
    triple: &str,
    passes: Option<&str>,
    format: CodeFormat,
) -> Result<Vec<u8>, Error> {
    let machine = machine(triple)?;
    let context = Context::create();
    let module = parse(bitcode, &context)?;
    module.set_triple(&machine.get_triple());
    if let Some(passes) = passes {
        run(&module, &machine, passes)?;
    }
    let buffer = machine
        .write_to_memory_buffer(&module, format.to_file_type())
        .map_err(|error| Error::codegen(format!("writing the machine code failed: {error}")))?;
    let bytes = buffer.as_slice();
    Ok(bytes[..bytes.len().saturating_sub(1)].to_vec())
}

fn run(module: &Module<'_>, machine: &TargetMachine, passes: &str) -> Result<(), Error> {
    module
        .run_passes(passes, machine, PassBuilderOptions::create())
        .map_err(|error| Error::codegen(format!("the pass pipeline failed: {error}")))
}
