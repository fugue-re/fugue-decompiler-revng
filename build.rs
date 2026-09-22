use std::env;
use std::fs;
use std::path::PathBuf;

use revng_build::Sdk;

fn main() {
    let sdk = Sdk::discover().unwrap_or_else(|error| panic!("{error}"));
    sdk.configure_linkage();
    println!("cargo::rustc-link-lib=dylib=revngLift");

    for library in ["LLVMBitReader", "LLVMBitWriter"] {
        println!("cargo::rustc-link-lib=dylib={library}");
    }
    for target in ["X86", "AArch64", "ARM", "Mips", "SystemZ"] {
        for component in ["Info", "Desc", "CodeGen", "AsmParser", "Disassembler"] {
            println!("cargo::rustc-link-lib=dylib=LLVM{target}{component}");
        }
    }

    let pipeline = sdk.prefix().join("share/revng/pipeline.yml");
    let baked =
        PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("pipeline.yml");
    fs::copy(&pipeline, &baked).unwrap_or_else(|error| panic!("{}: {error}", pipeline.display()));
    println!("cargo::rerun-if-changed={}", pipeline.display());

    let mut bridge = cxx_build::bridge("src/bridge.rs");
    bridge.file("cxx/src/tags.cc").file("cxx/src/lifter.cc");
    sdk.configure_cxx(&mut bridge);
    bridge.compile("revng-fugue-cxx");

    println!("cargo::rerun-if-changed=src/bridge.rs");
    println!("cargo::rerun-if-changed=cxx");
}
