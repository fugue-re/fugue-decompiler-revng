use revng_build::Sdk;

fn main() {
    let sdk = Sdk::discover().unwrap_or_else(|error| panic!("{error}"));
    sdk.configure_linkage();
    println!("cargo::rustc-link-lib=dylib=revngLift");

    let mut bridge = cxx_build::bridge("src/bridge.rs");
    bridge.file("cxx/src/tags.cc").file("cxx/src/lifter.cc");
    sdk.configure_cxx(&mut bridge);
    bridge.compile("revng-fugue-cxx");

    println!("cargo::rerun-if-changed=src/bridge.rs");
    println!("cargo::rerun-if-changed=cxx");
}
