use std::rc::Rc;

use revng_fugue::{
    Address, Architecture, Decompiler, Location, Primitive, Prototype, Struct, Type,
};

fn signature() -> Prototype {
    Prototype::returning(Primitive::signed(4))
        .with_argument(Primitive::signed(4))
        .with_argument(Primitive::signed(4))
}

#[test]
fn decompiles_the_add_function_with_an_explicit_prototype() {
    let output = Decompiler::from_raw(
        vec![0x89, 0xf8, 0x01, 0xf0, 0xc3],
        Address::new(0x400000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .with_prototype(signature())
    .decompile_function(Address::new(0x400000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("int32_t function(int32_t argument_0, int32_t argument_1)")
            && c.contains("return argument_0 +"),
        "unexpected C output:\n{c}",
    );
}

#[test]
fn decompiles_the_add_function_with_a_detected_prototype() {
    let output = Decompiler::from_raw(
        vec![0x89, 0xf8, 0x01, 0xf0, 0xc3],
        Address::new(0x400000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x400000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("argument_0") && c.contains("argument_1"),
        "expected detect-abi to recover two System V arguments:\n{c}",
    );
}

#[test]
fn decompiles_an_aarch64_add_function() {
    let output = Decompiler::from_raw(
        vec![0x00, 0x00, 0x01, 0x0b, 0xc0, 0x03, 0x5f, 0xd6],
        Address::new(0x400000),
        Architecture::AArch64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x400000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("argument_0") && c.contains("argument_1") && c.contains('+'),
        "expected an AAPCS64 add of two arguments:\n{c}",
    );
}

#[test]
fn decompiles_a_function_with_a_call() {
    let output = Decompiler::from_raw(
        vec![
            0x89, 0xf8, 0x01, 0xf0, 0xc3, 0xe8, 0xf6, 0xff, 0xff, 0xff, 0xc3,
        ],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x1005))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("function_0x1000") && c.contains("argument_0"),
        "expected a materialised call to the callee at 0x1000:\n{c}",
    );
}

#[test]
fn decompiles_an_aarch64_function_with_a_call() {
    let output = Decompiler::from_raw(
        vec![
            0x00, 0x00, 0x01, 0x0b, 0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x00, 0xd1, 0xfe, 0x07,
            0x00, 0xf9, 0xfc, 0xff, 0xff, 0x97, 0xfe, 0x07, 0x40, 0xf9, 0xff, 0x43, 0x00, 0x91,
            0xc0, 0x03, 0x5f, 0xd6,
        ],
        Address::new(0x1000),
        Architecture::AArch64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x1008))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("function_0x1000") && c.contains("return"),
        "expected an AAPCS64 call returning the callee result:\n{c}",
    );
}

#[test]
fn decompiles_an_unsupported_instruction_as_an_opaque_intrinsic() {
    let output = Decompiler::from_raw(
        vec![0x0f, 0xa2, 0xc3],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds despite the unsupported instruction");

    let c = output.c();
    assert!(
        c.contains("__unsupported_cpuid"),
        "expected a named opaque intrinsic for the unsupported instruction:\n{c}",
    );
}

#[test]
fn decompiles_a_call_to_an_imported_function() {
    let output = Decompiler::from_raw(
        vec![0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .with_import("imported_add", Address::new(0x2000), signature())
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("imported_add("),
        "expected a call to the imported function:\n{c}",
    );
}

#[test]
fn session_decompiles_functions_on_demand_and_caches() {
    let session = Decompiler::from_raw(
        vec![
            0x89, 0xf8, 0x01, 0xf0, 0xc3, 0xe8, 0xf6, 0xff, 0xff, 0xff, 0xc3,
        ],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .into_session();

    let caller = session
        .function(Address::new(0x1005))
        .expect("caller decompiles on demand");
    assert!(
        caller.c().contains("function_0x1000"),
        "unexpected caller output:\n{}",
        caller.c(),
    );

    let callee = session
        .function(Address::new(0x1000))
        .expect("callee decompiles on demand");
    assert!(
        callee.c().contains("function_0x1000"),
        "unexpected callee output:\n{}",
        callee.c(),
    );

    assert_eq!(
        caller.llvm_ir(),
        callee.llvm_ir(),
        "a callee should be decompiled from the caller's shared lifted context, not a re-lift",
    );

    let caller_again = session
        .function(Address::new(0x1005))
        .expect("cached decompilation");
    assert!(
        Rc::ptr_eq(&caller, &caller_again),
        "a repeated request should return the cached result",
    );
}

#[test]
fn honours_an_incorrect_struct_pointer_prototype() {
    let adversarial = Struct::new("Adversarial", 24)
        .with_field(0, "header", Type::pointer(Primitive::unsigned(8)))
        .with_field(8, "flags", Primitive::unsigned(4))
        .with_field(12, "count", Primitive::unsigned(4))
        .with_field(16, "value", Primitive::unsigned(8));
    let prototype = Prototype::returning(Primitive::void())
        .with_argument(Type::pointer(adversarial))
        .with_argument(Primitive::unsigned(4))
        .with_argument(Primitive::unsigned(4));

    let output = Decompiler::from_raw(
        vec![
            0x89, 0x37, 0x89, 0x57, 0x08, 0xc7, 0x47, 0x10, 0x00, 0x00, 0x00, 0x00, 0xc3,
        ],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .with_prototype(prototype)
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds despite the incorrect type");

    let c = output.c();
    assert!(
        c.contains("Adversarial *argument_0"),
        "the supplied struct type should be used for the parameter:\n{c}",
    );
    assert!(
        c.contains("argument_0->flags"),
        "a field whose layout matches the access should be used directly:\n{c}",
    );
    assert!(
        c.contains("&argument_0->value"),
        "a mismatched access should be reinterpreted through the field, not crash:\n{c}",
    );
}

#[test]
fn recovers_a_struct_type_via_data_layout_analysis() {
    let output = Decompiler::from_raw(
        vec![
            0x89, 0x37, 0x89, 0x57, 0x08, 0xc7, 0x47, 0x10, 0x00, 0x00, 0x00, 0x00, 0xc3,
        ],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("struct") && c.contains("argument_0->") && c.contains("offset_8"),
        "expected DLA to recover a struct type with named fields:\n{c}",
    );
}

#[test]
fn ptml_maps_source_tokens_to_instruction_addresses() {
    let output = Decompiler::from_raw(
        vec![0x89, 0xf8, 0x39, 0xf0, 0x7d, 0x02, 0x89, 0xf0, 0xc3],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .with_prototype(signature())
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds");

    let document = output.document();
    assert_eq!(
        document.text(),
        output.c(),
        "the stripped document must reproduce the C output verbatim",
    );

    let map = document.address_map();
    assert!(
        map.contains_key(&Address::new(0x1008)),
        "the return instruction at 0x1008 should map to source tokens: {:?}",
        map.keys().collect::<Vec<_>>(),
    );

    let return_offset = document.text().find("return").expect("a return statement");
    let mapped = document
        .tokens()
        .iter()
        .filter(|token| token.range().start >= return_offset)
        .find_map(|token| token.instruction_address());
    assert_eq!(
        mapped,
        Some(Address::new(0x1008)),
        "tokens in the return statement should carry the 0x1008 instruction address",
    );
}

#[test]
fn ptml_exposes_referenced_callees() {
    let output = Decompiler::from_raw(
        vec![
            0x89, 0xf8, 0x01, 0xf0, 0xc3, 0xe8, 0xf6, 0xff, 0xff, 0xff, 0xc3,
        ],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .decompile_function(Address::new(0x1005))
    .expect("decompilation succeeds");

    let document = output.document();
    let callees = document.referenced_functions().collect::<Vec<Address>>();
    assert!(
        callees.contains(&Address::new(0x1000)),
        "the caller's document should reference the callee at 0x1000: {callees:?}",
    );

    let has_primitive = document
        .tokens()
        .iter()
        .any(|token| matches!(token.references(), Some(Location::Primitive(_))));
    assert!(
        has_primitive,
        "type tokens should reference primitive locations"
    );
}

#[test]
fn decompiles_a_jump_table_switch() {
    let output = Decompiler::from_raw(
        vec![
            0x83, 0xff, 0x02, 0x77, 0x1b, 0x89, 0xff, 0xff, 0x24, 0xfd, 0x38, 0x10, 0x00, 0x00,
            0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x1e,
            0x00, 0x00, 0x00, 0xc3, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x1a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .with_prototype(Prototype::returning(Primitive::signed(4)).with_argument(Primitive::signed(4)))
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("switch") && c.contains("20U") && c.contains("30U"),
        "expected revng's solver to recover a jump-table switch with distinct cases:\n{c}",
    );

    println!("{c}")
}

#[test]
fn decompiles_a_branching_function() {
    let output = Decompiler::from_raw(
        vec![0x89, 0xf8, 0x39, 0xf0, 0x7d, 0x02, 0x89, 0xf0, 0xc3],
        Address::new(0x1000),
        Architecture::X86_64,
    )
    .expect("shellcode loads")
    .with_prototype(signature())
    .decompile_function(Address::new(0x1000))
    .expect("decompilation succeeds");

    let c = output.c();
    assert!(
        c.contains("return") && (c.contains("if") || c.contains('?')),
        "expected a conditional in the output:\n{c}",
    );
}
