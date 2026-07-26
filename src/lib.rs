mod address_space;
mod binary;
mod bridge;
mod error;
mod lifter;
mod manager;
mod module;
mod prototype;
mod ptml;
mod translate;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char, c_void};
use std::iter::once;
use std::mem::take;
use std::path::Path;
use std::ptr;
use std::rc::Rc;
use std::sync::OnceLock;

use revng_sys::{LLVMModuleRef, rp_binary_view, rp_initialize, rp_lifter_callbacks};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::address_space::AddressSpace;
use crate::lifter::FugueLifter;
use crate::manager::Manager;
use crate::module::BorrowedModule;
use crate::translate::{RegisterFile, TranslateError, lift};

pub use binary::{Address, Architecture, Binary, FunctionSymbol, Segment};
pub use error::Error;
pub use prototype::{Primitive, PrimitiveKind, Prototype, Struct, Type};
pub use ptml::{Document, Location, Token};

pub struct Output {
    llvm_ir: String,
    c: String,
    ptml: String,
}

impl Output {
    pub fn llvm_ir(&self) -> &str {
        &self.llvm_ir
    }

    pub fn c(&self) -> &str {
        &self.c
    }

    pub fn ptml(&self) -> &str {
        &self.ptml
    }

    pub fn document(&self) -> Document {
        ptml::parse(&self.ptml)
    }
}

struct Import {
    name: String,
    address: Address,
    prototype: Prototype,
}

pub struct Decompiler {
    binary: Rc<Binary>,
    abi: Option<String>,
    prototype: Option<Prototype>,
    imports: Vec<Import>,
}

impl Decompiler {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Self {
            binary: Rc::new(Binary::open(path)?),
            abi: None,
            prototype: None,
            imports: Vec::new(),
        })
    }

    pub fn from_raw(
        bytes: Vec<u8>,
        base: Address,
        architecture: Architecture,
    ) -> Result<Self, Error> {
        Ok(Self {
            binary: Rc::new(Binary::from_raw(bytes, base, architecture)?),
            abi: None,
            prototype: None,
            imports: Vec::new(),
        })
    }

    pub fn with_abi(mut self, abi: impl Into<String>) -> Self {
        self.abi = Some(abi.into());
        self
    }

    pub fn with_prototype(mut self, prototype: Prototype) -> Self {
        self.prototype = Some(prototype);
        self
    }

    pub fn with_import(
        mut self,
        name: impl Into<String>,
        address: Address,
        prototype: Prototype,
    ) -> Self {
        self.imports.push(Import {
            name: name.into(),
            address,
            prototype,
        });
        self
    }

    pub fn architecture(&self) -> Architecture {
        self.binary.architecture()
    }

    pub fn entry(&self) -> Option<Address> {
        self.binary.entry()
    }

    pub fn symbols(&self) -> &[FunctionSymbol] {
        self.binary.symbols()
    }

    pub fn decompile_function(&self, address: Address) -> Result<Output, Error> {
        self.build_harness(address.value())?
            .decompile(address.value())
    }

    fn build_harness(&self, seed: u64) -> Result<Harness, Error> {
        initialise()?;
        let architecture = self.binary.architecture();
        let pointer_size = architecture.pointer_size();

        let space = Box::new(AddressSpace::new(Rc::clone(&self.binary), seed));
        let mut manager = Manager::create(&space.callbacks())?;

        let abi = CString::new(self.abi.as_deref().unwrap_or(architecture.default_abi()))
            .expect("ABI name has no NUL");
        manager.set_default_abi(&abi)?;
        manager.register_imports(&abi, &self.imports, pointer_size)?;
        let imports = self
            .imports
            .iter()
            .map(|import| (import.address.value(), import.name.clone()))
            .collect::<FxHashMap<u64, String>>();

        let meta_address = CString::new(format!("{seed:#x}:Code_{}", architecture.revng_name()))
            .expect("meta address has no NUL");

        let mut context = LiftContext {
            binary: &self.binary,
            registers: RegisterFile::build(self.binary.language(), architecture),
            architecture,
            entry: seed,
            imports: &imports,
            error: CString::default(),
            llvm_ir: String::new(),
            functions: FxHashSet::default(),
        };
        let callbacks = rp_lifter_callbacks {
            opaque: ptr::from_mut(&mut context).cast(),
            lift: Some(lift_callback),
        };
        manager.set_lifter(&callbacks)?;
        manager.produce_root()?;

        let mut covered = FxHashSet::default();
        covered.insert(seed);
        match &self.prototype {
            Some(prototype) => {
                manager.set_prototype(&meta_address, &abi, prototype, pointer_size)?
            }
            None => {
                manager.detect_abi()?;
                let functions = once(seed)
                    .chain(context.functions.iter().copied())
                    .filter(|target| !imports.contains_key(target))
                    .collect::<BTreeSet<u64>>()
                    .into_iter()
                    .map(|target| {
                        CString::new(format!("{target:#x}:Code_{}", architecture.revng_name()))
                            .expect("meta address has no NUL")
                    })
                    .collect::<Vec<CString>>();
                manager.run_data_layout(&functions)?;
                manager.run_analysis(c"initial", c"convert-functions-to-cabi", None)?;
                covered.extend(
                    context
                        .functions
                        .iter()
                        .copied()
                        .filter(|target| !imports.contains_key(target)),
                );
            }
        }

        let llvm_ir = take(&mut context.llvm_ir);
        Ok(Harness {
            manager,
            space,
            covered,
            architecture,
            llvm_ir,
        })
    }

    pub fn into_session(self) -> Session {
        Session {
            decompiler: self,
            harness: RefCell::new(None),
            cache: RefCell::new(FxHashMap::default()),
        }
    }
}

struct Harness {
    manager: Manager,
    // SAFETY: `manager`'s address-space callbacks retain raw pointers into this,
    // so it must outlive `manager` (which is dropped first, being declared before it).
    #[allow(dead_code)]
    space: Box<AddressSpace>,
    covered: FxHashSet<u64>,
    architecture: Architecture,
    llvm_ir: String,
}

impl Harness {
    fn covers(&self, address: u64) -> bool {
        self.covered.contains(&address)
    }

    fn decompile(&self, address: u64) -> Result<Output, Error> {
        let meta_address = CString::new(format!(
            "{address:#x}:Code_{}",
            self.architecture.revng_name()
        ))
        .expect("meta address has no NUL");
        let ptml = self.manager.decompile_to_ptml(&meta_address)?;
        let c = ptml::strip(&ptml);
        Ok(Output {
            llvm_ir: self.llvm_ir.clone(),
            c,
            ptml,
        })
    }
}

pub struct Session {
    decompiler: Decompiler,
    harness: RefCell<Option<Harness>>,
    cache: RefCell<FxHashMap<u64, Rc<Output>>>,
}

impl Session {
    pub fn function(&self, address: Address) -> Result<Rc<Output>, Error> {
        let address = address.value();
        if let Some(output) = self.cache.borrow().get(&address) {
            return Ok(Rc::clone(output));
        }

        let covered = matches!(&*self.harness.borrow(), Some(harness) if harness.covers(address));
        if !covered {
            let harness = self.decompiler.build_harness(address)?;
            *self.harness.borrow_mut() = Some(harness);
        }

        let output = {
            let harness = self.harness.borrow();
            let harness = harness.as_ref().expect("a harness was built above");
            Rc::new(harness.decompile(address)?)
        };
        self.cache.borrow_mut().insert(address, Rc::clone(&output));
        Ok(output)
    }

    pub fn symbols(&self) -> &[FunctionSymbol] {
        self.decompiler.symbols()
    }

    pub fn architecture(&self) -> Architecture {
        self.decompiler.architecture()
    }

    pub fn entry(&self) -> Option<Address> {
        self.decompiler.entry()
    }
}

struct LiftContext<'a> {
    binary: &'a Binary,
    registers: RegisterFile<'a>,
    architecture: Architecture,
    entry: u64,
    imports: &'a FxHashMap<u64, String>,
    error: CString,
    llvm_ir: String,
    functions: FxHashSet<u64>,
}

impl LiftContext<'_> {
    fn fail(&mut self, message: &str, error_message: *mut *const c_char) -> bool {
        self.error = CString::new(message.replace('\0', "\\0")).expect("NUL bytes were replaced");
        if !error_message.is_null() {
            unsafe { *error_message = self.error.as_ptr() };
        }
        false
    }
}

unsafe extern "C" fn lift_callback(
    opaque: *mut c_void,
    model: *const c_void,
    binary: *const rp_binary_view,
    entries: *const *const c_char,
    entry_count: u64,
    output: LLVMModuleRef,
    error_message: *mut *const c_char,
) -> bool {
    let context = unsafe { &mut *opaque.cast::<LiftContext>() };
    let entry = unsafe { first_entry(entries, entry_count) }.unwrap_or(context.entry);

    let module = unsafe { BorrowedModule::from_raw(output) };
    let mut lifter = FugueLifter::new(
        module.as_module(),
        model,
        binary,
        context.architecture,
        entry,
    );

    let outcome = lift(
        module.as_module(),
        context.architecture,
        &context.registers,
        context.imports,
        context.binary,
        &mut lifter,
    )
    .and_then(|callees| {
        context.functions = callees;
        lifter.finalise();
        module.as_module().verify().map_err(TranslateError::Verify)
    });
    drop(lifter);

    match outcome {
        Ok(()) => {
            context.llvm_ir = module.print_to_string().to_string();
            true
        }
        Err(error) => context.fail(&error.to_string(), error_message),
    }
}

unsafe fn first_entry(entries: *const *const c_char, count: u64) -> Option<u64> {
    if count == 0 || entries.is_null() {
        return None;
    }
    let first = unsafe { *entries };
    if first.is_null() {
        return None;
    }
    let text = unsafe { CStr::from_ptr(first) }.to_str().ok()?;
    let address = text.split_once(':').map_or(text, |(address, _)| address);
    u64::from_str_radix(address.strip_prefix("0x")?, 16).ok()
}

fn initialise() -> Result<(), Error> {
    static INITIALISED: OnceLock<bool> = OnceLock::new();
    let initialised = *INITIALISED.get_or_init(|| {
        let pipeline = bridge::default_pipeline();
        if pipeline.is_empty() {
            return false;
        }
        let program = CString::new("revng-fugue").expect("program name has no NUL");
        let pipeline =
            CString::new(format!("--pipeline-path={pipeline}")).expect("pipeline path has no NUL");
        let argv = [program.as_ptr(), pipeline.as_ptr()];
        unsafe { rp_initialize(2, argv.as_ptr(), 0, ptr::null_mut()) }
    });
    if initialised {
        Ok(())
    } else {
        Err(Error::pipeline("rp_initialize failed"))
    }
}
