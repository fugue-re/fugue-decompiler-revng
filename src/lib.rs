use std::cell::{RefCell, UnsafeCell};
use std::collections::BTreeSet;
use std::env;
use std::ffi::{CStr, CString, c_char, c_void};
use std::iter::once;
use std::mem::take;
use std::path::Path;
use std::rc::Rc;
use std::sync::Once;

use revng_sys::{
    LLVMModuleRef, rp_binary_view, rp_initialise, rp_is_initialised, rp_lifter_callbacks,
};
use rustc_hash::{FxHashMap, FxHashSet};

mod address_space;
mod binary;
mod bridge;
mod codegen;
mod error;
mod lifter;
mod manager;
mod module;
mod prototype;
mod ptml;
mod translate;

use crate::address_space::AddressSpace;
use crate::lifter::FugueLifter;
use crate::manager::Manager;
use crate::module::BorrowedModule;
use crate::translate::{RegisterFile, TranslateError, lift};

pub use binary::{Address, Architecture, Binary, FunctionSymbol, Segment};
pub use codegen::{CodeFormat, compile, host_triple, optimise};
pub use error::Error;
pub use prototype::{Primitive, PrimitiveKind, Prototype, Struct, Type};
pub use ptml::{Document, Location, Token};
pub use translate::Untranslated;

/// The pipeline description, taken from the SDK this was built against so the
/// two cannot drift.
const PIPELINE: &str = include_str!(concat!(env!("OUT_DIR"), "/pipeline.yml"));
static INIT: Once = Once::new();

pub struct Output {
    llvm_ir: String,
    c: String,
    ptml: String,
    untranslated: Vec<Untranslated>,
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

    pub fn untranslated(&self) -> &[Untranslated] {
        &self.untranslated
    }
}

struct Import {
    name: String,
    address: Address,
    prototype: Prototype,
}

struct DeclaredFunction {
    address: Address,
    prototype: Prototype,
}

pub struct Decompiler {
    binary: Rc<Binary>,
    abi: Option<String>,
    prototype: Option<Prototype>,
    max_depth: Option<u32>,
    declared: Vec<DeclaredFunction>,
    imports: Vec<Import>,
}

impl Decompiler {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Self {
            binary: Rc::new(Binary::open(path)?),
            abi: None,
            prototype: None,
            max_depth: None,
            declared: Vec::new(),
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
            max_depth: None,
            declared: Vec::new(),
            imports: Vec::new(),
        })
    }

    pub fn with_abi(mut self, abi: impl Into<String>) -> Self {
        self.abi = Some(abi.into());
        self
    }

    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = Some(depth);
        self
    }

    pub fn with_returning_function(self, address: Address) -> Self {
        let pointer_size = self.binary.architecture().pointer_size() as u16;
        self.with_declared_function(
            address,
            Prototype::returning(Primitive::generic(pointer_size)),
        )
    }

    pub fn with_declared_function(mut self, address: Address, prototype: Prototype) -> Self {
        self.declared.push(DeclaredFunction { address, prototype });
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
        self.build_analysis(address.value())?
            .decompile(address.value())
    }

    fn build_analysis(&self, seed: u64) -> Result<Analysis, Error> {
        initialise(&[])?;
        let architecture = self.binary.architecture();
        let pointer_size = architecture.pointer_size();

        let space = Box::new(AddressSpace::new(Rc::clone(&self.binary), seed));
        let pipeline = CString::new(PIPELINE).expect("the pipeline has no NUL");
        let mut manager = Manager::create(&space.callbacks(), &pipeline)?;

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

        let context = Box::new(UnsafeCell::new(LiftContext {
            binary: Rc::clone(&self.binary),
            architecture,
            entry: seed,
            imports: imports.clone(),
            error: CString::default(),
            llvm_ir: String::new(),
            functions: FxHashSet::default(),
            lifted: FxHashSet::default(),
            untranslated: Vec::new(),
            max_depth: self.max_depth,
        }));
        let callbacks = rp_lifter_callbacks {
            opaque: context.get().cast(),
            lift: Some(lift_callback),
        };
        manager.set_lifter(&callbacks)?;
        manager.produce_root()?;

        // revng keeps `callbacks.opaque` and calls back into it whenever it
        // re-lifts, so the context is only ever reached through that pointer
        // and never through a reference that would invalidate it.
        let (lifted, reached) = {
            let state = unsafe { &*context.get() };
            (state.lifted.clone(), state.functions.clone())
        };

        let mut covered = FxHashSet::default();
        covered.insert(seed);
        match &self.prototype {
            Some(prototype) => {
                manager.set_prototype(&meta_address, &abi, c"function", prototype, pointer_size)?
            }
            None => {
                for DeclaredFunction { address, prototype } in self
                    .declared
                    .iter()
                    .filter(|declared| lifted.contains(&declared.address.value()))
                {
                    let meta_address = CString::new(format!(
                        "{:#x}:Code_{}",
                        address.value(),
                        architecture.revng_name()
                    ))
                    .expect("meta address has no NUL");
                    let name = CString::new(format!("function_{:#x}", address.value()))
                        .expect("function name has no NUL");
                    manager.add_function(&meta_address, &name)?;
                    manager.set_prototype(&meta_address, &abi, &name, prototype, pointer_size)?;
                }
                manager.detect_abi()?;
                let functions = once(seed)
                    .chain(reached.iter().copied())
                    .filter(|target| !imports.contains_key(target))
                    .collect::<BTreeSet<u64>>()
                    .into_iter()
                    .map(|target| {
                        CString::new(format!("{target:#x}:Code_{}", architecture.revng_name()))
                            .expect("meta address has no NUL")
                    })
                    .collect::<Vec<CString>>();
                manager.run_function_analysis(c"detect-c-strings", &functions)?;
                manager.run_function_analysis(c"analyze-data-layout", &functions)?;
                manager.run_analysis(c"", c"convert-functions-to-cabi", None)?;
                if self.max_depth.is_none() {
                    covered.extend(
                        reached
                            .iter()
                            .copied()
                            .filter(|target| !imports.contains_key(target)),
                    );
                }
            }
        }

        let (llvm_ir, untranslated) = {
            let state = unsafe { &mut *context.get() };
            (take(&mut state.llvm_ir), take(&mut state.untranslated))
        };
        Ok(Analysis {
            manager,
            space,
            context,
            covered,
            architecture,
            llvm_ir,
            untranslated,
        })
    }

    pub fn into_session(self) -> Session {
        Session {
            decompiler: self,
            analysis: RefCell::new(None),
            cache: RefCell::new(FxHashMap::default()),
        }
    }
}

struct Analysis {
    manager: Manager,
    // SAFETY: `manager`'s address-space callbacks retain raw pointers into this,
    // so it must outlive `manager` (which is dropped first, being declared before it).
    #[allow(dead_code)]
    space: Box<AddressSpace>,
    // SAFETY: the lifter callback keeps a raw pointer into this for as long as
    // the manager can re-lift, which outlives the call that built it.
    #[allow(dead_code)]
    context: Box<UnsafeCell<LiftContext>>,
    covered: FxHashSet<u64>,
    architecture: Architecture,
    llvm_ir: String,
    untranslated: Vec<Untranslated>,
}

impl Analysis {
    fn covers(&self, address: u64) -> bool {
        self.covered.contains(&address)
    }

    fn artefact(&mut self, stage: &str, container: &str, address: u64) -> Result<Vec<u8>, Error> {
        let stage = CString::new(stage).map_err(|_| Error::pipeline("stage name has a NUL"))?;
        let container =
            CString::new(container).map_err(|_| Error::pipeline("container name has a NUL"))?;
        let whole_binary = container.as_bytes() == b"llvm-root";
        let kind = if whole_binary { c"binary" } else { c"function" };
        let object = CString::new(format!(
            "{address:#x}:Code_{}",
            self.architecture.revng_name()
        ))
        .expect("meta address has no NUL");
        self.manager.produce_artefact(
            &stage,
            &container,
            kind,
            (!whole_binary).then_some(object.as_c_str()),
        )
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
            untranslated: self.untranslated.clone(),
        })
    }
}

pub struct Session {
    decompiler: Decompiler,
    analysis: RefCell<Option<Analysis>>,
    cache: RefCell<FxHashMap<u64, Rc<Output>>>,
}

impl Session {
    pub fn function(&self, address: Address) -> Result<Rc<Output>, Error> {
        let address = address.value();
        if let Some(output) = self.cache.borrow().get(&address) {
            return Ok(Rc::clone(output));
        }

        self.ensure_analysis(address)?;

        let output = {
            let analysis = self.analysis.borrow();
            let analysis = analysis.as_ref().expect("a analysis was built above");
            Rc::new(analysis.decompile(address)?)
        };
        self.cache.borrow_mut().insert(address, Rc::clone(&output));
        Ok(output)
    }

    pub fn module(&self, address: Address, stage: &str, container: &str) -> Result<Vec<u8>, Error> {
        let address = address.value();
        self.ensure_analysis(address)?;
        let mut analysis = self.analysis.borrow_mut();
        analysis
            .as_mut()
            .expect("a analysis was built above")
            .artefact(stage, container, address)
    }

    fn ensure_analysis(&self, address: u64) -> Result<(), Error> {
        let covered =
            matches!(&*self.analysis.borrow(), Some(analysis) if analysis.covers(address));
        if !covered {
            let analysis = self.decompiler.build_analysis(address)?;
            *self.analysis.borrow_mut() = Some(analysis);
        }
        Ok(())
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

struct LiftContext {
    binary: Rc<Binary>,
    architecture: Architecture,
    entry: u64,
    imports: FxHashMap<u64, String>,
    error: CString,
    llvm_ir: String,
    functions: FxHashSet<u64>,
    lifted: FxHashSet<u64>,
    untranslated: Vec<Untranslated>,
    max_depth: Option<u32>,
}

impl LiftContext {
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
        context.max_depth.is_none(),
    );

    let registers = RegisterFile::build(context.binary.language(), context.architecture);
    let outcome = lift(
        module.as_module(),
        context.architecture,
        &registers,
        &context.imports,
        &context.binary,
        &mut lifter,
        entry,
        context.max_depth,
    )
    .and_then(|outcome| {
        context.functions = outcome.callees;
        context.lifted = outcome.lifted;
        context.untranslated = outcome.untranslated;
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

/// Brings revng up. `rp_initialise` runs once per process and takes over LLVM's
/// global state, so a host that shares the process must be able to say which of
/// its signal handlers to keep.
pub fn initialise(preserve_signals: &[i32]) -> Result<(), Error> {
    let mut outcome = Ok(());
    INIT.call_once(|| {
        if unsafe { rp_is_initialised() } {
            return;
        }
        let program = env::args_os()
            .next()
            .and_then(|name| name.into_string().ok())
            .and_then(|name| CString::new(name).ok())
            .unwrap_or_else(|| c"revng".into());
        let argv = [program.as_ptr()];
        let mut signals = preserve_signals.to_vec();
        let started =
            unsafe { rp_initialise(1, argv.as_ptr(), signals.len() as u32, signals.as_mut_ptr()) };
        if !started {
            outcome = Err(Error::pipeline("rp_initialise failed"));
        }
    });
    outcome?;
    if unsafe { rp_is_initialised() } {
        Ok(())
    } else {
        Err(Error::pipeline("revng is not initialised"))
    }
}
