use std::mem::ManuallyDrop;
use std::ops::Deref;

use inkwell::module::Module;

/// An Inkwell view of an LLVM module owned by revng. The view never disposes
/// the underlying module; it is scoped to the revng callback that supplied it.
pub struct BorrowedModule<'callback> {
    module: ManuallyDrop<Module<'callback>>,
}

impl<'callback> BorrowedModule<'callback> {
    pub fn as_module(&self) -> &Module<'callback> {
        &self.module
    }

    /// # Safety
    ///
    /// `module` must be non-null and remain valid for `'callback`, with
    /// exclusive access for any mutations performed through the returned view.
    pub unsafe fn from_raw(module: revng_sys::LLVMModuleRef) -> Self {
        assert!(!module.is_null(), "revng supplied a null LLVM module");
        Self {
            module: ManuallyDrop::new(unsafe { Module::new(module.cast()) }),
        }
    }
}

impl<'callback> Deref for BorrowedModule<'callback> {
    type Target = Module<'callback>;

    fn deref(&self) -> &Self::Target {
        self.as_module()
    }
}
