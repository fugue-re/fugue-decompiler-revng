use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::NonNull;

use inkwell::basic_block::BasicBlock;
use inkwell::llvm_sys::prelude::LLVMBasicBlockRef;
use inkwell::module::Module;
use inkwell::values::{AsValueRef, IntValue, PointerValue};

use crate::binary::Architecture;
use crate::bridge;

#[repr(C)]
struct State {
    _private: [u8; 0],
}

pub(crate) struct FugueLifter<'ctx> {
    handle: NonNull<State>,
    _module: PhantomData<&'ctx ()>,
}

impl<'ctx> FugueLifter<'ctx> {
    pub(crate) fn new(
        module: &Module<'ctx>,
        model: *const c_void,
        view: *const revng_sys::rp_binary_view,
        architecture: Architecture,
        entry: u64,
    ) -> Self {
        let handle = unsafe {
            bridge::fugue_lifter_new(
                model as usize,
                view as usize,
                module.as_mut_ptr() as usize,
                architecture.tag_id(),
                architecture.pc_csv(),
                architecture.stack_pointer_csv(),
                entry,
            )
        };
        let handle = NonNull::new(handle as *mut State).expect("fugue_lifter_new returned null");
        Self {
            handle,
            _module: PhantomData,
        }
    }

    fn raw(&self) -> usize {
        self.handle.as_ptr() as usize
    }

    pub(crate) fn peek(&mut self) -> Option<(u64, BasicBlock<'ctx>)> {
        let mut address = 0u64;
        let block = unsafe { bridge::fugue_lifter_peek(self.raw(), &mut address) };
        let block = unsafe { BasicBlock::new(block as LLVMBasicBlockRef) }?;
        Some((address, block))
    }

    pub(crate) fn diverge(&mut self, block: BasicBlock<'ctx>, address: u64) -> bool {
        unsafe { bridge::fugue_lifter_diverge(self.raw(), block.as_mut_ptr() as usize, address) }
    }

    pub(crate) fn new_pc(&mut self, block: BasicBlock<'ctx>, address: u64, size: u64, first: bool) {
        unsafe {
            bridge::fugue_lifter_new_pc(
                self.raw(),
                block.as_mut_ptr() as usize,
                address,
                size,
                first,
            );
        }
    }

    pub(crate) fn exit_constant(&mut self, block: BasicBlock<'ctx>, target: u64) {
        unsafe {
            bridge::fugue_lifter_exit_constant(self.raw(), block.as_mut_ptr() as usize, target)
        };
    }

    pub(crate) fn exit_dynamic(&mut self, block: BasicBlock<'ctx>, value: IntValue<'ctx>) {
        unsafe {
            bridge::fugue_lifter_exit_dynamic(
                self.raw(),
                block.as_mut_ptr() as usize,
                value.as_value_ref() as usize,
            );
        }
    }

    pub(crate) fn exit_call(
        &mut self,
        block: BasicBlock<'ctx>,
        target: u64,
        return_address: u64,
        link_register: Option<PointerValue<'ctx>>,
        is_import: bool,
    ) {
        let link_register = link_register.map_or(0, |register| register.as_value_ref() as usize);
        unsafe {
            bridge::fugue_lifter_exit_call(
                self.raw(),
                block.as_mut_ptr() as usize,
                target,
                return_address,
                link_register,
                is_import,
            );
        }
    }

    pub(crate) fn register_direct_jumps(&mut self) {
        unsafe { bridge::fugue_lifter_register_direct_jumps(self.raw()) };
    }

    pub(crate) fn finalise(&mut self) {
        unsafe { bridge::fugue_lifter_finalize(self.raw()) };
    }
}

impl Drop for FugueLifter<'_> {
    fn drop(&mut self) {
        unsafe { bridge::fugue_lifter_free(self.raw()) };
    }
}
