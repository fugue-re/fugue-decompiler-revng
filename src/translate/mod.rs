mod registers;

use std::cmp::Ordering;
use std::num::NonZeroU32;

use fugue_core::il::pcode::{Op, PCodeOp, Varnode};
use fugue_core::lifter::Lifter;
use inkwell::basic_block::BasicBlock;
use inkwell::builder::{Builder, BuilderError};
use inkwell::context::ContextRef;
use inkwell::module::{Linkage, Module};
use inkwell::support::LLVMString;
use inkwell::types::IntType;
use inkwell::values::{
    AsValueRef, BasicMetadataValueEnum, FunctionValue, GlobalValue, InstructionValue, IntValue,
};
use inkwell::{AddressSpace, IntPredicate};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::binary::{Architecture, Binary};
use crate::bridge;
use crate::lifter::FugueLifter;

pub(crate) use registers::RegisterFile;

const MAX_INSTRUCTION_BYTES: usize = 16;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TranslateError {
    #[error("LLVM builder error")]
    Builder(#[from] BuilderError),
    #[error("intra-instruction control flow at {address:#x} is not supported")]
    IntraFlow { address: u64 },
    #[error("operation has no output varnode")]
    MissingOutput,
    #[error("the root function is missing from the module")]
    MissingRoot,
    #[error("undefined temporary in space {space} at offset {offset:#x} size {size}")]
    Temporary { space: u8, offset: u64, size: u16 },
    #[error("unrecognised register in space {space} at offset {offset:#x} size {size}")]
    UnknownRegister { space: u8, offset: u64, size: u16 },
    #[error("unsupported pcode operation: {0}")]
    Unsupported(Op),
    #[error("module verification failed: {0}")]
    Verify(LLVMString),
}

impl TranslateError {
    fn register(varnode: &Varnode) -> Self {
        Self::UnknownRegister {
            space: varnode.space(),
            offset: varnode.offset(),
            size: varnode.size() as u16,
        }
    }

    fn temporary(varnode: &Varnode) -> Self {
        Self::Temporary {
            space: varnode.space(),
            offset: varnode.offset(),
            size: varnode.size() as u16,
        }
    }
}

fn raw(value: impl AsValueRef) -> usize {
    value.as_value_ref() as usize
}

fn raw_block(block: BasicBlock<'_>) -> usize {
    block.as_mut_ptr() as usize
}

struct Lifted {
    address: u64,
    size: u8,
    operations: Vec<PCodeOp>,
    undecodable: bool,
}

impl Lifted {
    fn lift(binary: &Binary, lifter: &mut Lifter, address: u64) -> Self {
        let undecodable_size = binary.architecture().minimum_instruction_size();
        let mut buffer = [0u8; MAX_INSTRUCTION_BYTES];
        let read = binary.read(address, &mut buffer).unwrap_or(0);
        if read == 0 {
            return Self {
                address,
                size: undecodable_size,
                operations: Vec::new(),
                undecodable: true,
            };
        }

        let bytes = &buffer[..read];
        let mut operations = Vec::new();
        match lifter.lift_into(address, bytes, &mut operations) {
            Ok(length) => Self {
                address,
                size: length as u8,
                operations,
                undecodable: false,
            },
            Err(_) => Self {
                address,
                size: undecodable_size,
                operations: Vec::new(),
                undecodable: true,
            },
        }
    }

    fn fall(&self) -> u64 {
        self.address + u64::from(self.size)
    }
}

pub(crate) fn lift<'ctx>(
    module: &Module<'ctx>,
    architecture: Architecture,
    registers: &RegisterFile<'_>,
    imports: &FxHashMap<u64, String>,
    binary: &Binary,
    lifter: &mut FugueLifter<'ctx>,
) -> Result<FxHashSet<u64>, TranslateError> {
    let mut translator = Translator::new(module, architecture, registers, imports)?;
    let mut fugue = binary.lifter();
    while let Some((address, block)) = lifter.peek() {
        translator.translate_block(lifter, block, address, binary, &mut fugue)?;
        lifter.register_direct_jumps();
    }
    Ok(translator.callees)
}

struct Translator<'a, 'ctx> {
    module: &'a Module<'ctx>,
    context: ContextRef<'ctx>,
    builder: Builder<'ctx>,
    architecture: Architecture,
    registers: &'a RegisterFile<'a>,
    imports: &'a FxHashMap<u64, String>,
    csvs: FxHashMap<String, GlobalValue<'ctx>>,
    values: FxHashMap<Varnode, IntValue<'ctx>>,
    root: FunctionValue<'ctx>,
    callees: FxHashSet<u64>,
}

impl<'a, 'ctx> Translator<'a, 'ctx> {
    fn new(
        module: &'a Module<'ctx>,
        architecture: Architecture,
        registers: &'a RegisterFile<'a>,
        imports: &'a FxHashMap<u64, String>,
    ) -> Result<Self, TranslateError> {
        let root = module
            .get_function("root")
            .ok_or(TranslateError::MissingRoot)?;
        Ok(Self {
            module,
            context: module.get_context(),
            builder: module.get_context().create_builder(),
            architecture,
            registers,
            imports,
            csvs: FxHashMap::default(),
            values: FxHashMap::default(),
            root,
            callees: FxHashSet::default(),
        })
    }

    fn translate_block(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        block: BasicBlock<'ctx>,
        address: u64,
        binary: &Binary,
        fugue: &mut Lifter,
    ) -> Result<(), TranslateError> {
        self.builder.position_at_end(block);

        let mut addr = address;
        let mut is_first = true;
        loop {
            if !is_first && lifter.diverge(block, addr) {
                return Ok(());
            }

            let instruction = Lifted::lift(binary, fugue, addr);
            lifter.new_pc(
                block,
                instruction.address,
                u64::from(instruction.size),
                is_first,
            );
            self.builder.position_at_end(block);

            if self.translate_instruction(lifter, block, &instruction)? {
                return Ok(());
            }
            addr = instruction.fall();
            is_first = false;
        }
    }

    fn translate_instruction(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        block: BasicBlock<'ctx>,
        instruction: &Lifted,
    ) -> Result<bool, TranslateError> {
        if instruction.undecodable {
            self.emit_abort()?;
            return Ok(true);
        }

        let checkpoint = block.get_last_instruction();
        self.values.clear();
        match self.translate_operations(lifter, block, instruction) {
            Ok(terminated) => Ok(terminated),
            Err(_) => {
                self.rewind(block, checkpoint);
                self.emit_opaque(instruction)?;
                Ok(false)
            }
        }
    }

    fn translate_operations(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        block: BasicBlock<'ctx>,
        instruction: &Lifted,
    ) -> Result<bool, TranslateError> {
        for operation in &instruction.operations {
            match operation.op() {
                Op::Branch => {
                    self.emit_branch(lifter, block, operation, instruction.address)?;
                }
                Op::Call => {
                    self.emit_call(lifter, block, operation, instruction)?;
                }
                Op::CBranch => {
                    self.emit_cbranch(lifter, operation, instruction)?;
                }
                Op::IBranch | Op::ICall | Op::Return => {
                    self.emit_indirect(lifter, block, operation)?;
                }
                Op::Arg | Op::UserOp(_, _) => {
                    return Err(TranslateError::Unsupported(operation.op()));
                }
                _ => {
                    self.translate_operation(operation)?;
                    continue;
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn rewind(&mut self, block: BasicBlock<'ctx>, checkpoint: Option<InstructionValue<'ctx>>) {
        self.values.clear();
        while let Some(last) = block.get_last_instruction() {
            if Some(last) == checkpoint {
                break;
            }
            last.erase_from_basic_block();
        }
        self.builder.position_at_end(block);
    }

    fn emit_abort(&self) -> Result<(), TranslateError> {
        let abort = self.revng_abort();
        let message = self
            .builder
            .build_global_string_ptr("unsupported instruction", "")?;
        self.builder
            .build_call(abort, &[message.as_pointer_value().into()], "")?;
        self.builder.build_unreachable()?;
        Ok(())
    }

    fn revng_abort(&self) -> FunctionValue<'ctx> {
        if let Some(function) = self.module.get_function("revng_abort") {
            return function;
        }
        let ptr = self.context.ptr_type(AddressSpace::default());
        let ty = self.context.void_type().fn_type(&[ptr.into()], false);
        let function = self
            .module
            .add_function("revng_abort", ty, Some(Linkage::External));
        unsafe { bridge::tag_helper(raw(function)) };
        function
    }

    fn emit_opaque(&mut self, instruction: &Lifted) -> Result<(), TranslateError> {
        let userop = instruction.operations.iter().find_map(|operation| {
            if let Op::UserOp(id, _) = operation.op() {
                self.registers.user_operation(id)
            } else {
                None
            }
        });
        let sanitise = |name: &str| -> String {
            name.chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character.to_ascii_lowercase()
                    } else {
                        '_'
                    }
                })
                .collect()
        };
        let name = match userop {
            Some(userop) => format!("__unsupported_{}", sanitise(userop)),
            None => "__unsupported".to_owned(),
        };

        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let mut read = FxHashSet::default();
        let mut written = FxHashSet::default();
        for operation in &instruction.operations {
            for input in operation.inputs() {
                if let Some(global) = self.register_global(input, &mut read) {
                    reads.push(global);
                }
            }
            if let Some(output) = operation.output()
                && let Some(global) = self.register_global(output, &mut written)
            {
                writes.push(global);
            }
        }

        let block = raw_block(self.builder.get_insert_block().expect("an open block"));
        unsafe { bridge::emit_unsupported(block, &name, &reads, &writes) };
        Ok(())
    }

    fn register_global(
        &mut self,
        varnode: &Varnode,
        seen: &mut FxHashSet<String>,
    ) -> Option<usize> {
        if varnode.space() != self.registers.space() {
            return None;
        }
        let access = self.registers.resolve(varnode)?;
        if !seen.insert(access.csv.clone()) {
            return None;
        }
        let global = self.csv(&access.csv, access.register_size);
        Some(raw(global.as_pointer_value()))
    }

    fn emit_branch(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        block: BasicBlock<'ctx>,
        operation: &PCodeOp,
        address: u64,
    ) -> Result<(), TranslateError> {
        let target = operation.inputs()[0];
        if target.is_constant() {
            return Err(TranslateError::IntraFlow { address });
        }
        lifter.exit_constant(block, target.offset());
        Ok(())
    }

    fn emit_cbranch(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        operation: &PCodeOp,
        instruction: &Lifted,
    ) -> Result<(), TranslateError> {
        let inputs = operation.inputs();
        let target = inputs[0];
        if target.is_constant() {
            return Err(TranslateError::IntraFlow {
                address: instruction.address,
            });
        }
        let condition = self.read(&inputs[1])?;
        let condition = self
            .builder
            .build_int_truncate(condition, self.context.bool_type(), "")?;

        let taken = self.context.append_basic_block(self.root, "");
        let fall = self.context.append_basic_block(self.root, "");
        self.builder
            .build_conditional_branch(condition, taken, fall)?;

        lifter.exit_constant(taken, target.offset());
        lifter.exit_constant(fall, instruction.fall());
        Ok(())
    }

    fn emit_call(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        block: BasicBlock<'ctx>,
        operation: &PCodeOp,
        instruction: &Lifted,
    ) -> Result<(), TranslateError> {
        let target = operation.inputs()[0];
        if target.is_constant() {
            return Err(TranslateError::IntraFlow {
                address: instruction.address,
            });
        }
        let symbol = self.imports.get(&target.offset()).cloned();
        if symbol.is_none() {
            self.callees.insert(target.offset());
        }
        let link_register = self
            .architecture
            .link_register_csv()
            .map(|name| self.csv(name, 8).as_pointer_value());
        lifter.exit_call(
            block,
            target.offset(),
            instruction.fall(),
            link_register,
            symbol.is_some(),
        );
        if let Some(symbol) = &symbol {
            let terminator = block
                .get_terminator()
                .expect("the call block is terminated");
            unsafe { bridge::emit_jump_to_symbol(raw(terminator), symbol) };
        }
        Ok(())
    }

    fn emit_indirect(
        &mut self,
        lifter: &mut FugueLifter<'ctx>,
        block: BasicBlock<'ctx>,
        operation: &PCodeOp,
    ) -> Result<(), TranslateError> {
        let target = self.read(&operation.inputs()[0])?;
        let target = self.coerce_pc(target)?;
        lifter.exit_dynamic(block, target);
        Ok(())
    }

    fn coerce_pc(&self, value: IntValue<'ctx>) -> Result<IntValue<'ctx>, TranslateError> {
        let i64 = self.context.i64_type();
        Ok(match value.get_type().get_bit_width().cmp(&64) {
            Ordering::Equal => value,
            Ordering::Less => self.builder.build_int_z_extend(value, i64, "")?,
            Ordering::Greater => self.builder.build_int_truncate(value, i64, "")?,
        })
    }

    fn translate_operation(&mut self, operation: &PCodeOp) -> Result<(), TranslateError> {
        let inputs = operation.inputs();
        match operation.op() {
            Op::Copy => {
                let value = self.read(&inputs[0])?;
                self.write(operation, value)
            }
            Op::Load(_) => {
                let address = self.read(&inputs[0])?;
                let output = operation.output().ok_or(TranslateError::MissingOutput)?;
                let element = self.int_type(output.size() as u16);
                let pointer = self.builder.build_int_to_ptr(
                    address,
                    self.context.ptr_type(AddressSpace::default()),
                    "",
                )?;
                let value = self
                    .builder
                    .build_load(element, pointer, "")?
                    .into_int_value();
                self.write(operation, value)
            }
            Op::Store(_) => {
                let address = self.read(&inputs[0])?;
                let value = self.read(&inputs[1])?;
                let pointer = self.builder.build_int_to_ptr(
                    address,
                    self.context.ptr_type(AddressSpace::default()),
                    "",
                )?;
                self.builder.build_store(pointer, value)?;
                Ok(())
            }
            Op::IntAdd => self.arithmetic(operation, |b, l, r| b.build_int_add(l, r, "")),
            Op::IntSub => self.arithmetic(operation, |b, l, r| b.build_int_sub(l, r, "")),
            Op::IntMul => self.arithmetic(operation, |b, l, r| b.build_int_mul(l, r, "")),
            Op::IntDiv => self.arithmetic(operation, |b, l, r| b.build_int_unsigned_div(l, r, "")),
            Op::IntSignedDiv => {
                self.arithmetic(operation, |b, l, r| b.build_int_signed_div(l, r, ""))
            }
            Op::IntRem => self.arithmetic(operation, |b, l, r| b.build_int_unsigned_rem(l, r, "")),
            Op::IntSignedRem => {
                self.arithmetic(operation, |b, l, r| b.build_int_signed_rem(l, r, ""))
            }
            Op::IntAnd | Op::BoolAnd => self.arithmetic(operation, |b, l, r| b.build_and(l, r, "")),
            Op::IntOr | Op::BoolOr => self.arithmetic(operation, |b, l, r| b.build_or(l, r, "")),
            Op::IntXor | Op::BoolXor => self.arithmetic(operation, |b, l, r| b.build_xor(l, r, "")),
            Op::IntLeftShift => self.arithmetic(operation, |b, l, r| b.build_left_shift(l, r, "")),
            Op::IntRightShift => {
                self.arithmetic(operation, |b, l, r| b.build_right_shift(l, r, false, ""))
            }
            Op::IntSignedRightShift => {
                self.arithmetic(operation, |b, l, r| b.build_right_shift(l, r, true, ""))
            }
            Op::IntEq => self.compare(operation, IntPredicate::EQ),
            Op::IntNotEq => self.compare(operation, IntPredicate::NE),
            Op::IntLess => self.compare(operation, IntPredicate::ULT),
            Op::IntSignedLess => self.compare(operation, IntPredicate::SLT),
            Op::IntLessEq => self.compare(operation, IntPredicate::ULE),
            Op::IntSignedLessEq => self.compare(operation, IntPredicate::SLE),
            Op::IntCarry => {
                let left = self.read(&inputs[0])?;
                let right = self.read(&inputs[1])?;
                let sum = self.builder.build_int_add(left, right, "")?;
                let bit = self
                    .builder
                    .build_int_compare(IntPredicate::ULT, sum, left, "")?;
                self.write_bool(operation, bit)
            }
            Op::IntSignedCarry => {
                let left = self.read(&inputs[0])?;
                let right = self.read(&inputs[1])?;
                let sum = self.builder.build_int_add(left, right, "")?;
                let overflow = self.overflow_sign(left, right, sum)?;
                self.write_bool(operation, overflow)
            }
            Op::IntSignedBorrow => {
                let left = self.read(&inputs[0])?;
                let right = self.read(&inputs[1])?;
                let difference = self.builder.build_int_sub(left, right, "")?;
                let overflow = self.overflow_sign(left, difference, right)?;
                self.write_bool(operation, overflow)
            }
            Op::IntNot => self.unary(operation, |b, v| b.build_int_neg(v, "")),
            Op::IntNeg => self.unary(operation, |b, v| b.build_not(v, "")),
            Op::BoolNot => {
                let value = self.read(&inputs[0])?;
                let result =
                    self.builder
                        .build_xor(value, value.get_type().const_int(1, false), "")?;
                self.write(operation, result)
            }
            Op::ZeroExt => self.extend(operation, false),
            Op::SignExt => self.extend(operation, true),
            Op::Subpiece => {
                let value = self.read(&inputs[0])?;
                let output = operation.output().ok_or(TranslateError::MissingOutput)?;
                let shift = value.get_type().const_int(inputs[1].offset() * 8, false);
                let shifted = self.builder.build_right_shift(value, shift, false, "")?;
                let truncated = self.builder.build_int_truncate(
                    shifted,
                    self.int_type(output.size() as u16),
                    "",
                )?;
                self.write(operation, truncated)
            }
            Op::CountOnes => self.count(operation, "llvm.ctpop"),
            Op::CountLeadingZeros => self.count(operation, "llvm.ctlz"),
            other => Err(TranslateError::Unsupported(other)),
        }
    }

    fn arithmetic(
        &mut self,
        operation: &PCodeOp,
        build: impl Fn(
            &Builder<'ctx>,
            IntValue<'ctx>,
            IntValue<'ctx>,
        ) -> Result<IntValue<'ctx>, BuilderError>,
    ) -> Result<(), TranslateError> {
        let inputs = operation.inputs();
        let left = self.read(&inputs[0])?;
        let right = self.read(&inputs[1])?;
        let result = build(&self.builder, left, right)?;
        self.write(operation, result)
    }

    fn unary(
        &mut self,
        operation: &PCodeOp,
        build: impl Fn(&Builder<'ctx>, IntValue<'ctx>) -> Result<IntValue<'ctx>, BuilderError>,
    ) -> Result<(), TranslateError> {
        let value = self.read(&operation.inputs()[0])?;
        let result = build(&self.builder, value)?;
        self.write(operation, result)
    }

    fn compare(
        &mut self,
        operation: &PCodeOp,
        predicate: IntPredicate,
    ) -> Result<(), TranslateError> {
        let inputs = operation.inputs();
        let left = self.read(&inputs[0])?;
        let right = self.read(&inputs[1])?;
        let bit = self.builder.build_int_compare(predicate, left, right, "")?;
        self.write_bool(operation, bit)
    }

    fn overflow_sign(
        &self,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
        result: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>, TranslateError> {
        let left_result = self.builder.build_xor(left, result, "")?;
        let right_result = self.builder.build_xor(right, result, "")?;
        let both = self.builder.build_and(left_result, right_result, "")?;
        Ok(self.builder.build_int_compare(
            IntPredicate::SLT,
            both,
            both.get_type().const_zero(),
            "",
        )?)
    }

    fn extend(&mut self, operation: &PCodeOp, signed: bool) -> Result<(), TranslateError> {
        let value = self.read(&operation.inputs()[0])?;
        let output = operation.output().ok_or(TranslateError::MissingOutput)?;
        let target = self.int_type(output.size() as u16);
        let result = if signed {
            self.builder.build_int_s_extend(value, target, "")?
        } else {
            self.builder.build_int_z_extend(value, target, "")?
        };
        self.write(operation, result)
    }

    fn count(&mut self, operation: &PCodeOp, intrinsic: &str) -> Result<(), TranslateError> {
        let value = self.read(&operation.inputs()[0])?;
        let output = operation.output().ok_or(TranslateError::MissingOutput)?;
        let counted = self.count_intrinsic(intrinsic, value)?;
        let target = self.int_type(output.size() as u16);
        let result = match counted
            .get_type()
            .get_bit_width()
            .cmp(&target.get_bit_width())
        {
            Ordering::Equal => counted,
            Ordering::Less => self.builder.build_int_z_extend(counted, target, "")?,
            Ordering::Greater => self.builder.build_int_truncate(counted, target, "")?,
        };
        self.write(operation, result)
    }

    fn count_intrinsic(
        &self,
        intrinsic: &str,
        value: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>, TranslateError> {
        let width = value.get_type();
        let leading_zeros = intrinsic == "llvm.ctlz";
        let name = format!("{intrinsic}.i{}", width.get_bit_width());
        let function = self.module.get_function(&name).unwrap_or_else(|| {
            let signature = if leading_zeros {
                width.fn_type(&[width.into(), self.context.bool_type().into()], false)
            } else {
                width.fn_type(&[width.into()], false)
            };
            self.module.add_function(&name, signature, None)
        });
        let arguments: Vec<BasicMetadataValueEnum> = if leading_zeros {
            vec![value.into(), self.context.bool_type().const_zero().into()]
        } else {
            vec![value.into()]
        };
        let result = self.builder.build_call(function, &arguments, "")?;
        Ok(result.try_as_basic_value().unwrap_basic().into_int_value())
    }

    fn read(&mut self, varnode: &Varnode) -> Result<IntValue<'ctx>, TranslateError> {
        let width = self.int_type(varnode.size() as u16);
        if varnode.is_constant() {
            return Ok(width.const_int(varnode.offset(), false));
        }
        if varnode.space() == self.registers.space() {
            let access = self
                .registers
                .resolve(varnode)
                .ok_or_else(|| TranslateError::register(varnode))?;
            let register_type = self.int_type(access.register_size);
            let global = self.csv(&access.csv, access.register_size);
            let mut value = self
                .builder
                .build_load(register_type, global.as_pointer_value(), "")?
                .into_int_value();
            if access.byte_offset != 0 {
                value = self.builder.build_right_shift(
                    value,
                    register_type.const_int(access.byte_offset * 8, false),
                    false,
                    "",
                )?;
            }
            if register_type.get_bit_width() != width.get_bit_width() {
                value = self.builder.build_int_truncate(value, width, "")?;
            }
            return Ok(value);
        }
        self.values
            .get(varnode)
            .copied()
            .ok_or_else(|| TranslateError::temporary(varnode))
    }

    fn write(&mut self, operation: &PCodeOp, value: IntValue<'ctx>) -> Result<(), TranslateError> {
        let output = operation.output().ok_or(TranslateError::MissingOutput)?;
        self.write_varnode(output, value)
    }

    fn write_bool(
        &mut self,
        operation: &PCodeOp,
        bit: IntValue<'ctx>,
    ) -> Result<(), TranslateError> {
        let output = operation.output().ok_or(TranslateError::MissingOutput)?;
        let value =
            self.builder
                .build_int_z_extend(bit, self.int_type(output.size() as u16), "")?;
        self.write_varnode(output, value)
    }

    fn write_varnode(
        &mut self,
        varnode: &Varnode,
        value: IntValue<'ctx>,
    ) -> Result<(), TranslateError> {
        if varnode.space() != self.registers.space() {
            self.values.insert(*varnode, value);
            return Ok(());
        }
        let access = self
            .registers
            .resolve(varnode)
            .ok_or_else(|| TranslateError::register(varnode))?;
        let register_type = self.int_type(access.register_size);
        let global = self.csv(&access.csv, access.register_size);
        if access.byte_offset == 0 && access.size == access.register_size {
            return self.store(global, value);
        }
        let old = self
            .builder
            .build_load(register_type, global.as_pointer_value(), "")?
            .into_int_value();
        let widened = self.builder.build_int_z_extend(value, register_type, "")?;
        let bits = access.byte_offset * 8;
        let shifted =
            self.builder
                .build_left_shift(widened, register_type.const_int(bits, false), "")?;
        let ones: u64 = if access.size >= 8 {
            u64::MAX
        } else {
            (1u64 << (u32::from(access.size) * 8)) - 1
        };
        let mask = !(ones << bits);
        let cleared = self
            .builder
            .build_and(old, register_type.const_int(mask, false), "")?;
        let merged = self.builder.build_or(cleared, shifted, "")?;
        self.store(global, merged)
    }

    fn csv(&mut self, name: &str, size: u16) -> GlobalValue<'ctx> {
        if let Some(global) = self.csvs.get(name) {
            return *global;
        }
        let global = self.module.get_global(name).unwrap_or_else(|| {
            let ty = self.int_type(size);
            let global = self.module.add_global(ty, None, name);
            global.set_linkage(Linkage::External);
            global.set_initializer(&ty.const_zero());
            unsafe { bridge::tag_csv(raw(global)) };
            global
        });
        self.csvs.insert(name.to_owned(), global);
        global
    }

    fn store(
        &self,
        global: GlobalValue<'ctx>,
        value: IntValue<'ctx>,
    ) -> Result<(), TranslateError> {
        self.builder.build_store(global.as_pointer_value(), value)?;
        Ok(())
    }

    fn int_type(&self, bytes: u16) -> IntType<'ctx> {
        let bits = NonZeroU32::new(u32::from(bytes) * 8).expect("varnode size is non-zero");
        self.context
            .custom_width_int_type(bits)
            .expect("valid integer width")
    }
}
