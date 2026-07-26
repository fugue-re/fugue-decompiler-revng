#include "revng-fugue/cxx/include/tags.h"

#include <cstddef>
#include <cstdint>

#include "rust/cxx.h"

#include "llvm-c/Types.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/CBindingWrapping.h"

#include "revng/Model/Architecture.h"
#include "revng/Model/FunctionTags.h"
#include "revng/Support/Assert.h"
#include "revng/Support/BasicBlockID.h"
#include "revng/Support/BlockType.h"
#include "revng/Support/MetaAddress.h"
#include "revng/Support/ResourceFinder.h"

namespace revng_fugue {

void tag_helper(std::uintptr_t Value) {
  auto *Function = llvm::cast<llvm::Function>(
      llvm::unwrap(reinterpret_cast<LLVMValueRef>(Value)));
  FunctionTags::Helper.addTo(Function);
}

void tag_csv(std::uintptr_t Value) {
  auto *Global = llvm::cast<llvm::GlobalVariable>(
      llvm::unwrap(reinterpret_cast<LLVMValueRef>(Value)));
  FunctionTags::CSV.addTo(Global);
}

void emit_jump_to_symbol(std::uintptr_t TerminatorValue, rust::Str Symbol) {
  auto *Terminator = llvm::cast<llvm::Instruction>(
      llvm::unwrap(reinterpret_cast<LLVMValueRef>(TerminatorValue)));
  llvm::Module *Module = Terminator->getModule();
  llvm::LLVMContext &Context = Module->getContext();

  llvm::Function *Marker = Module->getFunction("jump_to_symbol");
  if (Marker == nullptr) {
    auto *Pointer = llvm::PointerType::get(Context, 0);
    auto *Type = llvm::FunctionType::get(llvm::Type::getVoidTy(Context),
                                         { Pointer }, false);
    Marker = llvm::Function::Create(Type, llvm::GlobalValue::ExternalLinkage,
                                    "jump_to_symbol", Module);
    FunctionTags::Marker.addTo(Marker);
  }

  llvm::IRBuilder<> Builder(Terminator);
  llvm::Value *Name = Builder.CreateGlobalStringPtr(
      llvm::StringRef(Symbol.data(), Symbol.size()));
  Builder.CreateCall(Marker, { Name });
}

static void set_csv_metadata(llvm::Function *Function, llvm::StringRef Kind,
                             rust::Slice<const std::uintptr_t> Globals) {
  llvm::LLVMContext &Context = Function->getContext();
  llvm::SmallVector<llvm::Metadata *, 8> Entries;
  for (std::uintptr_t Global : Globals) {
    auto *Variable = llvm::cast<llvm::GlobalVariable>(
        llvm::unwrap(reinterpret_cast<LLVMValueRef>(Global)));
    Entries.push_back(llvm::MDString::get(Context, Variable->getName()));
  }
  llvm::Metadata *Zero = llvm::ConstantAsMetadata::get(
      llvm::ConstantInt::get(llvm::Type::getInt32Ty(Context), 0));
  llvm::Metadata *Inner = llvm::MDTuple::get(Context, Entries);
  Function->setMetadata(Kind, llvm::MDTuple::get(Context, { Zero, Inner }));
}

void emit_unsupported(std::uintptr_t BlockValue, rust::Str Name,
                      rust::Slice<const std::uintptr_t> Reads,
                      rust::Slice<const std::uintptr_t> Writes) {
  auto *Block = llvm::unwrap(reinterpret_cast<LLVMBasicBlockRef>(BlockValue));
  llvm::Module *Module = Block->getParent()->getParent();
  llvm::LLVMContext &Context = Module->getContext();
  llvm::StringRef FunctionName(Name.data(), Name.size());

  llvm::Function *Function = Module->getFunction(FunctionName);
  if (Function == nullptr) {
    auto *Type = llvm::FunctionType::get(llvm::Type::getVoidTy(Context), {},
                                         false);
    Function = llvm::Function::Create(Type, llvm::GlobalValue::ExternalLinkage,
                                      FunctionName, Module);
    FunctionTags::Helper.addTo(Function);
    set_csv_metadata(Function, "revng.csvaccess.offsets.load", Reads);
    set_csv_metadata(Function, "revng.csvaccess.offsets.store", Writes);
  }
  llvm::CallInst::Create(Function->getFunctionType(), Function, {}, "", Block);
}

rust::String default_pipeline() {
  auto Path = revng::ResourceFinder.findFile("share/revng/pipelines/"
                                             "revng-pipelines.yml");
  if (not Path or Path->empty())
    return rust::String();
  return rust::String(*Path);
}

}
