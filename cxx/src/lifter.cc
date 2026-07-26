#include "revng-fugue/cxx/include/lifter.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "rust/cxx.h"

#include "llvm-c/Types.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CBindingWrapping.h"

#include "revng/Lift/JumpTargetManager.h"
#include "revng/Model/Architecture.h"
#include "revng/Model/Binary.h"
#include "revng/Model/FunctionTags.h"
#include "revng/Model/ProgramCounterHandler.h"
#include "revng/Model/RawBinaryView.h"
#include "revng/Support/BasicBlockID.h"
#include "revng/Support/IRBuilder.h"
#include "revng/Support/IRHelperRegistry.h"
#include "revng/Support/MetaAddress.h"

namespace revng_fugue {

namespace {

model::Architecture::Values architecture(std::uint8_t Value) {
  switch (Value) {
  case 0:
    return model::Architecture::x86_64;
  case 1:
    return model::Architecture::aarch64;
  default:
    revng_abort("invalid architecture");
  }
}

class FugueLifter {
public:
  llvm::Module &Module;
  const TupleTree<model::Binary> &Model;
  const RawBinaryView &View;
  model::Architecture::Values Architecture;
  std::unique_ptr<ProgramCounterHandler> PCH;
  llvm::Function *Root;
  llvm::GlobalVariable *PCCSV;
  llvm::Function *NewPCMarker;
  llvm::Function *Identity;
  std::unique_ptr<JumpTargetManager> JTM;
  std::vector<llvm::BasicBlock *> ExitBlocks;

  FugueLifter(llvm::Module &M, const TupleTree<model::Binary> &Model,
              const RawBinaryView &View, model::Architecture::Values Arch,
              llvm::StringRef PCName, llvm::StringRef SPName,
              std::uint64_t Entry)
      : Module(M), Model(Model), View(View), Architecture(Arch) {
    llvm::LLVMContext &Context = M.getContext();

    auto Factory = [&](PCAffectingCSV::Values) -> llvm::GlobalVariable * {
      PCCSV = createCSV(PCName, 8);
      return PCCSV;
    };
    PCH = ProgramCounterHandler::create(Arch, &M, Factory);

    auto *SPCSV = createCSV(SPName, 8);
    auto *RootType =
        llvm::FunctionType::get(llvm::Type::getVoidTy(Context),
                                { SPCSV->getValueType() }, false);
    Root = llvm::Function::Create(RootType, llvm::GlobalValue::ExternalLinkage,
                                  "root", M);
    FunctionTags::Root.addTo(Root);
    Root->addFnAttr(llvm::Attribute::NullPointerIsValid);

    revng::IRBuilder Builder(Context);
    auto *EntryBlock = llvm::BasicBlock::Create(Context, "entrypoint", Root);
    Builder.SetInsertPoint(EntryBlock);
    Builder.CreateStore(Root->arg_begin(), SPCSV);

    auto *Int8Ptr = llvm::PointerType::get(Context, 0);
    auto *NewPCType = llvm::FunctionType::get(
        llvm::Type::getVoidTy(Context),
        { Int8Ptr, llvm::Type::getInt64Ty(Context),
          llvm::Type::getInt32Ty(Context), llvm::Type::getInt32Ty(Context),
          Int8Ptr },
        false);
    NewPCMarker = createIRHelper("newpc", M, NewPCType,
                                 llvm::GlobalValue::ExternalLinkage);
    FunctionTags::Marker.addTo(NewPCMarker);
    NewPCMarker->addFnAttr(llvm::Attribute::WillReturn);
    NewPCMarker->addFnAttr(llvm::Attribute::NoUnwind);
    NewPCMarker->addFnAttr(llvm::Attribute::NoMerge);

    createRecoverySupport();

    JTM = std::make_unique<JumpTargetManager>(Root, PCH.get(), Model, View);
    JTM->harvestGlobalData();

    MetaAddress EntryPC = MetaAddress::fromPC(Arch, Entry);
    JTM->registerJT(EntryPC, JTReason::GlobalData);
    PCH->initializePC(Builder, EntryPC);

    auto *Int8 = Builder.getInt8Ty();
    auto *IdentityType = llvm::FunctionType::get(Int8, { Int8 }, false);
    Identity = llvm::Function::Create(
        IdentityType, llvm::GlobalValue::ExternalLinkage, "id", M);
    Identity->setOnlyReadsMemory();
    auto *Opaque = Builder.CreateCall(Identity, { Builder.getInt8(0) });
    auto *ReachSwitch = Builder.CreateSwitch(Opaque, JTM->dispatcher());
    ReachSwitch->addCase(Builder.getInt8(1), JTM->anyPC());
    ReachSwitch->addCase(Builder.getInt8(2), JTM->unexpectedPC());

    JTM->setCFGForm(CFGForm::SemanticPreserving);
  }

  void createRecoverySupport() {
    llvm::LLVMContext &Context = Module.getContext();
    auto *VoidTy = llvm::Type::getVoidTy(Context);
    auto *Int16 = llvm::Type::getInt16Ty(Context);
    auto *Int32 = llvm::Type::getInt32Ty(Context);
    auto *Int64 = llvm::Type::getInt64Ty(Context);
    auto *Ptr = llvm::PointerType::get(Context, 0);

    auto *PlainMetaAddress = llvm::StructType::get(Context,
                                                   { Int32, Int16, Int16,
                                                     Int64 },
                                                   false);
    for (llvm::StringRef Name : { "current_pc", "last_pc" })
      new llvm::GlobalVariable(Module, PlainMetaAddress, false,
                               llvm::GlobalValue::ExternalLinkage,
                               llvm::ConstantAggregateZero::get(PlainMetaAddress),
                               Name);

    auto *SetType = llvm::FunctionType::get(VoidTy,
                                            { Ptr, Int32, Int16, Int16, Int64 },
                                            false);
    auto *Setter = llvm::Function::Create(SetType,
                                          llvm::GlobalValue::ExternalLinkage,
                                          "set_PlainMetaAddress", Module);
    llvm::ReturnInst::Create(Context,
                             llvm::BasicBlock::Create(Context, "", Setter));

    auto *UnknownPCType = llvm::FunctionType::get(VoidTy, {}, false);
    auto *UnknownPC = llvm::Function::Create(UnknownPCType,
                                             llvm::GlobalValue::ExternalLinkage,
                                             "unknown_pc", Module);
    UnknownPC->addFnAttr(llvm::Attribute::NoReturn);
  }

  llvm::GlobalVariable *createCSV(llvm::StringRef Name, unsigned Bytes) {
    if (auto *Existing = Module.getGlobalVariable(Name, true))
      return Existing;
    auto *Type = llvm::Type::getIntNTy(Module.getContext(), Bytes * 8);
    auto *Global = new llvm::GlobalVariable(Module, Type, false,
                                            llvm::GlobalValue::ExternalLinkage,
                                            llvm::ConstantInt::get(Type, 0),
                                            Name);
    FunctionTags::CSV.addTo(Global);
    return Global;
  }

  llvm::BasicBlock *peek(std::uint64_t &Address) {
    JumpTargetManager::BlockWithAddress Result = JTM->peek();
    if (Result == JumpTargetManager::NoMoreTargets)
      return nullptr;
    Address = Result.first.address();
    return Result.second;
  }
};

}

std::uintptr_t fugue_lifter_new(std::uintptr_t ModelValue,
                                std::uintptr_t ViewValue,
                                std::uintptr_t ModuleValue,
                                std::uint8_t Architecture, rust::Str PCName,
                                rust::Str SPName, std::uint64_t Entry) {
  auto *Model = reinterpret_cast<const TupleTree<model::Binary> *>(ModelValue);
  auto *View = reinterpret_cast<const RawBinaryView *>(ViewValue);
  auto *Module = llvm::unwrap(reinterpret_cast<LLVMModuleRef>(ModuleValue));
  auto *State = new FugueLifter(*Module, *Model, *View,
                                architecture(Architecture),
                                llvm::StringRef(PCName.data(), PCName.size()),
                                llvm::StringRef(SPName.data(), SPName.size()),
                                Entry);
  return reinterpret_cast<std::uintptr_t>(State);
}

void fugue_lifter_free(std::uintptr_t State) {
  delete reinterpret_cast<FugueLifter *>(State);
}

std::uintptr_t fugue_lifter_peek(std::uintptr_t State, std::uint64_t &Address) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  llvm::BasicBlock *Block = Lifter->peek(Address);
  return reinterpret_cast<std::uintptr_t>(llvm::wrap(Block));
}

bool fugue_lifter_diverge(std::uintptr_t State, std::uintptr_t BlockValue,
                          std::uint64_t Address) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  MetaAddress PC = MetaAddress::fromPC(Lifter->Architecture, Address);
  llvm::BasicBlock *DivergeTo = Lifter->JTM->newPC(PC);
  if (DivergeTo == nullptr)
    return false;
  auto *Block = llvm::unwrap(reinterpret_cast<LLVMBasicBlockRef>(BlockValue));
  revng::IRBuilder Builder(Block);
  Builder.CreateBr(DivergeTo);
  return true;
}

void fugue_lifter_new_pc(std::uintptr_t State, std::uintptr_t BlockValue,
                         std::uint64_t Address, std::uint64_t Size,
                         bool IsFirst) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  llvm::LLVMContext &Context = Lifter->Module.getContext();
  MetaAddress PC = MetaAddress::fromPC(Lifter->Architecture, Address);
  auto *Block = llvm::unwrap(reinterpret_cast<LLVMBasicBlockRef>(BlockValue));
  revng::IRBuilder Builder(Block);
  auto *Int8Ptr = llvm::PointerType::get(Context, 0);
  llvm::Value *Arguments[] = {
    BasicBlockID(PC).toValue(&Lifter->Module),
    Builder.getInt64(Size),
    Builder.getInt32(-1),
    Builder.getInt32(0),
    llvm::ConstantPointerNull::get(Int8Ptr)
  };
  auto *Call = Builder.CreateCall(Lifter->NewPCMarker, Arguments);
  if (not IsFirst)
    Lifter->JTM->registerInstruction(PC, Call);
}

void fugue_lifter_exit_constant(std::uintptr_t State, std::uintptr_t BlockValue,
                                std::uint64_t Target) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  auto *Block = llvm::unwrap(reinterpret_cast<LLVMBasicBlockRef>(BlockValue));
  revng::IRBuilder Builder(Block);
  MetaAddress PC = MetaAddress::fromPC(Lifter->Architecture, Target);
  Lifter->PCH->setPC(Builder, PC);
  Builder.CreateCall(Lifter->JTM->exitTB(), { Builder.getInt32(0) });
  Builder.CreateUnreachable();
  Lifter->ExitBlocks.push_back(Block);
}

void fugue_lifter_exit_dynamic(std::uintptr_t State, std::uintptr_t BlockValue,
                               std::uintptr_t ValueRef) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  auto *Block = llvm::unwrap(reinterpret_cast<LLVMBasicBlockRef>(BlockValue));
  auto *Value = llvm::unwrap(reinterpret_cast<LLVMValueRef>(ValueRef));
  revng::IRBuilder Builder(Block);
  Builder.CreateStore(Value, Lifter->PCCSV);
  Builder.CreateCall(Lifter->JTM->exitTB(), { Builder.getInt32(0) });
  Builder.CreateUnreachable();
  Lifter->ExitBlocks.push_back(Block);
}

void fugue_lifter_exit_call(std::uintptr_t State, std::uintptr_t BlockValue,
                            std::uint64_t Target, std::uint64_t ReturnAddress,
                            std::uintptr_t LinkRegisterValue, bool IsImport) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  auto *Block = llvm::unwrap(reinterpret_cast<LLVMBasicBlockRef>(BlockValue));
  llvm::Module &M = Lifter->Module;
  llvm::LLVMContext &Context = M.getContext();
  revng::IRBuilder Builder(Block);

  MetaAddress TargetPC = MetaAddress::fromPC(Lifter->Architecture, Target);
  MetaAddress ReturnPC = MetaAddress::fromPC(Lifter->Architecture,
                                             ReturnAddress);

  auto *Pointer = llvm::PointerType::get(Context, 0);
  llvm::BasicBlock *CalleeBlock = IsImport ?
                                      nullptr :
                                      Lifter->JTM->registerJT(TargetPC,
                                                              JTReason::Callee);
  llvm::BasicBlock *ReturnBlock =
      Lifter->JTM->registerJT(ReturnPC, JTReason::ReturnAddress);

  if (not IsImport)
    Lifter->PCH->setPC(Builder, TargetPC);

  llvm::Function *Marker = M.getFunction("function_call");
  if (Marker == nullptr) {
    auto *Type = llvm::FunctionType::get(llvm::Type::getVoidTy(Context),
                                         { Pointer, Pointer, Pointer, Pointer },
                                         false);
    Marker = llvm::Function::Create(Type, llvm::GlobalValue::InternalLinkage,
                                    "function_call", &M);
    FunctionTags::Marker.addTo(Marker);
    llvm::ReturnInst::Create(Context,
                             llvm::BasicBlock::Create(Context, "", Marker));
  }

  llvm::Constant *Callee = llvm::ConstantPointerNull::get(Pointer);
  if (CalleeBlock != nullptr)
    Callee = llvm::BlockAddress::get(CalleeBlock);
  llvm::Value *LinkRegister =
      LinkRegisterValue != 0 ?
          llvm::unwrap(reinterpret_cast<LLVMValueRef>(LinkRegisterValue)) :
          llvm::cast<llvm::Value>(llvm::ConstantPointerNull::get(Pointer));
  llvm::Value *Arguments[] = { Callee, llvm::BlockAddress::get(ReturnBlock),
                               ReturnPC.toValue(&M), LinkRegister };
  Builder.CreateCall(Marker, Arguments);

  if (IsImport) {
    Builder.CreateCall(Lifter->JTM->exitTB(), { Builder.getInt32(0) });
    Builder.CreateUnreachable();
    Lifter->ExitBlocks.push_back(Block);
  } else {
    Builder.CreateBr(CalleeBlock);
  }
}

void fugue_lifter_register_direct_jumps(std::uintptr_t State) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  for (llvm::BasicBlock *ExitBlock : Lifter->ExitBlocks) {
    auto &&[Result, NextPC] = Lifter->PCH->getUniqueJumpTarget(ExitBlock);
    if (Result == NextJumpTarget::Unique && Lifter->JTM->isPC(NextPC)
        && not Lifter->JTM->hasJT(NextPC))
      Lifter->JTM->registerJT(NextPC, JTReason::DirectJump);
  }
  Lifter->ExitBlocks.clear();
}

void fugue_lifter_finalize(std::uintptr_t State) {
  auto *Lifter = reinterpret_cast<FugueLifter *>(State);
  Lifter->JTM->finalizeJumpTargets();
  Lifter->JTM->createJTReasonMD();

  llvm::SmallVector<llvm::CallInst *, 4> ToErase;
  for (llvm::User *User : Lifter->Identity->users()) {
    auto *Call = llvm::cast<llvm::CallInst>(User);
    Call->replaceAllUsesWith(Call->getArgOperand(0));
    ToErase.push_back(Call);
  }
  for (llvm::CallInst *Call : ToErase)
    Call->eraseFromParent();
  Lifter->Identity->eraseFromParent();
}

}
