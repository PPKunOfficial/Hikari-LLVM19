// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "include/IndirectBranch.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

static cl::opt<bool>
    UseStack("indibran-use-stack", cl::init(true), cl::NotHidden,
             cl::desc("[IndirectBranch]Stack-based indirect jumps"));
static bool UseStackTemp = true;

static cl::opt<bool>
    EncryptJumpTarget("indibran-enc-jump-target", cl::init(false),
                      cl::NotHidden,
                      cl::desc("[IndirectBranch]Encrypt jump target"));
static bool EncryptJumpTargetTemp = false;

namespace llvm {
struct IndirectBranch : public FunctionPass {
  static char ID;
  bool flag;
  bool initialized;
  std::unordered_map<BasicBlock *, unsigned long long> indexmap;
  std::unordered_map<Function *, ConstantInt *> encmap;
  std::unordered_set<Function *> to_obf_funcs;
  IndirectBranch() : FunctionPass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  IndirectBranch(bool flag) : FunctionPass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "IndirectBranch"; }
  bool initialize(Module &M) {
    PassBuilder PB;
    FunctionAnalysisManager FAM;
    FunctionPassManager FPM;
    PB.registerFunctionAnalyses(FAM);
    FPM.addPass(LowerSwitchPass());

    SmallVector<Constant *, 32> BBs;
    unsigned long long i = 0;
    for (Function &F : M) {
      if (!toObfuscate(flag, &F, "indibr"))
        continue;
      else
        to_obf_funcs.insert(&F);
      if (!toObfuscateBoolOption(&F, "indibran_use_stack", &UseStackTemp))
        UseStackTemp = UseStack;

      // See https://github.com/61bcdefg/Hikari-LLVM15/issues/32
      FPM.run(F, FAM);

      if (!toObfuscateBoolOption(&F, "indibran_enc_jump_target",
                                 &EncryptJumpTargetTemp))
        EncryptJumpTargetTemp = EncryptJumpTarget;

      if (EncryptJumpTargetTemp)
        encmap[&F] = ConstantInt::get(
            Type::getInt32Ty(M.getContext()),
            cryptoutils->get_range(UINT8_MAX, UINT16_MAX * 2) * 4);
      for (BasicBlock &BB : F)
        if (!BB.isEntryBlock()) {
          indexmap[&BB] = i++;
          BBs.emplace_back(
              EncryptJumpTargetTemp
                  ? ConstantExpr::getGetElementPtr(
                        Type::getInt8Ty(M.getContext()),
                        ConstantExpr::getBitCast(
                            BlockAddress::get(&BB),
                            Type::getInt8Ty(M.getContext())->getPointerTo()),
                        encmap[&F])
                  : BlockAddress::get(&BB));
        }
    }
    if (to_obf_funcs.size()) {
      ArrayType *AT = ArrayType::get(
          Type::getInt8Ty(M.getContext())->getPointerTo(), BBs.size());
      Constant *BlockAddressArray =
          ConstantArray::get(AT, ArrayRef<Constant *>(BBs));
      GlobalVariable *Table = new GlobalVariable(
          M, AT, false, GlobalValue::LinkageTypes::PrivateLinkage,
          BlockAddressArray, "IndirectBranchingGlobalTable");
      appendToCompilerUsed(M, {Table});
    }
    this->initialized = true;
    return true;
  }
  bool runOnFunction(Function &Func) override {
    Module *M = Func.getParent();
    if (!this->initialized)
      initialize(*M);
    if (std::find(to_obf_funcs.begin(), to_obf_funcs.end(), &Func) ==
        to_obf_funcs.end())
      return false;
    errs() << "Running IndirectBranch On " << Func.getName() << "\n";
    SmallVector<BranchInst *, 32> BIs;
    for (Instruction &Inst : instructions(Func))
      if (BranchInst *BI = dyn_cast<BranchInst>(&Inst))
        BIs.emplace_back(BI);

    Type *Int8Ty = Type::getInt8Ty(M->getContext());
    Type *Int32Ty = Type::getInt32Ty(M->getContext());
    Type *Int8PtrTy = Type::getInt8Ty(M->getContext())->getPointerTo();

    Value *zero = ConstantInt::get(Int32Ty, 0);

    IRBuilder<NoFolder> *IRBEntry =
        new IRBuilder<NoFolder>(&Func.getEntryBlock().front());
    for (BranchInst *BI : BIs) {
      if (UseStackTemp &&
          IRBEntry->GetInsertPoint() !=
              (BasicBlock::iterator)Func.getEntryBlock().front())
        IRBEntry->SetInsertPoint(Func.getEntryBlock().getTerminator());
      IRBuilder<NoFolder> *IRBBI = new IRBuilder<NoFolder>(BI);
      SmallVector<BasicBlock *, 2> BBs;
      // We use the condition's evaluation result to generate the GEP
      // instruction  False evaluates to 0 while true evaluates to 1.  So here
      // we insert the false block first
      if (BI->isConditional() && !BI->getSuccessor(1)->isEntryBlock())
        BBs.emplace_back(BI->getSuccessor(1));
      if (!BI->getSuccessor(0)->isEntryBlock())
        BBs.emplace_back(BI->getSuccessor(0));

      GlobalVariable *LoadFrom = nullptr;
      if (BI->isConditional() ||
          indexmap.find(BI->getSuccessor(0)) == indexmap.end()) {
        ArrayType *AT = ArrayType::get(Int8PtrTy, BBs.size());
        SmallVector<Constant *, 2> BlockAddresses;
        for (BasicBlock *BB : BBs)
          BlockAddresses.emplace_back(
              EncryptJumpTargetTemp ? ConstantExpr::getGetElementPtr(
                                          Int8Ty,
                                          ConstantExpr::getBitCast(
                                              BlockAddress::get(BB), Int8PtrTy),
                                          encmap[&Func])
                                    : BlockAddress::get(BB));
        // Create a new GV
        Constant *BlockAddressArray =
            ConstantArray::get(AT, ArrayRef<Constant *>(BlockAddresses));
        LoadFrom = new GlobalVariable(
            *M, AT, false, GlobalValue::LinkageTypes::PrivateLinkage,
            BlockAddressArray, "HikariConditionalLocalIndirectBranchingTable");
        appendToCompilerUsed(*Func.getParent(), {LoadFrom});
      } else {
        LoadFrom = M->getGlobalVariable("IndirectBranchingGlobalTable", true);
      }
      AllocaInst *LoadFromAI = nullptr;
      if (UseStackTemp) {
        LoadFromAI = IRBEntry->CreateAlloca(LoadFrom->getType());
        IRBEntry->CreateStore(LoadFrom, LoadFromAI);
      }
      Value *index, *RealIndex = nullptr;
      if (BI->isConditional()) {
        Value *condition = BI->getCondition();
        Value *zext = IRBBI->CreateZExt(condition, Int32Ty);
        if (UseStackTemp) {
          AllocaInst *condAI = IRBEntry->CreateAlloca(Int32Ty);
          IRBBI->CreateStore(zext, condAI);
          index = condAI;
        } else {
          index = zext;
        }
        RealIndex = index;
      } else {
        Value *indexval = nullptr;
        ConstantInt *IndexEncKey =
            EncryptJumpTargetTemp ? cast<ConstantInt>(ConstantInt::get(
                                        Int32Ty, cryptoutils->get_uint32_t()))
                                  : nullptr;
        if (EncryptJumpTargetTemp) {
          GlobalVariable *indexgv = new GlobalVariable(
              *M, Int32Ty, false, GlobalValue::LinkageTypes::PrivateLinkage,
              ConstantInt::get(IndexEncKey->getType(),
                               IndexEncKey->getValue() ^
                                   indexmap[BI->getSuccessor(0)]),
              "IndirectBranchingIndex");
          appendToCompilerUsed(*M, {indexgv});
          indexval = (UseStackTemp ? IRBEntry : IRBBI)
                         ->CreateLoad(indexgv->getValueType(), indexgv);
        } else {
          indexval = ConstantInt::get(Int32Ty, indexmap[BI->getSuccessor(0)]);
          if (UseStackTemp) {
            AllocaInst *indexAI = IRBEntry->CreateAlloca(Int32Ty);
            IRBEntry->CreateStore(indexval, indexAI);
            indexval = IRBBI->CreateLoad(indexAI->getAllocatedType(), indexAI);
          }
        }
        index = indexval;
        RealIndex = EncryptJumpTargetTemp ? IRBBI->CreateXor(index, IndexEncKey)
                                          : index;
      }
      Value *LI, *enckeyLoad, *gepptr = nullptr;
      if (UseStackTemp) {
        LoadInst *LILoadFrom =
            IRBBI->CreateLoad(LoadFrom->getType(), LoadFromAI);
        Value *GEP = IRBBI->CreateGEP(
            LoadFrom->getValueType(), LILoadFrom,
            {zero, BI->isConditional() ? IRBBI->CreateLoad(Int32Ty, RealIndex)
                                       : RealIndex});
        if (!EncryptJumpTargetTemp)
          LI = IRBBI->CreateLoad(Int8PtrTy, GEP,
                                 "IndirectBranchingTargetAddress");
        else
          gepptr = IRBBI->CreateLoad(Int8PtrTy, GEP);
      } else {
        Value *GEP = IRBBI->CreateGEP(LoadFrom->getValueType(), LoadFrom,
                                      {zero, RealIndex});
        if (!EncryptJumpTargetTemp)
          LI = IRBBI->CreateLoad(Int8PtrTy, GEP,
                                 "IndirectBranchingTargetAddress");
        else
          gepptr = IRBBI->CreateLoad(Int8PtrTy, GEP);
      }
      if (EncryptJumpTargetTemp) {
        ConstantInt *encenckey = cast<ConstantInt>(
            ConstantInt::get(Int32Ty, cryptoutils->get_uint32_t()));
        GlobalVariable *enckeyGV = new GlobalVariable(
            *M, Int32Ty, false, GlobalValue::LinkageTypes::PrivateLinkage,
            ConstantInt::get(Int32Ty,
                             encenckey->getValue() ^ encmap[&Func]->getValue()),
            "IndirectBranchingAddressEncryptKey");
        appendToCompilerUsed(*M, enckeyGV);
        enckeyLoad = IRBBI->CreateXor(
            IRBBI->CreateLoad(enckeyGV->getValueType(), enckeyGV), encenckey);
        LI =
            IRBBI->CreateGEP(Int8Ty, gepptr, IRBBI->CreateSub(zero, enckeyLoad),
                             "IndirectBranchingTargetAddress");
      }
      IndirectBrInst *indirBr = IndirectBrInst::Create(LI, BBs.size());
      for (BasicBlock *BB : BBs)
        indirBr->addDestination(BB);
      ReplaceInstWithInst(BI, indirBr);
    }
    shuffleBasicBlocks(Func);
    return true;
  }
  void shuffleBasicBlocks(Function &F) {
    SmallVector<BasicBlock *, 32> blocks;
    for (BasicBlock &block : F)
      if (!block.isEntryBlock())
        blocks.emplace_back(&block);

    if (blocks.size() < 2)
      return;

    for (size_t i = blocks.size() - 1; i > 0; i--)
      std::swap(blocks[i], blocks[cryptoutils->get_range(i + 1)]);

    Function::iterator fi = F.begin();
    for (BasicBlock *block : blocks) {
      fi++;
      block->moveAfter(&*(fi));
    }
  }
};
} // namespace llvm

FunctionPass *llvm::createIndirectBranchPass(bool flag) {
  return new IndirectBranch(flag);
}
char IndirectBranch::ID = 0;
INITIALIZE_PASS(IndirectBranch, "indibran", "IndirectBranching", false, false)
