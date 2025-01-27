// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "include/Flattening.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"

using namespace llvm;

namespace {
struct Flattening : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  bool flag;
  Flattening() : FunctionPass(ID) { this->flag = true; }
  Flattening(bool flag) : FunctionPass(ID) { this->flag = flag; }
  bool runOnFunction(Function &F) override;
  void flatten(Function *f);
};
} // namespace

char Flattening::ID = 0;
FunctionPass *llvm::createFlatteningPass(bool flag) {
  return new Flattening(flag);
}
INITIALIZE_PASS(Flattening, "cffobf", "Enable Control Flow Flattening.", false,
                false)
bool Flattening::runOnFunction(Function &F) {
  Function *tmp = &F;
  // Do we obfuscate
  if (toObfuscate(flag, tmp, "fla") && !F.isPresplitCoroutine()) {
    errs() << "Running ControlFlowFlattening On " << F.getName() << "\n";
    flatten(tmp);
  }

  return true;
}

void Flattening::flatten(Function *f) {
  SmallVector<BasicBlock *, 8> origBB;
  BasicBlock *loopEntry, *loopEnd;
  LoadInst *load;
  SwitchInst *switchI;
  AllocaInst *switchVar, *switchVarAddr;
  const DataLayout &DL = f->getParent()->getDataLayout();

  // SCRAMBLER
  std::unordered_map<uint32_t, uint32_t> scrambling_key;
  // END OF SCRAMBLER

  PassBuilder PB;
  FunctionAnalysisManager FAM;
  FunctionPassManager FPM;
  PB.registerFunctionAnalyses(FAM);
  FPM.addPass(LowerSwitchPass());
  FPM.run(*f, FAM);

  for (BasicBlock &BB : *f) {
    if (BB.isEHPad() || BB.isLandingPad()) {
      errs() << f->getName()
             << " Contains Exception Handing Instructions and is unsupported "
                "for flattening in the open-source version of Hikari.\n";
      return;
    }
    if (!isa<BranchInst>(BB.getTerminator()) &&
        !isa<ReturnInst>(BB.getTerminator()))
      return;
    origBB.emplace_back(&BB);
  }

  // Nothing to flatten
  if (origBB.size() <= 1)
    return;

  // Remove first BB
  origBB.erase(origBB.begin());

  // Get a pointer on the first BB
  Function::iterator tmp = f->begin();
  BasicBlock *insert = &*tmp;

  // If main begin with an if
  BranchInst *br = nullptr;
  if (isa<BranchInst>(insert->getTerminator()))
    br = cast<BranchInst>(insert->getTerminator());

  if ((br && br->isConditional()) ||
      insert->getTerminator()->getNumSuccessors() > 1) {
    BasicBlock::iterator i = insert->end();
    --i;

    if (insert->size() > 1) {
      --i;
    }

    BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
    origBB.insert(origBB.begin(), tmpBB);
  }

  // Remove jump
  Instruction *oldTerm = insert->getTerminator();

  // Create switch variable and set as it
  switchVar = new AllocaInst(Type::getInt32Ty(f->getContext()),
                             DL.getAllocaAddrSpace(), "switchVar", oldTerm);
  switchVarAddr =
      new AllocaInst(Type::getInt32Ty(f->getContext())->getPointerTo(),
                     DL.getAllocaAddrSpace(), "", oldTerm);

  // Remove jump
  oldTerm->eraseFromParent();

  new StoreInst(ConstantInt::get(Type::getInt32Ty(f->getContext()),
                                 cryptoutils->scramble32(0, scrambling_key)),
                switchVar, insert);
  new StoreInst(switchVar, switchVarAddr, insert);

  // Create main loop
  loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f, insert);
  loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f, insert);

  load = new LoadInst(switchVar->getAllocatedType(), switchVar, "switchVar",
                      loopEntry);

  // Move first BB on top
  insert->moveBefore(loopEntry);
  BranchInst::Create(loopEntry, insert);

  // loopEnd jump to loopEntry
  BranchInst::Create(loopEntry, loopEnd);

  BasicBlock *swDefault =
      BasicBlock::Create(f->getContext(), "switchDefault", f, loopEnd);
  BranchInst::Create(loopEnd, swDefault);

  // Create switch instruction itself and set condition
  switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, loopEntry);
  switchI->setCondition(load);

  // Remove branch jump from 1st BB and make a jump to the while
  f->begin()->getTerminator()->eraseFromParent();

  BranchInst::Create(loopEntry, &*f->begin());

  // Put BB in the switch
  for (BasicBlock *i : origBB) {
    ConstantInt *numCase = nullptr;

    // Move the BB inside the switch (only visual, no code logic)
    i->moveBefore(loopEnd);

    // Add case to switch
    numCase = cast<ConstantInt>(ConstantInt::get(
        switchI->getCondition()->getType(),
        cryptoutils->scramble32(switchI->getNumCases(), scrambling_key)));
    switchI->addCase(numCase, i);
  }

  // Recalculate switchVar
  for (BasicBlock *i : origBB) {
    ConstantInt *numCase = nullptr;

    // If it's a non-conditional jump
    if (i->getTerminator()->getNumSuccessors() == 1) {
      // Get successor and delete terminator
      BasicBlock *succ = i->getTerminator()->getSuccessor(0);
      i->getTerminator()->eraseFromParent();

      // Get next case
      numCase = switchI->findCaseDest(succ);

      // If next case == default case (switchDefault)
      if (!numCase) {
        numCase = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(switchI->getNumCases() - 1,
                                                     scrambling_key)));
      }

      // Update switchVar and jump to the end of loop
      new StoreInst(
          numCase,
          new LoadInst(switchVarAddr->getAllocatedType(), switchVarAddr, "", i),
          i);
      BranchInst::Create(loopEnd, i);
      continue;
    }

    // If it's a conditional jump
    if (i->getTerminator()->getNumSuccessors() == 2) {
      // Get next cases
      ConstantInt *numCaseTrue =
          switchI->findCaseDest(i->getTerminator()->getSuccessor(0));
      ConstantInt *numCaseFalse =
          switchI->findCaseDest(i->getTerminator()->getSuccessor(1));

      // Check if next case == default case (switchDefault)
      if (!numCaseTrue) {
        numCaseTrue = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(switchI->getNumCases() - 1,
                                                     scrambling_key)));
      }

      if (!numCaseFalse) {
        numCaseFalse = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(switchI->getNumCases() - 1,
                                                     scrambling_key)));
      }

      // Create a SelectInst
      BranchInst *br = cast<BranchInst>(i->getTerminator());
      SelectInst *sel =
          SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "",
                             i->getTerminator());

      // Erase terminator
      i->getTerminator()->eraseFromParent();
      // Update switchVar and jump to the end of loop
      new StoreInst(
          sel,
          new LoadInst(switchVarAddr->getAllocatedType(), switchVarAddr, "", i),
          i);
      BranchInst::Create(loopEnd, i);
      continue;
    }
  }
  errs() << "Fixing Stack\n";
  fixStack(f);
  errs() << "Fixed Stack\n";
}
