// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "include/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include <set>
#include <sstream>

using namespace llvm;

namespace llvm {

// Shamefully borrowed from ../Scalar/RegToMem.cpp :(
bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  SmallVector<PHINode *, 8> tmpPhi;
  SmallVector<Instruction *, 32> tmpReg;
  BasicBlock *bbEntry = &*f->begin();
  // Find first non-alloca instruction and create insertion point. This is
  // safe if block is well-formed: it always have terminator, otherwise
  // we'll get and assertion.
  BasicBlock::iterator I = bbEntry->begin();
  while (isa<AllocaInst>(I))
    ++I;
  Instruction *AllocaInsertionPoint = &*I;
  do {
    tmpPhi.clear();
    tmpReg.clear();
    for (BasicBlock &i : *f) {
      for (Instruction &j : i) {
        if (isa<PHINode>(&j)) {
          PHINode *phi = cast<PHINode>(&j);
          tmpPhi.emplace_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(&j) && j.getParent() == bbEntry) &&
            (valueEscapes(&j) || j.isUsedOutsideOfBlock(&i))) {
          tmpReg.emplace_back(&j);
          continue;
        }
      }
    }
#if LLVM_VERSION_MAJOR >= 19
    for (Instruction *I : tmpReg)
      DemoteRegToStack(*I, false, AllocaInsertionPoint->getIterator());
    for (PHINode *P : tmpPhi)
      DemotePHIToStack(P, AllocaInsertionPoint->getIterator());
#else
    for (Instruction *I : tmpReg)
      DemoteRegToStack(*I, false, AllocaInsertionPoint);
    for (PHINode *P : tmpPhi)
      DemotePHIToStack(P, AllocaInsertionPoint);
#endif
  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}

// Unlike O-LLVM which uses __attribute__ that is not supported by the ObjC
// CFE. We use a dummy call here and remove the call later Very dumb and
// definitely slower than the function attribute method Merely a hack
bool readFlag(Function *f, std::string attribute) {
  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          CI->getCalledFunction()->getName().starts_with("hikari_" +
                                                         attribute)) {
#else
          CI->getCalledFunction()->getName().startswith("hikari_" +
                                                        attribute)) {
#endif
        CI->eraseFromParent();
        return true;
      }
    }
    if (InvokeInst *II = dyn_cast<InvokeInst>(Inst)) {
      if (II->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          II->getCalledFunction()->getName().starts_with("hikari_" +
                                                         attribute)) {
#else
          II->getCalledFunction()->getName().startswith("hikari_" +
                                                        attribute)) {
#endif
        BasicBlock *normalDest = II->getNormalDest();
        BasicBlock *unwindDest = II->getUnwindDest();
        BasicBlock *parent = II->getParent();
        if (parent->size() == 1) {
          parent->replaceAllUsesWith(normalDest);
          II->eraseFromParent();
          parent->eraseFromParent();
        } else {
          BranchInst::Create(normalDest, II);
          II->eraseFromParent();
        }
        if (pred_size(unwindDest) == 0)
          unwindDest->eraseFromParent();
        return true;
      }
    }
  }
  return false;
}

bool toObfuscate(bool flag, Function *f, std::string attribute) {
  // Check if declaration and external linkage
  if (f->isDeclaration() || f->hasAvailableExternallyLinkage()) {
    return false;
  }
  std::string attr = attribute;
  std::string attrNo = "no" + attr;
  if (readAnnotationMetadata(f, attrNo) || readFlag(f, attrNo)) {
    return false;
  }
  if (readAnnotationMetadata(f, attr) || readFlag(f, attr)) {
    return true;
  }
  return flag;
}

bool toObfuscateBoolOption(Function *f, std::string option, bool *val) {
  std::string opt = option;
  std::string optDisable = "no" + option;
  if (readAnnotationMetadata(f, optDisable) || readFlag(f, optDisable)) {
    *val = false;
    return true;
  }
  if (readAnnotationMetadata(f, opt) || readFlag(f, opt)) {
    *val = true;
    return true;
  }
  return false;
}

static const char obfkindid[] = "MD_obf";

bool readAnnotationMetadataUint32OptVal(Function *f, std::string opt,
                                        uint32_t *val) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      StringRef mdstr = cast<MDString>(N.get())->getString();
      std::string estr = opt + "=";
#if LLVM_VERSION_MAJOR >= 18
      if (mdstr.starts_with(estr)) {
#else
      if (mdstr.startswith(estr)) {
#endif
        *val = atoi(mdstr.substr(strlen(estr.c_str())).str().c_str());
        return true;
      }
    }
  }
  return false;
}

bool readFlagUint32OptVal(Function *f, std::string opt, uint32_t *val) {
  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          CI->getCalledFunction()->getName().starts_with("hikari_" + opt)) {
#else
          CI->getCalledFunction()->getName().startswith("hikari_" + opt)) {
#endif
        if (ConstantInt *C = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          CI->eraseFromParent();
          return true;
        }
      }
    }
    if (InvokeInst *II = dyn_cast<InvokeInst>(Inst)) {
      if (II->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          II->getCalledFunction()->getName().starts_with("hikari_" + opt)) {
#else
          II->getCalledFunction()->getName().startswith("hikari_" + opt)) {
#endif
        if (ConstantInt *C = dyn_cast<ConstantInt>(II->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          BasicBlock *normalDest = II->getNormalDest();
          BasicBlock *unwindDest = II->getUnwindDest();
          BasicBlock *parent = II->getParent();
          if (parent->size() == 1) {
            parent->replaceAllUsesWith(normalDest);
            II->eraseFromParent();
            parent->eraseFromParent();
          } else {
            BranchInst::Create(normalDest, II);
            II->eraseFromParent();
          }
          if (pred_size(unwindDest) == 0)
            unwindDest->eraseFromParent();
          return true;
        }
      }
    }
  }
  return false;
}

bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val) {
  if (readAnnotationMetadataUint32OptVal(f, option, val) ||
      readFlagUint32OptVal(f, option, val))
    return true;
  return false;
}

bool hasApplePtrauth(Module *M) {
  for (GlobalVariable &GV : M->globals())
    if (GV.getSection() == "llvm.ptrauth")
      return true;
  return false;
}

void FixBasicBlockConstantExpr(BasicBlock *BB) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  // Things to note:
  // - Phis must be placed at BB start so CEs must be placed prior to current BB
  assert(!BB->empty() && "BasicBlock is empty!");
  assert(BB->getParent() && "BasicBlock must be in a Function!");
  Instruction *FunctionInsertPt =
      &*(BB->getParent()->getEntryBlock().getFirstInsertionPt());

  for (Instruction &I : *BB) {
    if (isa<LandingPadInst>(I) || isa<FuncletPadInst>(I) ||
        isa<IntrinsicInst>(I))
      continue;
    for (unsigned int i = 0; i < I.getNumOperands(); i++)
      if (ConstantExpr *C = dyn_cast<ConstantExpr>(I.getOperand(i))) {
        IRBuilder<NoFolder> IRB(&I);
        if (isa<PHINode>(I))
          IRB.SetInsertPoint(FunctionInsertPt);
        Instruction *Inst = IRB.Insert(C->getAsInstruction());
        I.setOperand(i, Inst);
      }
  }
}

void FixFunctionConstantExpr(Function *Func) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  for (BasicBlock &BB : *Func)
    FixBasicBlockConstantExpr(&BB);
}

void turnOffOptimization(Function *f) {
  f->removeFnAttr(Attribute::AttrKind::MinSize);
  f->removeFnAttr(Attribute::AttrKind::OptimizeForSize);
  if (!f->hasFnAttribute(Attribute::AttrKind::OptimizeNone) &&
      !f->hasFnAttribute(Attribute::AttrKind::AlwaysInline)) {
    f->addFnAttr(Attribute::AttrKind::OptimizeNone);
    f->addFnAttr(Attribute::AttrKind::NoInline);
  }
}

static inline std::vector<std::string> splitString(std::string str) {
  std::stringstream ss(str);
  std::string word;
  std::vector<std::string> words;
  while (ss >> word)
    words.emplace_back(word);
  return words;
}

void annotation2Metadata(Module &M) {
  GlobalVariable *Annotations = M.getGlobalVariable("llvm.global.annotations");
  if (!Annotations)
    return;
  auto *C = dyn_cast<ConstantArray>(Annotations->getInitializer());
  if (!C)
    return;
  for (unsigned int i = 0; i < C->getNumOperands(); i++)
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C->getOperand(i))) {
      GlobalValue *StrC =
          dyn_cast<GlobalValue>(CS->getOperand(1)->stripPointerCasts());
      if (!StrC)
        continue;
      ConstantDataSequential *StrData =
          dyn_cast<ConstantDataSequential>(StrC->getOperand(0));
      if (!StrData)
        continue;
      Function *Fn = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts());
      if (!Fn)
        continue;

      // Add annotation to the function.
      std::vector<std::string> strs =
          splitString(StrData->getAsCString().str());
      for (std::string str : strs)
        writeAnnotationMetadata(Fn, str);
    }
}

bool readAnnotationMetadata(Function *f, std::string annotation) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands())
      if (cast<MDString>(N.get())->getString() == annotation)
        return true;
  }
  return false;
}

void writeAnnotationMetadata(Function *f, std::string annotation) {
  LLVMContext &Context = f->getContext();
  MDBuilder MDB(Context);

  MDNode *Existing = f->getMetadata(obfkindid);
  SmallVector<Metadata *, 4> Names;
  bool AppendName = true;
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      if (cast<MDString>(N.get())->getString() == annotation)
        AppendName = false;
      Names.emplace_back(N.get());
    }
  }
  if (AppendName)
    Names.emplace_back(MDB.createString(annotation));

  MDNode *MD = MDTuple::get(Context, Names);
  f->setMetadata(obfkindid, MD);
}

bool AreUsersInOneFunction(GlobalVariable *GV) {
  SmallPtrSet<Function *, 6> userFunctions;
  for (User *U : GV->users()) {
    if (Instruction *I = dyn_cast<Instruction>(U)) {
      userFunctions.insert(I->getFunction());
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(U)) {
      for (User *U2 : CE->users()) {
        if (Instruction *I = dyn_cast<Instruction>(U2)) {
          userFunctions.insert(I->getFunction());
        }
      }
    } else {
      return false;
    }
  }
  return userFunctions.size() <= 1;
}

#if 0
std::map<GlobalValue *, StringRef> BuildAnnotateMap(Module &M) {
  std::map<GlobalValue *, StringRef> VAMap;
  GlobalVariable *glob = M.getGlobalVariable("llvm.global.annotations");
  if (glob != nullptr && glob->hasInitializer()) {
    ConstantArray *CDA = cast<ConstantArray>(glob->getInitializer());
    for (Value *op : CDA->operands()) {
      ConstantStruct *anStruct = cast<ConstantStruct>(op);
      /*
        Structure: [Value,Annotation,SourceFilePath,LineNumber]
        Usually wrapped inside GEP/BitCast
        We only care about Value and Annotation Here
      */
      GlobalValue *Value =
          cast<GlobalValue>(anStruct->getOperand(0)->getOperand(0));
      GlobalVariable *Annotation =
          cast<GlobalVariable>(anStruct->getOperand(1)->getOperand(0));
      if (Annotation->hasInitializer()) {
        VAMap[Value] =
            cast<ConstantDataSequential>(Annotation->getInitializer())
                ->getAsCString();
      }
    }
  }
  return VAMap;
}
#endif

} // namespace llvm
