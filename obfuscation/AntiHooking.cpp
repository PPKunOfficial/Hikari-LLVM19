/*
    LLVM Anti Hooking Pass
    Copyright (C) 2017 Zhang(https://github.com/Naville/)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/ADT/SmallString.h"
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "include/AntiHook.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <fstream>

// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 56
#define AARCH64_SIGNATURE_B 0b000101
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 75
#define AARCH64_SIGNATURE_BR 0b1101011000011111000000
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 79
#define AARCH64_SIGNATURE_BRK 0b11010100001

using namespace llvm;

static cl::opt<std::string>
    PreCompiledIRPath("adhexrirpath",
                      cl::desc("External Path Pointing To Pre-compiled Anti "
                               "Hooking Handler IR"),
                      cl::value_desc("filename"), cl::init(""));

static cl::opt<bool> CheckInlineHook("ah_inline", cl::init(true), cl::NotHidden,
                                     cl::desc("Check Inline Hook for AArch64"));
static bool CheckInlineHookTemp = true;

static cl::opt<bool>
    CheckObjectiveCRuntimeHook("ah_objcruntime", cl::init(true), cl::NotHidden,
                               cl::desc("Check Objective-C Runtime Hook"));
static bool CheckObjectiveCRuntimeHookTemp = true;

static cl::opt<bool> AntiRebindSymbol("ah_antirebind", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Make fishhook unavailable"));
static bool AntiRebindSymbolTemp = false;

namespace llvm {
struct AntiHook : public ModulePass {
  static char ID;
  bool flag;
  bool initialized;
  bool opaquepointers;
  Triple triple;
  AntiHook() : ModulePass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  AntiHook(bool flag) : ModulePass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "AntiHook"; }
  bool initialize(Module &M) {
    this->triple = Triple(M.getTargetTriple());
    if (PreCompiledIRPath == "") {
      SmallString<32> Path;
      if (sys::path::home_directory(Path)) { // Stolen from LineEditor.cpp
        sys::path::append(Path, "Hikari");
        sys::path::append(Path,
                          "PrecompiledAntiHooking-" +
                              Triple::getArchTypeName(triple.getArch()) + "-" +
                              Triple::getOSTypeName(triple.getOS()) + ".bc");
        PreCompiledIRPath = Path.c_str();
      }
    }
    std::ifstream f(PreCompiledIRPath);
    if (f.good()) {
      errs() << "Linking PreCompiled AntiHooking IR From:" << PreCompiledIRPath
             << "\n";
      SMDiagnostic SMD;
      std::unique_ptr<Module> ADBM(
          parseIRFile(StringRef(PreCompiledIRPath), SMD, M.getContext()));
      Linker::linkModules(M, std::move(ADBM), Linker::Flags::OverrideFromSrc);
    } else {
      errs() << "Failed To Link PreCompiled AntiHooking IR From:"
             << PreCompiledIRPath << "\n";
    }
#if LLVM_VERSION_MAJOR >= 17
    opaquepointers = true;
#else
    opaquepointers = !M.getContext().supportsTypedPointers();
#endif

    if (triple.getVendor() == Triple::VendorType::Apple &&
        StructType::getTypeByName(M.getContext(), "struct._objc_method")) {
      Type *Int8PtrTy = Type::getInt8Ty(M.getContext())->getPointerTo();
      M.getOrInsertFunction("objc_getClass",
                            FunctionType::get(Int8PtrTy, {Int8PtrTy}, false));
      M.getOrInsertFunction("sel_registerName",
                            FunctionType::get(Int8PtrTy, {Int8PtrTy}, false));
      FunctionType *IMPType =
          FunctionType::get(Int8PtrTy, {Int8PtrTy, Int8PtrTy}, true);
      PointerType *IMPPointerType = PointerType::getUnqual(IMPType);
      M.getOrInsertFunction(
          "method_getImplementation",
          FunctionType::get(IMPPointerType,
                            {PointerType::getUnqual(StructType::getTypeByName(
                                M.getContext(), "struct._objc_method"))},
                            false));
      M.getOrInsertFunction(
          "class_getInstanceMethod",
          FunctionType::get(PointerType::getUnqual(StructType::getTypeByName(
                                M.getContext(), "struct._objc_method")),
                            {Int8PtrTy, Int8PtrTy}, false));
      M.getOrInsertFunction(
          "class_getClassMethod",
          FunctionType::get(PointerType::getUnqual(StructType::getTypeByName(
                                M.getContext(), "struct._objc_method")),
                            {Int8PtrTy, Int8PtrTy}, false));
    }
    return true;
  }

  bool runOnModule(Module &M) override {
    for (Function &F : M) {
      if (toObfuscate(flag, &F, "antihook")) {
        errs() << "Running AntiHooking On " << F.getName() << "\n";
        if (!this->initialized)
          initialize(M);
        if (!toObfuscateBoolOption(&F, "ah_inline", &CheckInlineHookTemp))
          CheckInlineHookTemp = CheckInlineHook;
        if (triple.isAArch64() && CheckInlineHookTemp) {
          HandleInlineHookAArch64(&F);
        }
        if (!toObfuscateBoolOption(&F, "ah_antirebind", &AntiRebindSymbolTemp))
          AntiRebindSymbolTemp = AntiRebindSymbol;
        if (AntiRebindSymbolTemp)
          for (Instruction &I : instructions(F))
            if (isa<CallInst>(&I) || isa<InvokeInst>(&I)) {
              CallSite CS(&I);
              Function *Called = CS.getCalledFunction();
              if (!Called)
                Called = dyn_cast<Function>(
                    CS.getCalledValue()->stripPointerCasts());
              if (Called && Called->isDeclaration() &&
                  Called->isExternalLinkage(Called->getLinkage()) &&
                  !Called->isIntrinsic() &&
#if LLVM_VERSION_MAJOR >= 18
                  !Called->getName().starts_with("clang.")) {
#else
                  !Called->getName().startswith("clang.")) {
#endif
                GlobalVariable *GV = cast<GlobalVariable>(M.getOrInsertGlobal(
                    ("AntiRebindSymbol_" + Called->getName()).str(),
                    Called->getType()));
                if (!GV->hasInitializer()) {
                  GV->setConstant(true); // make the gv not writable
                  GV->setInitializer(Called);
                  GV->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
                }
                appendToCompilerUsed(M, {GV});
                Value *Load =
                    new LoadInst(GV->getValueType(), GV, Called->getName(), &I);
                Value *BitCasted = BitCastInst::CreateBitOrPointerCast(
                    Load, CS.getCalledValue()->getType(), "", &I);
                CS.setCalledFunction(BitCasted);
              }
            }
        if (!toObfuscateBoolOption(&F, "ah_objcruntime",
                                   &CheckObjectiveCRuntimeHookTemp))
          CheckObjectiveCRuntimeHookTemp = CheckObjectiveCRuntimeHook;
        if (!CheckObjectiveCRuntimeHookTemp)
          continue;
        GlobalVariable *methodListGV = nullptr;
        ConstantStruct *methodStruct = nullptr;
        for (User *U : F.users()) {
          if (opaquepointers)
            if (ConstantStruct *CS = dyn_cast<ConstantStruct>(U))
              if (CS->getType()->getName() == "struct._objc_method")
                methodStruct = CS;
          for (User *U2 : U->users()) {
            if (!opaquepointers)
              if (ConstantStruct *CS = dyn_cast<ConstantStruct>(U2))
                if (CS->getType()->getName() == "struct._objc_method")
                  methodStruct = CS;
            for (User *U3 : U2->users())
              for (User *U4 : U3->users()) {
                if (opaquepointers) {
#if LLVM_VERSION_MAJOR >= 18
                  if (U4->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
                      U4->getName().starts_with("_OBJC_$_CLASS_METHODS"))
                    methodListGV = dyn_cast<GlobalVariable>(U4);
                } else
                  for (User *U5 : U4->users()) {
                    if (U5->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
                        U5->getName().starts_with("_OBJC_$_CLASS_METHODS"))
#else
                  if (U4->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
                      U4->getName().startswith("_OBJC_$_CLASS_METHODS"))
                    methodListGV = dyn_cast<GlobalVariable>(U4);
                } else
                  for (User *U5 : U4->users()) {
                    if (U5->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
                        U5->getName().startswith("_OBJC_$_CLASS_METHODS"))
#endif
                      methodListGV = dyn_cast<GlobalVariable>(U5);
                  }
              }
          }
        }
        if (methodListGV && methodStruct) {
          GlobalVariable *SELNameGV = cast<GlobalVariable>(
              methodStruct->getOperand(0)->stripPointerCasts());
          ConstantDataSequential *SELNameCDS =
              cast<ConstantDataSequential>(SELNameGV->getInitializer());
          bool classmethod =
#if LLVM_VERSION_MAJOR >= 18
              methodListGV->getName().starts_with("_OBJC_$_CLASS_METHODS");
#else
              methodListGV->getName().startswith("_OBJC_$_CLASS_METHODS");
#endif
          std::string classname =
              methodListGV->getName()
                  .substr(strlen(classmethod ? "_OBJC_$_CLASS_METHODS_"
                                             : "_OBJC_$_INSTANCE_METHODS_"))
                  .str();
          std::string selname = SELNameCDS->getAsCString().str();
          HandleObjcRuntimeHook(&F, classname, selname, classmethod);
        }
      }
    }
    return true;
  } // End runOnFunction

  void HandleInlineHookAArch64(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "HookDetectedHandler", F);
    BasicBlock *Detect = BasicBlock::Create(F->getContext(), "", F);
    BasicBlock *Detect2 = BasicBlock::Create(F->getContext(), "", F);
    // Change A's terminator to jump to B
    // We'll add new terminator in B to jump C later
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(Detect, A);

    IRBuilder<> IRBDetect(Detect);
    IRBuilder<> IRBDetect2(Detect2);
    IRBuilder<> IRBB(B);

    Type *Int64Ty = Type::getInt64Ty(F->getContext());
    Type *Int32Ty = Type::getInt32Ty(F->getContext());
    Type *Int32PtrTy = Type::getInt32Ty(F->getContext())->getPointerTo();

    Value *Load =
        IRBDetect.CreateLoad(Int32Ty, IRBDetect.CreateBitCast(F, Int32PtrTy));
    Value *LS2 = IRBDetect.CreateLShr(Load, ConstantInt::get(Int32Ty, 26));
    Value *ICmpEQ2 = IRBDetect.CreateICmpEQ(
        LS2, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_B));
    Value *LS3 = IRBDetect.CreateLShr(Load, ConstantInt::get(Int32Ty, 21));
    Value *ICmpEQ3 = IRBDetect.CreateICmpEQ(
        LS3, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BRK));
    Value *Or = IRBDetect.CreateOr(ICmpEQ2, ICmpEQ3);
    IRBDetect.CreateCondBr(Or, B, Detect2);

    Value *PTI = IRBDetect2.CreatePtrToInt(F, Int64Ty);
    Value *AddFour = IRBDetect2.CreateAdd(PTI, ConstantInt::get(Int64Ty, 4));
    Value *ITP = IRBDetect2.CreateIntToPtr(AddFour, Int32PtrTy);
    Value *Load2 = IRBDetect2.CreateLoad(Int32Ty, ITP);
    Value *LS4 = IRBDetect2.CreateLShr(Load2, ConstantInt::get(Int32Ty, 10));
    Value *ICmpEQ4 = IRBDetect2.CreateICmpEQ(
        LS4, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BR));
    Value *AddEight = IRBDetect2.CreateAdd(PTI, ConstantInt::get(Int64Ty, 8));
    Value *ITP2 = IRBDetect2.CreateIntToPtr(AddEight, Int32PtrTy);
    Value *Load3 = IRBDetect2.CreateLoad(Int32Ty, ITP2);
    Value *LS5 = IRBDetect2.CreateLShr(Load3, ConstantInt::get(Int32Ty, 10));
    Value *ICmpEQ5 = IRBDetect2.CreateICmpEQ(
        LS5, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BR));
    Value *Or2 = IRBDetect2.CreateOr(ICmpEQ4, ICmpEQ5);
    IRBDetect2.CreateCondBr(Or2, B, C);
    CreateCallbackAndJumpBack(&IRBB, C);
  }

  void HandleObjcRuntimeHook(Function *ObjcMethodImp, std::string classname,
                             std::string selname, bool classmethod) {
    /*
    We split the originalBB A into:
       A < - RuntimeHook Detection
       | \
       |  B for handler()
       | /
       C < - Original Following BB
    */
    Module *M = ObjcMethodImp->getParent();

    BasicBlock *A = &(ObjcMethodImp->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B = BasicBlock::Create(A->getContext(), "HookDetectedHandler",
                                       ObjcMethodImp, C);
    // Delete A's terminator
    A->getTerminator()->eraseFromParent();

    IRBuilder<> IRBA(A);
    IRBuilder<> IRBB(B);

    Type *Int8PtrTy = Type::getInt8Ty(M->getContext())->getPointerTo();

    Value *GetClass = IRBA.CreateCall(M->getFunction("objc_getClass"),
                                      {IRBA.CreateGlobalStringPtr(classname)});
    Value *GetSelector = IRBA.CreateCall(M->getFunction("sel_registerName"),
                                         {IRBA.CreateGlobalStringPtr(selname)});
    Value *GetMethod =
        IRBA.CreateCall(M->getFunction(classmethod ? "class_getClassMethod"
                                                   : "class_getInstanceMethod"),
                        {GetClass, GetSelector});
    Value *GetMethodImp = IRBA.CreateCall(
        M->getFunction("method_getImplementation"), {GetMethod});
    Value *IcmpEq =
        IRBA.CreateICmpEQ(IRBA.CreateBitCast(GetMethodImp, Int8PtrTy),
                          ConstantExpr::getBitCast(ObjcMethodImp, Int8PtrTy));
    IRBA.CreateCondBr(IcmpEq, C, B);
    CreateCallbackAndJumpBack(&IRBB, C);
  }
  void CreateCallbackAndJumpBack(IRBuilder<> *IRBB, BasicBlock *C) {
    Module *M = C->getModule();
    Function *AHCallBack = M->getFunction("AHCallBack");
    if (AHCallBack) {
      IRBB->CreateCall(AHCallBack);
    } else {
      if (triple.isOSDarwin() && triple.isAArch64()) {
        std::string exitsvcasm = "mov w16, #1\n";
        exitsvcasm +=
            "svc #" + std::to_string(cryptoutils->get_range(65536)) + "\n";
        InlineAsm *IA =
            InlineAsm::get(FunctionType::get(IRBB->getVoidTy(), false),
                           exitsvcasm, "", true, false);
        IRBB->CreateCall(IA);
      } else {
        FunctionType *ABFT =
            FunctionType::get(Type::getVoidTy(M->getContext()), false);
        Function *abort_declare =
            cast<Function>(M->getOrInsertFunction("abort", ABFT).getCallee());
        abort_declare->addFnAttr(Attribute::AttrKind::NoReturn);
        IRBB->CreateCall(abort_declare);
      }
    }
    IRBB->CreateBr(C);
  }
};
} // namespace llvm

ModulePass *llvm::createAntiHookPass(bool flag) { return new AntiHook(flag); }
char AntiHook::ID = 0;
INITIALIZE_PASS(AntiHook, "antihook", "AntiHook", false, false)
