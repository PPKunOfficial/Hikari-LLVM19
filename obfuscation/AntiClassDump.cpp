// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
/*
  For maximum usability. We provide two modes for this pass, as defined in
  include/AntiClassDump.h THIN mode is used on per-module
  basis without LTO overhead and structs are left in the module where possible.
  This is particularly useful for cases where LTO is not possible. For example
  static library. Full mode is used at LTO stage, this mode constructs
  dependency graph and perform full wipe-out as well as llvm.global_ctors
  injection.
  This pass only provides thin mode
*/

#include "include/AntiClassDump.h"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "include/Utils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <deque>
#include <map>
#include <unordered_map>

using namespace llvm;

static cl::opt<bool>
    UseInitialize("acd-use-initialize", cl::init(true), cl::NotHidden,
                  cl::desc("[AntiClassDump]Inject codes to +initialize"));
static cl::opt<bool>
    RenameMethodIMP("acd-rename-methodimp", cl::init(false), cl::NotHidden,
                    cl::desc("[AntiClassDump]Rename methods imp"));
namespace llvm {
struct AntiClassDump : public ModulePass {
  static char ID;
  bool appleptrauth;
  bool opaquepointers;
  Triple triple;
  AntiClassDump() : ModulePass(ID) {}
  StringRef getPassName() const override { return "AntiClassDump"; }
  bool doInitialization(Module &M) override {
    // Basic Defs
    triple = Triple(M.getTargetTriple());
    if (triple.getVendor() != Triple::VendorType::Apple) {
      // We only support AAPL's ObjC Implementation ATM
      errs()
          << M.getTargetTriple()
          << " is Not Supported For LLVM AntiClassDump\nProbably GNU Step?\n";
      return false;
    }
    Type *Int8PtrTy = Type::getInt8Ty(M.getContext())->getPointerTo();
    // Generic ObjC Runtime Declarations
    FunctionType *IMPType =
        FunctionType::get(Int8PtrTy, {Int8PtrTy, Int8PtrTy}, true);
    PointerType *IMPPointerType = PointerType::getUnqual(IMPType);
    FunctionType *class_replaceMethod_type = FunctionType::get(
        IMPPointerType, {Int8PtrTy, Int8PtrTy, IMPPointerType, Int8PtrTy},
        false);
    M.getOrInsertFunction("class_replaceMethod", class_replaceMethod_type);
    FunctionType *sel_registerName_type =
        FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
    M.getOrInsertFunction("sel_registerName", sel_registerName_type);
    FunctionType *objc_getClass_type =
        FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
    M.getOrInsertFunction("objc_getClass", objc_getClass_type);
    M.getOrInsertFunction("objc_getMetaClass", objc_getClass_type);
    // Types Collected. Now Inject Functions
    FunctionType *class_getName_Type =
        FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
    M.getOrInsertFunction("class_getName", class_getName_Type);
    FunctionType *objc_getMetaClass_Type =
        FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
    M.getOrInsertFunction("objc_getMetaClass", objc_getMetaClass_Type);
    appleptrauth = hasApplePtrauth(&M);
#if LLVM_VERSION_MAJOR >= 17
    opaquepointers = true;
#else
    opaquepointers = !M.getContext().supportsTypedPointers();
#endif
    return true;
  }
  bool runOnModule(Module &M) override {
    errs() << "Running AntiClassDump On " << M.getSourceFileName() << "\n";
    SmallVector<GlobalVariable *, 32> OLCGVs;
    for (GlobalVariable &GV : M.globals()) {
#if LLVM_VERSION_MAJOR >= 18
      if (GV.getName().starts_with("OBJC_LABEL_CLASS_$")) {
#else
      if (GV.getName().startswith("OBJC_LABEL_CLASS_$")) {
#endif
        OLCGVs.emplace_back(&GV);
      }
    }
    if (!OLCGVs.size()) {
      errs() << "No ObjC Class Found in :" << M.getSourceFileName() << "\n";
      return false;
    }
    for (GlobalVariable *OLCGV : OLCGVs) {
      ConstantArray *OBJC_LABEL_CLASS_CDS =
          dyn_cast<ConstantArray>(OLCGV->getInitializer());
      assert(OBJC_LABEL_CLASS_CDS &&
             "OBJC_LABEL_CLASS_$ Not ConstantArray.Is the target using "
             "unsupported legacy runtime?");
      SmallVector<std::string, 4>
          readyclses;                   // This is for storing classes that
                                        // can be used in handleClass()
      std::deque<std::string> tmpclses; // This is temporary storage for classes
      std::unordered_map<std::string /*class*/, std::string /*super class*/>
          dependency;
      std::unordered_map<std::string /*Class*/, GlobalVariable *>
          GVMapping; // Map ClassName to corresponding GV
      for (unsigned int i = 0; i < OBJC_LABEL_CLASS_CDS->getNumOperands();
           i++) {
        ConstantExpr *clsEXPR =
            opaquepointers
                ? nullptr
                : dyn_cast<ConstantExpr>(OBJC_LABEL_CLASS_CDS->getOperand(i));
        GlobalVariable *CEGV = dyn_cast<GlobalVariable>(
            opaquepointers ? OBJC_LABEL_CLASS_CDS->getOperand(i)
                           : clsEXPR->getOperand(0));
        ConstantStruct *clsCS =
            dyn_cast<ConstantStruct>(CEGV->getInitializer());
        /*
          First Operand MetaClass.
          Second Operand SuperClass
          Fifth Operand ClassRO
        */
        GlobalVariable *SuperClassGV =
            dyn_cast_or_null<GlobalVariable>(clsCS->getOperand(1));
        SuperClassGV = readPtrauth(SuperClassGV);
        std::string supclsName = "";
        std::string clsName = CEGV->getName().str();
        clsName.replace(clsName.find("OBJC_CLASS_$_"), strlen("OBJC_CLASS_$_"),
                        "");

        if (SuperClassGV) { // We need to handle Classed that doesn't have a
                            // base
          supclsName = SuperClassGV->getName().str();
          supclsName.replace(supclsName.find("OBJC_CLASS_$_"),
                             strlen("OBJC_CLASS_$_"), "");
        }
        dependency[clsName] = supclsName;
        GVMapping[clsName] = CEGV;
        if (supclsName == "" /*NULL Super Class*/ ||
            (SuperClassGV &&
             !SuperClassGV->hasInitializer() /*External Super Class*/)) {
          readyclses.emplace_back(clsName);
        } else {
          tmpclses.emplace_back(clsName);
        }
        // Sort Initialize Sequence Based On Dependency
        while (tmpclses.size()) {
          std::string clstmp = tmpclses.front();
          tmpclses.pop_front();
          std::string SuperClassName = dependency[clstmp];
          if (SuperClassName != "" &&
              std::find(readyclses.begin(), readyclses.end(), SuperClassName) ==
                  readyclses.end()) {
            // SuperClass is unintialized non-null class.Push back and waiting
            // until baseclass is allocated
            tmpclses.emplace_back(clstmp);
          } else {
            // BaseClass Ready. Push into ReadyClasses
            readyclses.emplace_back(clstmp);
          }
        }

        // Now run handleClass for each class
        for (std::string className : readyclses) {
          handleClass(GVMapping[className], &M);
        }
      }
    }
    return true;
  } // runOnModule
  std::unordered_map<std::string, Value *>
  splitclass_ro_t(ConstantStruct *class_ro,
                  Module *M) { // Split a class_ro_t structure
    std::unordered_map<std::string, Value *> info;
    StructType *objc_method_list_t_type =
        StructType::getTypeByName(M->getContext(), "struct.__method_list_t");
    for (unsigned i = 0; i < class_ro->getType()->getNumElements(); i++) {
      Constant *tmp = dyn_cast<Constant>(class_ro->getAggregateElement(i));
      if (tmp->isNullValue()) {
        continue;
      }
      Type *type = tmp->getType();
      if ((!opaquepointers &&
           type == PointerType::getUnqual(objc_method_list_t_type)) ||
          (opaquepointers &&
#if LLVM_VERSION_MAJOR >= 18
           (tmp->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().starts_with("_OBJC_$_CLASS_METHODS")))) {
#else
           (tmp->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().startswith("_OBJC_$_CLASS_METHODS")))) {
#endif
        // Insert Methods
        GlobalVariable *methodListGV =
            readPtrauth(cast<GlobalVariable>(tmp->stripPointerCasts()));
        assert(methodListGV->hasInitializer() &&
               "MethodListGV doesn't have initializer");
        ConstantStruct *methodListStruct =
            cast<ConstantStruct>(methodListGV->getInitializer());
        // Extracting %struct._objc_method array from %struct.__method_list_t =
        // type { i32, i32, [0 x %struct._objc_method] }
        info["METHODLIST"] =
            cast<ConstantArray>(methodListStruct->getOperand(2));
      }
    }
    return info;
  } // splitclass_ro_t
  void handleClass(GlobalVariable *GV, Module *M) {
    assert(GV->hasInitializer() &&
           "ObjC Class Structure's Initializer Missing");
    ConstantStruct *CS = dyn_cast<ConstantStruct>(GV->getInitializer());
    StringRef ClassName = GV->getName();
    ClassName = ClassName.substr(strlen("OBJC_CLASS_$_"));
    StringRef SuperClassName =
        readPtrauth(
            cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts()))
            ->getName();
    SuperClassName = SuperClassName.substr(strlen("OBJC_CLASS_$_"));
    errs() << "Handling Class:" << ClassName
           << " With SuperClass:" << SuperClassName << "\n";

    // Let's extract stuffs
    // struct _class_t {
    //   struct _class_t *isa;
    //   struct _class_t * const superclass;
    //   void *cache;
    //   IMP *vtable;
    //   struct class_ro_t *ro;
    // }
    GlobalVariable *metaclassGV = readPtrauth(
        cast<GlobalVariable>(CS->getOperand(0)->stripPointerCasts()));
    GlobalVariable *class_ro = readPtrauth(
        cast<GlobalVariable>(CS->getOperand(4)->stripPointerCasts()));
    assert(metaclassGV->hasInitializer() && "MetaClass GV Initializer Missing");
    GlobalVariable *metaclass_ro = readPtrauth(cast<GlobalVariable>(
        metaclassGV->getInitializer()
            ->getOperand(metaclassGV->getInitializer()->getNumOperands() - 1)
            ->stripPointerCasts()));
    // Begin IRBuilder Initializing
    std::unordered_map<std::string, Value *> Info = splitclass_ro_t(
        cast<ConstantStruct>(metaclass_ro->getInitializer()), M);
    BasicBlock *EntryBB = nullptr;
    if (Info.find("METHODLIST") != Info.end()) {
      ConstantArray *method_list = cast<ConstantArray>(Info["METHODLIST"]);
      for (unsigned i = 0; i < method_list->getNumOperands(); i++) {
        ConstantStruct *methodStruct =
            cast<ConstantStruct>(method_list->getOperand(i));
        // methodStruct has type %struct._objc_method = type { i8*, i8*, i8* }
        // which contains {GEP(NAME),GEP(TYPE),BitCast(IMP)}
        // Let's extract these info now
        // methodStruct->getOperand(0)->getOperand(0) is SELName
        GlobalVariable *SELNameGV = cast<GlobalVariable>(
            opaquepointers ? methodStruct->getOperand(0)
                           : methodStruct->getOperand(0)->getOperand(0));
        ConstantDataSequential *SELNameCDS =
            cast<ConstantDataSequential>(SELNameGV->getInitializer());
        StringRef selname = SELNameCDS->getAsCString();
        if ((selname == "initialize" && UseInitialize) ||
            (selname == "load" && !UseInitialize)) {
          Function *IMPFunc = cast<Function>(readPtrauth(cast<GlobalVariable>(
              methodStruct->getOperand(2)->stripPointerCasts())));
          errs() << "Found Existing initializer\n";
          EntryBB = &(IMPFunc->getEntryBlock());
        }
      }
    } else {
      errs() << "Didn't Find ClassMethod List\n";
    }
    if (!EntryBB) {
      // We failed to find existing +initializer,create new one
      errs() << "Creating initializer\n";
      FunctionType *InitializerType = FunctionType::get(
          Type::getVoidTy(M->getContext()), ArrayRef<Type *>(), false);
      Function *Initializer = Function::Create(
          InitializerType, GlobalValue::LinkageTypes::PrivateLinkage,
          "AntiClassDumpInitializer", M);
      EntryBB = BasicBlock::Create(M->getContext(), "", Initializer);
      ReturnInst::Create(EntryBB->getContext(), EntryBB);
    }
    IRBuilder<> *IRB = new IRBuilder<>(EntryBB, EntryBB->getFirstInsertionPt());
    // We now prepare ObjC API Definitions
    Function *objc_getClass = M->getFunction("objc_getClass");
    // End of ObjC API Definitions
    Value *ClassNameGV = IRB->CreateGlobalStringPtr(ClassName);
    // Now Scan For Props and Ivars in OBJC_CLASS_RO AND OBJC_METACLASS_RO
    // Note that class_ro_t's structure is different for 32 and 64bit runtime
    CallInst *Class = IRB->CreateCall(objc_getClass, {ClassNameGV});
    // Add Methods
    ConstantStruct *metaclassCS =
        cast<ConstantStruct>(class_ro->getInitializer());
    ConstantStruct *classCS =
        cast<ConstantStruct>(metaclass_ro->getInitializer());
    if (!metaclassCS->getAggregateElement(5)->isNullValue()) {
      errs() << "Handling Instance Methods For Class:" << ClassName << "\n";
      HandleMethods(metaclassCS, IRB, M, Class, false);

      errs() << "Updating Instance Method Map For Class:" << ClassName << "\n";
      Type *objc_method_type =
          StructType::getTypeByName(M->getContext(), "struct._objc_method");
      ArrayType *AT = ArrayType::get(objc_method_type, 0);
      Constant *newMethodList = ConstantArray::get(AT, ArrayRef<Constant *>());
      GlobalVariable *methodListGV = readPtrauth(cast<GlobalVariable>(
          metaclassCS->getAggregateElement(5)->stripPointerCasts()));
      StructType *oldGVType =
          cast<StructType>(methodListGV->getInitializer()->getType());
      SmallVector<Type *, 3> newStructType;
      SmallVector<Constant *, 3> newStructValue;
      // I'm fully aware that it's consistent Int32 on all platforms
      // This is future-proof
      newStructType.emplace_back(oldGVType->getElementType(0));
      newStructValue.emplace_back(
          methodListGV->getInitializer()->getAggregateElement(0u));
      newStructType.emplace_back(oldGVType->getElementType(1));
      newStructValue.emplace_back(
          ConstantInt::get(oldGVType->getElementType(1), 0));
      newStructType.emplace_back(AT);
      newStructValue.emplace_back(newMethodList);
      StructType *newType =
          StructType::get(M->getContext(), ArrayRef<Type *>(newStructType));
      Constant *newMethodStruct = ConstantStruct::get(
          newType,
          ArrayRef<Constant *>(newStructValue)); // l_OBJC_$_CLASS_METHODS_
      GlobalVariable *newMethodStructGV = new GlobalVariable(
          *M, newType, true, GlobalValue::LinkageTypes::PrivateLinkage,
          newMethodStruct, "ACDNewInstanceMethodMap");
      appendToCompilerUsed(*M, {newMethodStructGV});
      newMethodStructGV->copyAttributesFrom(methodListGV);
      Constant *bitcastExpr = ConstantExpr::getBitCast(
          newMethodStructGV,
          opaquepointers ? newType->getPointerTo()
                         : PointerType::getUnqual(StructType::getTypeByName(
                               M->getContext(), "struct.__method_list_t")));
      metaclassCS->handleOperandChange(metaclassCS->getAggregateElement(5),
                                       opaquepointers ? newMethodStructGV
                                                      : bitcastExpr);
      methodListGV->replaceAllUsesWith(
          opaquepointers
              ? newMethodStructGV
              : ConstantExpr::getBitCast(
                    newMethodStructGV,
                    methodListGV->getType())); // llvm.compiler.used doesn't
                                               // allow Null/Undef Value
      methodListGV->dropAllReferences();
      methodListGV->eraseFromParent();
      errs() << "Updated Instance Method Map of:" << class_ro->getName()
             << "\n";
    }
    // MethodList has index of 5
    // We need to create a new type first then bitcast to required type later
    // Since the original type's contained arraytype has count of 0
    GlobalVariable *methodListGV = nullptr; // is striped MethodListGV
    if (!classCS->getAggregateElement(5)->isNullValue()) {
      errs() << "Handling Class Methods For Class:" << ClassName << "\n";
      HandleMethods(classCS, IRB, M, Class, true);
      methodListGV = readPtrauth(cast<GlobalVariable>(
          classCS->getAggregateElement(5)->stripPointerCasts()));
    }
    errs() << "Updating Class Method Map For Class:" << ClassName << "\n";
    Type *objc_method_type =
        StructType::getTypeByName(M->getContext(), "struct._objc_method");
    ArrayType *AT = ArrayType::get(objc_method_type, 1);
    Constant *MethName = nullptr;
    if (UseInitialize) {
      MethName = cast<Constant>(IRB->CreateGlobalStringPtr("initialize"));
    } else {
      MethName = cast<Constant>(IRB->CreateGlobalStringPtr("load"));
    }
    // This method signature is generated by clang
    // See
    // http://llvm.org/viewvc/llvm-project/cfe/trunk/lib/AST/ASTContext.cpp?revision=320954&view=markup
    // ASTContext::getObjCEncodingForMethodDecl
    // The one hard-coded here is generated for macOS 64Bit
    Constant *MethType = nullptr;
    if (triple.isOSDarwin() && triple.isArch64Bit()) {
      MethType = IRB->CreateGlobalStringPtr("v16@0:8");
    } else if (triple.isOSDarwin() && triple.isArch32Bit()) {
      MethType = IRB->CreateGlobalStringPtr("v8@0:4");
    } else {
      errs() << "Unknown Platform.Blindly applying method signature for "
                "macOS 64Bit\n";
      MethType = IRB->CreateGlobalStringPtr("v16@0:8");
    }
    Constant *BitCastedIMP = cast<Constant>(
        IRB->CreateBitCast(IRB->GetInsertBlock()->getParent(),
                           objc_getClass->getFunctionType()->getParamType(0)));
    std::vector<Constant *> methodStructContents; //{GEP(NAME),GEP(TYPE),IMP}
    methodStructContents.emplace_back(MethName);
    methodStructContents.emplace_back(MethType);
    methodStructContents.emplace_back(BitCastedIMP);
    Constant *newMethod = ConstantStruct::get(
        cast<StructType>(objc_method_type),
        ArrayRef<Constant *>(methodStructContents)); // objc_method_t
    Constant *newMethodList = ConstantArray::get(
        AT, ArrayRef<Constant *>(newMethod)); // Container of objc_method_t
    std::vector<Type *> newStructType;
    std::vector<Constant *> newStructValue;
    // I'm fully aware that it's consistent Int32 on all platforms
    // This is future-proof
    newStructType.emplace_back(Type::getInt32Ty(M->getContext()));
    newStructValue.emplace_back(
        ConstantInt::get(Type::getInt32Ty(M->getContext()),
                         0x18)); // 0x18 is extracted from
                                 // built-code on macOS.No
                                 // idea what does it mean
    newStructType.emplace_back(Type::getInt32Ty(M->getContext()));
    newStructValue.emplace_back(
        ConstantInt::get(Type::getInt32Ty(M->getContext()),
                         1)); // this is class count
    newStructType.emplace_back(AT);
    newStructValue.emplace_back(newMethodList);
    StructType *newType =
        StructType::get(M->getContext(), ArrayRef<Type *>(newStructType));
    Constant *newMethodStruct = ConstantStruct::get(
        newType,
        ArrayRef<Constant *>(newStructValue)); // l_OBJC_$_CLASS_METHODS_
    GlobalVariable *newMethodStructGV = new GlobalVariable(
        *M, newType, true, GlobalValue::LinkageTypes::PrivateLinkage,
        newMethodStruct, "ACDNewClassMethodMap");
    appendToCompilerUsed(*M, {newMethodStructGV});
    if (methodListGV) {
      newMethodStructGV->copyAttributesFrom(methodListGV);
    }
    Constant *bitcastExpr = ConstantExpr::getBitCast(
        newMethodStructGV,
        opaquepointers ? newType->getPointerTo()
                       : PointerType::getUnqual(StructType::getTypeByName(
                             M->getContext(), "struct.__method_list_t")));
    opaquepointers ? classCS->setOperand(5, bitcastExpr)
                   : classCS->handleOperandChange(
                         classCS->getAggregateElement(5), bitcastExpr);
    if (methodListGV) {
      methodListGV->replaceAllUsesWith(ConstantExpr::getBitCast(
          newMethodStructGV,
          methodListGV->getType())); // llvm.compiler.used doesn't allow
                                     // Null/Undef Value
      methodListGV->dropAllReferences();
      methodListGV->eraseFromParent();
    }
    errs() << "Updated Class Method Map of:" << class_ro->getName() << "\n";
    // End ClassCS Handling
  } // handleClass
  void HandleMethods(ConstantStruct *class_ro, IRBuilder<> *IRB, Module *M,
                     Value *Class, bool isMetaClass) {
    Function *sel_registerName = M->getFunction("sel_registerName");
    Function *class_replaceMethod = M->getFunction("class_replaceMethod");
    Function *class_getName = M->getFunction("class_getName");
    Function *objc_getMetaClass = M->getFunction("objc_getMetaClass");
    StructType *objc_method_list_t_type =
        StructType::getTypeByName(M->getContext(), "struct.__method_list_t");
    for (unsigned int i = 0; i < class_ro->getType()->getNumElements(); i++) {
      Constant *tmp = dyn_cast<Constant>(class_ro->getAggregateElement(i));
      if (tmp->isNullValue()) {
        continue;
      }
      Type *type = tmp->getType();
      if ((!opaquepointers &&
           type == PointerType::getUnqual(objc_method_list_t_type)) ||
          (opaquepointers &&
#if LLVM_VERSION_MAJOR >= 18
           (tmp->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().starts_with("_OBJC_$_CLASS_METHODS")))) {
#else
           (tmp->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().startswith("_OBJC_$_CLASS_METHODS")))) {
#endif
        // Insert Methods
        GlobalVariable *methodListGV =
            readPtrauth(cast<GlobalVariable>(tmp->stripPointerCasts()));
        assert(methodListGV->hasInitializer() &&
               "MethodListGV doesn't have initializer");
        ConstantStruct *methodListStruct =
            cast<ConstantStruct>(methodListGV->getInitializer());
        // Extracting %struct._objc_method array from %struct.__method_list_t =
        // type { i32, i32, [0 x %struct._objc_method] }
        if (methodListStruct->getOperand(2)->isZeroValue()) {
          return;
        }
        ConstantArray *methodList =
            cast<ConstantArray>(methodListStruct->getOperand(2));
        for (unsigned int i = 0; i < methodList->getNumOperands(); i++) {
          ConstantStruct *methodStruct =
              cast<ConstantStruct>(methodList->getOperand(i));
          // methodStruct has type %struct._objc_method = type { i8*, i8*, i8* }
          // which contains {GEP(NAME),GEP(TYPE),IMP}
          // Let's extract these info now
          // We should first register the selector
          Constant *SELName = IRB->CreateGlobalStringPtr(
              cast<ConstantDataSequential>(
                  cast<GlobalVariable>(
                      opaquepointers
                          ? methodStruct->getOperand(0)
                          : cast<ConstantExpr>(methodStruct->getOperand(0))
                                ->getOperand(0))
                      ->getInitializer())
                  ->getAsCString());
          CallInst *SEL = IRB->CreateCall(sel_registerName, {SELName});
          Type *IMPType =
              class_replaceMethod->getFunctionType()->getParamType(2);
          Value *BitCastedIMP = IRB->CreateBitCast(
              appleptrauth
                  ? opaquepointers
                        ? cast<GlobalVariable>(methodStruct->getOperand(2))
                              ->getInitializer()
                              ->getOperand(0)
                        : cast<ConstantExpr>(
                              cast<GlobalVariable>(methodStruct->getOperand(2))
                                  ->getInitializer()
                                  ->getOperand(0))
                              ->getOperand(0)
                  : methodStruct->getOperand(2),
              IMPType);
          std::vector<Value *> replaceMethodArgs;
          if (isMetaClass) {
            CallInst *className = IRB->CreateCall(class_getName, {Class});
            CallInst *MetaClass =
                IRB->CreateCall(objc_getMetaClass, {className});
            replaceMethodArgs.emplace_back(MetaClass); // Class
          } else {
            replaceMethodArgs.emplace_back(Class); // Class
          }
          replaceMethodArgs.emplace_back(SEL);          // SEL
          replaceMethodArgs.emplace_back(BitCastedIMP); // imp
          replaceMethodArgs.emplace_back(IRB->CreateGlobalStringPtr(
              cast<ConstantDataSequential>(
                  cast<GlobalVariable>(
                      opaquepointers
                          ? methodStruct->getOperand(1)
                          : cast<ConstantExpr>(methodStruct->getOperand(1))
                                ->getOperand(0))
                      ->getInitializer())
                  ->getAsCString())); // type
          IRB->CreateCall(class_replaceMethod,
                          ArrayRef<Value *>(replaceMethodArgs));
          if (RenameMethodIMP) {
            Function *MethodIMP = cast<Function>(
                appleptrauth
                    ? opaquepointers
                          ? cast<GlobalVariable>(methodStruct->getOperand(2))
                                ->getInitializer()
                                ->getOperand(0)
                          : cast<ConstantExpr>(
                                cast<GlobalVariable>(
                                    methodStruct->getOperand(2)->getOperand(0))
                                    ->getInitializer()
                                    ->getOperand(0))
                                ->getOperand(0)
                : opaquepointers ? methodStruct->getOperand(2)
                                 : methodStruct->getOperand(2)->getOperand(0));
            MethodIMP->setName("ACDMethodIMP");
          }
        }
      }
    }
  }
  GlobalVariable *readPtrauth(GlobalVariable *GV) {
    if (GV->getSection() == "llvm.ptrauth") {
      Value *V = GV->getInitializer()->getOperand(0);
      return cast<GlobalVariable>(
          opaquepointers ? V : cast<ConstantExpr>(V)->getOperand(0));
    }
    return GV;
  }
};
} // namespace llvm
ModulePass *llvm::createAntiClassDumpPass() { return new AntiClassDump(); }
char AntiClassDump::ID = 0;
INITIALIZE_PASS(AntiClassDump, "acd", "Enable Anti-ClassDump.", false, false)
