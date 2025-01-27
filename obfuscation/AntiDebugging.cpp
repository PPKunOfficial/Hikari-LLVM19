/*
 *  LLVM AntiDebugging Pass
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
#include "include/AntiDebugging.h"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/ADT/SmallString.h"
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include <fstream>

using namespace llvm;

static cl::opt<std::string> PreCompiledIRPath(
    "adbextirpath",
    cl::desc("External Path Pointing To Pre-compiled AntiDebugging IR"),
    cl::value_desc("filename"), cl::init(""));
static cl::opt<uint32_t>
    ProbRate("adb_prob",
             cl::desc("Choose the probability [%] For Each Function To Be "
                      "Obfuscated By AntiDebugging"),
             cl::value_desc("Probability Rate"), cl::init(40), cl::Optional);

namespace llvm {
struct AntiDebugging : public ModulePass {
  static char ID;
  bool flag;
  bool initialized;
  Triple triple;
  AntiDebugging() : ModulePass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  AntiDebugging(bool flag) : ModulePass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "AntiDebugging"; }
  bool initialize(Module &M) {
    if (PreCompiledIRPath == "") {
      SmallString<32> Path;
      if (sys::path::home_directory(Path)) { // Stolen from LineEditor.cpp
        sys::path::append(Path, "Hikari");
        Triple tri(M.getTargetTriple());
        sys::path::append(Path, "PrecompiledAntiDebugging-" +
                                    Triple::getArchTypeName(tri.getArch()) +
                                    "-" + Triple::getOSTypeName(tri.getOS()) +
                                    ".bc");
        PreCompiledIRPath = Path.c_str();
      }
    }
    std::ifstream f(PreCompiledIRPath);
    if (f.good()) {
      errs() << "Linking PreCompiled AntiDebugging IR From:"
             << PreCompiledIRPath << "\n";
      SMDiagnostic SMD;
      std::unique_ptr<Module> ADBM(
          parseIRFile(StringRef(PreCompiledIRPath), SMD, M.getContext()));
      Linker::linkModules(M, std::move(ADBM), Linker::Flags::LinkOnlyNeeded);
      // FIXME: Mess with GV in ADBCallBack
      Function *ADBCallBack = M.getFunction("ADBCallBack");
      if (ADBCallBack) {
        assert(!ADBCallBack->isDeclaration() &&
               "AntiDebuggingCallback is not concrete!");
        ADBCallBack->setVisibility(
            GlobalValue::VisibilityTypes::HiddenVisibility);
        ADBCallBack->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
        ADBCallBack->removeFnAttr(Attribute::AttrKind::NoInline);
        ADBCallBack->removeFnAttr(Attribute::AttrKind::OptimizeNone);
        ADBCallBack->addFnAttr(Attribute::AttrKind::AlwaysInline);
      }
      Function *ADBInit = M.getFunction("InitADB");
      if (ADBInit) {
        assert(!ADBInit->isDeclaration() &&
               "AntiDebuggingInitializer is not concrete!");
        ADBInit->setVisibility(GlobalValue::VisibilityTypes::HiddenVisibility);
        ADBInit->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
        ADBInit->removeFnAttr(Attribute::AttrKind::NoInline);
        ADBInit->removeFnAttr(Attribute::AttrKind::OptimizeNone);
        ADBInit->addFnAttr(Attribute::AttrKind::AlwaysInline);
      }
    } else {
      errs() << "Failed To Link PreCompiled AntiDebugging IR From:"
             << PreCompiledIRPath << "\n";
    }
    this->initialized = true;
    this->triple = Triple(M.getTargetTriple());
    return true;
  }
  bool runOnModule(Module &M) override {
    if (ProbRate > 100) {
      errs() << "AntiDebugging application function percentage "
                "-adb_prob=x must be 0 < x <= 100";
      return false;
    }
    for (Function &F : M) {
      if (toObfuscate(flag, &F, "adb") && F.getName() != "ADBCallBack" &&
          F.getName() != "InitADB") {
        errs() << "Running AntiDebugging On " << F.getName() << "\n";
        if (!this->initialized)
          initialize(M);
        if (cryptoutils->get_range(100) <= ProbRate)
          runOnFunction(F);
      }
    }
    return true;
  }
  bool runOnFunction(Function &F) {
    BasicBlock *EntryBlock = &(F.getEntryBlock());
    // Now operate on Linked AntiDBGCallbacks
    Function *ADBCallBack = F.getParent()->getFunction("ADBCallBack");
    Function *ADBInit = F.getParent()->getFunction("InitADB");
    if (ADBCallBack && ADBInit) {
      CallInst::Create(ADBInit, "",
                       cast<Instruction>(EntryBlock->getFirstInsertionPt()));
    } else {
      errs() << "The ADBCallBack and ADBInit functions were not found\n";
      if (!F.getReturnType()
               ->isVoidTy()) // We insert InlineAsm in the Terminator, which
                             // causes register contamination if the return type
                             // is not Void.
        return false;
      if (triple.isOSDarwin() && triple.isAArch64()) {
        errs() << "Injecting Inline Assembly AntiDebugging For:"
               << F.getParent()->getTargetTriple() << "\n";
        std::string antidebugasm = "";
        switch (cryptoutils->get_range(2)) {
        case 0: {
          std::string s[] = {"mov x0, #31\n", "mov w0, #31\n", "mov x1, #0\n",
                             "mov w1, #0\n",  "mov x2, #0\n",  "mov w2, #0\n",
                             "mov x3, #0\n",  "mov w3, #0\n",  "mov x16, #26\n",
                             "mov w16, #26\n"}; // svc ptrace
          bool c[5] = {false, false, false, false, false};
          while (c[0] != true || c[1] != true || c[2] != true || c[3] != true ||
                 c[4] != true) {
            switch (cryptoutils->get_range(5)) {
            case 0:
              if (!c[0]) {
                antidebugasm += s[cryptoutils->get_range(2)];
                c[0] = true;
              }
              break;
            case 1:
              if (!c[1]) {
                antidebugasm += s[2 + cryptoutils->get_range(2)];
                c[1] = true;
              }
              break;
            case 2:
              if (!c[2]) {
                antidebugasm += s[4 + cryptoutils->get_range(2)];
                c[2] = true;
              }
              break;
            case 3:
              if (!c[3]) {
                antidebugasm += s[6 + cryptoutils->get_range(2)];
                c[3] = true;
              }
              break;
            case 4:
              if (!c[4]) {
                antidebugasm += s[8 + cryptoutils->get_range(2)];
                c[4] = true;
              }
              break;
            default:
              break;
            }
          }
          break;
        }
        case 1: {
          std::string s[] = {"mov x0, #26\n", "mov w0, #26\n", "mov x1, #31\n",
                             "mov w1, #31\n", "mov x2, #0\n",  "mov w2, #0\n",
                             "mov x3, #0\n",  "mov w3, #0\n",  "mov x16, #0\n",
                             "mov w16, #0\n"}; // svc syscall ptrace
          bool c[5] = {false, false, false, false, false};
          while (c[0] != true || c[1] != true || c[2] != true || c[3] != true ||
                 c[4] != true) {
            switch (cryptoutils->get_range(5)) {
            case 0:
              if (!c[0]) {
                antidebugasm += s[cryptoutils->get_range(2)];
                c[0] = true;
              }
              break;
            case 1:
              if (!c[1]) {
                antidebugasm += s[2 + cryptoutils->get_range(2)];
                c[1] = true;
              }
              break;
            case 2:
              if (!c[2]) {
                antidebugasm += s[4 + cryptoutils->get_range(2)];
                c[2] = true;
              }
              break;
            case 3:
              if (!c[3]) {
                antidebugasm += s[6 + cryptoutils->get_range(2)];
                c[3] = true;
              }
              break;
            case 4:
              if (!c[4]) {
                antidebugasm += s[8 + cryptoutils->get_range(2)];
                c[4] = true;
              }
              break;
            default:
              break;
            }
          }
          break;
        }
        }
        antidebugasm +=
            "svc #" + std::to_string(cryptoutils->get_range(65536)) + "\n";
        InlineAsm *IA = InlineAsm::get(
            FunctionType::get(Type::getVoidTy(EntryBlock->getContext()), false),
            antidebugasm, "", true, false);
        Instruction *I = nullptr;
        for (BasicBlock &BB : F)
          I = BB.getTerminator();
#if LLVM_VERSION_MAJOR >= 16
        CallInst::Create(IA, std::nullopt, "", I);
#else
        CallInst::Create(IA, None, "", I);
#endif
      } else {
        errs() << "Unsupported Inline Assembly AntiDebugging Target: "
               << F.getParent()->getTargetTriple() << "\n";
      }
    }
    return true;
  }
};

ModulePass *createAntiDebuggingPass(bool flag) {
  return new AntiDebugging(flag);
}
} // namespace llvm

char AntiDebugging::ID = 0;
INITIALIZE_PASS(AntiDebugging, "adb", "Enable AntiDebugging.", false, false)
