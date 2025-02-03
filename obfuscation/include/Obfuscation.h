#ifndef _OBFUSCATION_H_
#define _OBFUSCATION_H_

#include "include/AntiClassDump.h"
#include "include/AntiDebugging.h"
#include "include/AntiHook.h"
#include "include/BogusControlFlow.h"
#include "include/ConstantEncryption.h"
#include "include/CryptoUtils.h"
#include "include/Flattening.h"
#include "include/FunctionCallObfuscate.h"
#include "include/FunctionWrapper.h"
#include "include/IndirectBranch.h"
#include "include/Split.h"
#include "include/StringEncryption.h"
#include "include/Substitution.h"
#include "llvm/Support/Timer.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace llvm {

class ObfuscationPass : public PassInfoMixin<ObfuscationPass> {
public:
  ObfuscationPass() {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }
};

ModulePass *createObfuscationLegacyPass();
void initializeObfuscationPass(PassRegistry &Registry);

} // namespace llvm

#endif
