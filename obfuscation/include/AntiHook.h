#ifndef _ANTI_HOOK_H_
#define _ANTI_HOOK_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

ModulePass *createAntiHookPass(bool flag);
void initializeAntiHookPass(PassRegistry &Registry);

} // namespace llvm

#endif
