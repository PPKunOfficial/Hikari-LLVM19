#ifndef _ANTI_CLASSDUMP_H_
#define _ANTI_CLASSDUMP_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

ModulePass *createAntiClassDumpPass();
void initializeAntiClassDumpPass(PassRegistry &Registry);

} // namespace llvm

#endif
