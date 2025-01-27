#ifndef _INDIRECT_BRANCH_H_
#define _INDIRECT_BRANCH_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

FunctionPass *createIndirectBranchPass(bool flag);
void initializeIndirectBranchPass(PassRegistry &Registry);

} // namespace llvm

#endif
