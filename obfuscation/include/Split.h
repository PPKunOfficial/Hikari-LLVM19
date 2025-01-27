#ifndef _SPLIT_H_
#define _SPLIT_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

FunctionPass *createSplitBasicBlockPass(bool flag);
void initializeSplitBasicBlockPass(PassRegistry &Registry);

} // namespace llvm

#endif
