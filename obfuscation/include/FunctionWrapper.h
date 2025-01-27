#ifndef _FUNCTION_WRAPPER_H_
#define _FUNCTION_WRAPPER_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

ModulePass *createFunctionWrapperPass(bool flag);
void initializeFunctionWrapperPass(PassRegistry &Registry);

} // namespace llvm

#endif
