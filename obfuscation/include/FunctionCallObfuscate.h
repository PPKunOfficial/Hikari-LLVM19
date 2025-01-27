#ifndef _FUNCTION_CALL_OBFUSCATION_H_
#define _FUNCTION_CALL_OBFUSCATION_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

FunctionPass *createFunctionCallObfuscatePass(bool flag);
void initializeFunctionCallObfuscatePass(PassRegistry &Registry);

} // namespace llvm

#endif
