#ifndef _CONSTANT_ENCRYPTION_H_
#define _CONSTANT_ENCRYPTION_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

ModulePass *createConstantEncryptionPass(bool flag);
void initializeConstantEncryptionPass(PassRegistry &Registry);

} // namespace llvm

#endif
