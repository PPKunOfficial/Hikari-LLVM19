#ifndef _STRING_ENCRYPTION_H_
#define _STRING_ENCRYPTION_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

ModulePass *createStringEncryptionPass(bool flag);
void initializeStringEncryptionPass(PassRegistry &Registry);

} // namespace llvm

#endif
