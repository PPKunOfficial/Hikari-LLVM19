//===- Substitution.h - Substitution Obfuscation
// pass-------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains includes and defines for the substitution pass
//
//===----------------------------------------------------------------------===//

#ifndef _SUBSTITUTIONS_H_
#define _SUBSTITUTIONS_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

FunctionPass *createSubstitutionPass(bool flag);
void initializeSubstitutionPass(PassRegistry &Registry);

} // namespace llvm

#endif
