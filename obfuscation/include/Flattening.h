//===- FlatteningIncludes.h - Flattening Obfuscation pass------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains includes and defines for the flattening pass
//
//===----------------------------------------------------------------------===//

#ifndef _FLATTENING_H_
#define _FLATTENING_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {
FunctionPass *createFlatteningPass(bool flag);
void initializeFlatteningPass(PassRegistry &Registry);

} // namespace llvm

#endif
