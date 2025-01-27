//===- BogusControlFlow.h - BogusControlFlow Obfuscation
// pass-------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===--------------------------------------------------------------------------------===//
//
// This file contains includes and defines for the bogusControlFlow pass
//
//===--------------------------------------------------------------------------------===//

#ifndef _BOGUSCONTROLFLOW_H_
#define _BOGUSCONTROLFLOW_H_

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {

FunctionPass *createBogusControlFlowPass(bool flag);
void initializeBogusControlFlowPass(PassRegistry &Registry);

} // namespace llvm

#endif
