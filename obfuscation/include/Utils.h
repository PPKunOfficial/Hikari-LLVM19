#ifndef _UTILS_H_
#define _UTILS_H_

#include "llvm/IR/Module.h"
#include <string>

namespace llvm {

void fixStack(Function *f);
bool toObfuscate(bool flag, Function *f, std::string attribute);
bool toObfuscateBoolOption(Function *f, std::string option, bool *val);
bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val);
bool hasApplePtrauth(Module *M);
void FixFunctionConstantExpr(Function *Func);
void turnOffOptimization(Function *f);
void annotation2Metadata(Module &M);
bool readAnnotationMetadata(Function *f, std::string annotation);
void writeAnnotationMetadata(Function *f, std::string annotation);
bool AreUsersInOneFunction(GlobalVariable *GV);
#if 0
std::map<GlobalValue*, StringRef> BuildAnnotateMap(Module& M);
#endif

} // namespace llvm

#endif
