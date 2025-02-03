// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "include/Substitution.h"
#include "include/CryptoUtils.h"
#include "include/SubstituteImpl.h"
#include "include/Utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

#define DEBUG_TYPE "substitution"

static cl::opt<uint32_t>
    ObfTimes("sub_loop",
             cl::desc("Choose how many time the -sub pass loops on a function"),
             cl::value_desc("number of times"), cl::init(1), cl::Optional);
static uint32_t ObfTimesTemp = 1;

static cl::opt<uint32_t>
    ObfProbRate("sub_prob",
                cl::desc("Choose the probability [%] each instructions will be "
                         "obfuscated by the InstructionSubstitution pass"),
                cl::value_desc("probability rate"), cl::init(50), cl::Optional);
static uint32_t ObfProbRateTemp = 50;

// Stats
STATISTIC(Add, "Add substitued");
STATISTIC(Sub, "Sub substitued");
STATISTIC(Mul, "Mul substitued");
// STATISTIC(Div,  "Div substitued");
// STATISTIC(Rem,  "Rem substitued");
// STATISTIC(Shi,  "Shift substitued");
STATISTIC(And, "And substitued");
STATISTIC(Or, "Or substitued");
STATISTIC(Xor, "Xor substitued");

namespace {

struct Substitution : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  bool flag;
  Substitution(bool flag) : Substitution() { this->flag = flag; }
  Substitution() : FunctionPass(ID) { this->flag = true; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscateUint32Option(&F, "sub_loop", &ObfTimesTemp))
      ObfTimesTemp = ObfTimes;
    if (!toObfuscateUint32Option(&F, "sub_prob", &ObfProbRateTemp))
      ObfProbRateTemp = ObfProbRate;

    // Check if the percentage is correct
    if (ObfTimesTemp <= 0) {
      errs() << "Substitution application number -sub_loop=x must be x > 0";
      return false;
    }
    if (ObfProbRateTemp > 100) {
      errs() << "InstructionSubstitution application instruction percentage "
                "-sub_prob=x must be 0 < x <= 100";
      return false;
    }

    Function *tmp = &F;
    // Do we obfuscate
    if (toObfuscate(flag, tmp, "sub")) {
      errs() << "Running Instruction Substitution On " << F.getName() << "\n";
      substitute(tmp);
      return true;
    }

    return false;
  };
  bool substitute(Function *f) {
    // Loop for the number of time we run the pass on the function
    uint32_t times = ObfTimesTemp;
    do {
      for (Instruction &inst : instructions(f))
        if (inst.isBinaryOp() &&
            cryptoutils->get_range(100) <= ObfProbRateTemp) {
          switch (inst.getOpcode()) {
          case BinaryOperator::Add:
            // case BinaryOperator::FAdd:
            SubstituteImpl::substituteAdd(cast<BinaryOperator>(&inst));
            ++Add;
            break;
          case BinaryOperator::Sub:
            // case BinaryOperator::FSub:
            SubstituteImpl::substituteSub(cast<BinaryOperator>(&inst));
            ++Sub;
            break;
          case BinaryOperator::Mul:
            // case BinaryOperator::FMul:
            SubstituteImpl::substituteMul(cast<BinaryOperator>(&inst));
            ++Mul;
            break;
          case BinaryOperator::UDiv:
          case BinaryOperator::SDiv:
          case BinaryOperator::FDiv:
            //++Div;
            break;
          case BinaryOperator::URem:
          case BinaryOperator::SRem:
          case BinaryOperator::FRem:
            //++Rem;
            break;
          case Instruction::Shl:
            //++Shi;
            break;
          case Instruction::LShr:
            //++Shi;
            break;
          case Instruction::AShr:
            //++Shi;
            break;
          case Instruction::And:
            SubstituteImpl::substituteAnd(cast<BinaryOperator>(&inst));
            ++And;
            break;
          case Instruction::Or:
            SubstituteImpl::substituteOr(cast<BinaryOperator>(&inst));
            ++Or;
            break;
          case Instruction::Xor:
            SubstituteImpl::substituteXor(cast<BinaryOperator>(&inst));
            ++Xor;
            break;
          default:
            break;
          } // End switch
        } // End isBinaryOp
    } while (--times); // for times
    return true;
  }
};
} // namespace

char Substitution::ID = 0;
INITIALIZE_PASS(Substitution, "subobf", "Enable Instruction Substitution.",
                false, false)
FunctionPass *llvm::createSubstitutionPass(bool flag) {
  return new Substitution(flag);
}
