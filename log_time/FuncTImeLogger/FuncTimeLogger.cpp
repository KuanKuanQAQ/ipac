#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

namespace {

struct FuncTimeLogger : public PassInfoMixin<FuncTimeLogger> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
      return PreservedAnalyses::all();

    LLVMContext &C = F.getContext();
    Module *M = F.getParent();

    FunctionCallee LogFunc = M->getOrInsertFunction(
        "log_time",
        Type::getVoidTy(C),
        Type::getInt8PtrTy(C),
        Type::getInt1Ty(C)
    );

    IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());
    Value *FuncName = Builder.CreateGlobalStringPtr(F.getName());
    Value *IsExit = Builder.getInt1(false);
    Builder.CreateCall(LogFunc, {FuncName, IsExit});

    for (auto &BB : F) {
      Instruction *Term = BB.getTerminator();
      if (isa<ReturnInst>(Term)) {
        IRBuilder<> RetBuilder(Term);
        Value *ExitVal = RetBuilder.getInt1(true);
        RetBuilder.CreateCall(LogFunc, {FuncName, ExitVal});
      }
    }

    return PreservedAnalyses::none();
  }
};

} // namespace

// === Plugin registration for new pass manager ===
llvm::PassPluginLibraryInfo getFuncTimeLoggerPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FuncTimeLogger", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "functime") {
                    FPM.addPass(FuncTimeLogger());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return getFuncTimeLoggerPluginInfo();
}