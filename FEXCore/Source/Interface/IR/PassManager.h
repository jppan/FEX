// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
$end_info$
*/

#pragma once

#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/ThreadPoolAllocator.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/vector.h>

#include <functional>
#include <utility>

namespace FEXCore::Context {
class ContextImpl;
}

namespace FEXCore::HLE {
class SyscallHandler;
}

namespace FEXCore::IR {
class PassManager;
class IREmitter;

class Pass {
public:
  virtual ~Pass() = default;
  virtual void Run(IREmitter* IREmit) = 0;

  void RegisterPassManager(PassManager* _Manager) {
    Manager = _Manager;
  }

protected:
  PassManager* Manager {};
};

class PassManager final {
public:
  void AddDefaultPasses(FEXCore::Context::ContextImpl* ctx);
  void AddDefaultValidationPasses();
  Pass* InsertPass(fextl::unique_ptr<Pass> Pass, fextl::string Name = "") {
    auto PassPtr = InsertAt(Passes.end(), std::move(Pass))->get();

    if (!Name.empty()) {
      NameToPassMaping[Name] = PassPtr;
    }
    return PassPtr;
  }

  void InsertRegisterAllocationPass(FEXCore::Context::ContextImpl* ctx);

  void Run(IREmitter* IREmit);

  bool HasPass(fextl::string Name) const {
    return NameToPassMaping.contains(Name);
  }

  template<typename T>
  T* GetPass(fextl::string Name) {
#ifdef FEX_IOS_HOST
    /* iOS-Madeira ml2028: every named pass is inserted together with its
     * concrete type (currently the only typed lookup is "RA", installed by
     * InsertRegisterAllocationPass).  Do not send this lookup through
     * libc++'s __dynamic_cast on ARM64EC.  The runtime implements its virtual
     * RTTI walk with an ARM64EC exit thunk, and the JIT-pool copy of libc++'s
     * __os_arm64x_dispatch_call_no_redirect slot can still contain the image
     * initializer (NULL) while the first FEX thread is being constructed.
     * That made CreateArm64JITCore branch directly to address zero. */
    return static_cast<T*>(NameToPassMaping[Name]);
#else
    return dynamic_cast<T*>(NameToPassMaping[Name]);
#endif
  }

  Pass* GetPass(fextl::string Name) {
    return NameToPassMaping[Name];
  }

  void RegisterSyscallHandler(FEXCore::HLE::SyscallHandler* Handler) {
    SyscallHandler = Handler;
  }

  void Finalize();

protected:
  FEXCore::HLE::SyscallHandler* SyscallHandler {};

private:
  using PassArrayType = fextl::vector<fextl::unique_ptr<Pass>>;
  PassArrayType::iterator InsertAt(PassArrayType::iterator pos, fextl::unique_ptr<Pass> Pass) {
    Pass->RegisterPassManager(this);
    return Passes.insert(pos, std::move(Pass));
  }
  PassArrayType Passes;
  fextl::unordered_map<fextl::string, Pass*> NameToPassMaping;

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  fextl::vector<fextl::unique_ptr<Pass>> ValidationPasses;
  void InsertValidationPass(fextl::unique_ptr<Pass> Pass, fextl::string Name = "") {
    Pass->RegisterPassManager(this);
    auto PassPtr = ValidationPasses.emplace_back(std::move(Pass)).get();

    if (!Name.empty()) {
      NameToPassMaping[Name] = PassPtr;
    }
  }
#endif

  FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);
  FEX_CONFIG_OPT(PassManagerDumpIR, PASSMANAGERDUMPIR);
};
} // namespace FEXCore::IR
