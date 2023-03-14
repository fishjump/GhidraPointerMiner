#pragma once

#include "Value.hpp"

namespace pointer_solver {

struct Copy {
  // output = COPY input0
  // output: should be the same type as input0
  // input0: should be the same type as output
  void meet(Value *output, Value *input0) {
    output->propagateTo(input0);
    input0->propagateTo(output);
  }
};

struct Load {
  // output = LOAD input0
  // output: cannot deduce the type
  // input0: should be a pointer
  void meet(Value *output, Value *input0) { input0->meet(ToPointer()); }

  // output = LOAD input0, input1
  // output: cannot deduce the type
  // input0: should be a pointer
  // input1: should be an integer offset
  void meet(Value *output, Value *input0, Value *input1) {
    input0->meet(ToPointer());
    input1->meet(ToInt());
  }
};

struct Store {
  // STORE input0, input1
  // input0: should be a pointer
  // input1: cannot deduce the type
  void meet(Value *input0, Value *input1) { input0->meet(ToPointer()); }

  // STORE input0, input1, input2
  // input0: should be a pointer
  // input1: should be an integer offset
  // input2: cannot deduce the type
  void meet(Value *input0, Value *input1, Value *input2) {
    input0->meet(ToPointer());
    input1->meet(ToInt());
  }
};

struct Branch {

  // BRANCH input0
  // input0: should be a pointer
  void meet(Value *input0) { input0->meet(ToPointer()); }
};

struct CBranch {

  // CBRANCH input0, input1
  // input0: should be a pointer
  // input1: should be a boolean
  void meet(Value *input0, Value *input1) {
    input0->meet(ToPointer());
    input1->meet(ToBool());
  }
};

struct BranchIndirect {

  // BRANCHIND input0
  // input0: should be a pointer
  void meet(Value *input0) { input0->meet(ToPointer()); }
};

struct Call {

  // CALL input0
  // input0: should be a pointer
  void meet(Value *input0) { input0->meet(ToPointer()); }
};

struct CallIndirect {

  // CALLIND input0
  // input0: should be a pointer
  void meet(Value *input0) { input0->meet(ToPointer()); }
};

struct Return {

  // RETURN input0
  // input0: cannot deduce the type
  void meet(Value *input0) { input0->meet(ToPointer()); }
};

struct PtrSub {

  // output = PTRSUB input0, input1
  // output: should be a pointer
  // input0: should be a pointer
  // input1: should be an integer
  void meet(Value *output, Value *input0, Value *input1) {
    output->meet(ToPointer());
    input0->meet(ToPointer());
    input1->meet(ToInt());
  }
};

} // namespace pointer_solver