#pragma once

#include "Value.hpp"

#include <iostream>

#define CREATE_INT_LOGIC_OPERATION(NAME, OP_NAME)                              \
  struct NAME : IntLogicOperation {                                            \
    bool _sanityCheck(Instruction *inst) final {                               \
      return (inst->getOp() == #OP_NAME) &&                                    \
             IntLogicOperation::_sanityCheck(inst);                            \
    }                                                                          \
  };

#define CREATE_INT_BINARY_OPERATION(NAME, OP_NAME)                             \
  struct NAME : IntBinaryOperation {                                           \
    bool _sanityCheck(Instruction *inst) final {                               \
      return (inst->getOp() == #OP_NAME) &&                                    \
             IntBinaryOperation::_sanityCheck(inst);                           \
    }                                                                          \
  };

#define CREATE_INT_UNARY_OPERATION(NAME, OP_NAME)                              \
  struct NAME : IntUnaryOperation {                                            \
    bool _sanityCheck(Instruction *inst) final {                               \
      return (inst->getOp() == #OP_NAME) &&                                    \
             IntUnaryOperation::_sanityCheck(inst);                            \
    }                                                                          \
  };

#define CREATE_FLOAT_BINARY_OPERATION(NAME, OP_NAME)                           \
  struct NAME : Operation {                                                    \
    bool _sanityCheck(Instruction *inst) final {                               \
      return inst->getOp() == #OP_NAME && inst->getResult() != nullptr &&      \
             inst->getOperands().size() == 2;                                  \
    }                                                                          \
                                                                               \
    void _roughDeduce(Instruction *inst) final {                               \
      auto output = inst->getResult();                                         \
      auto input0 = inst->getOperands()[0];                                    \
      auto input1 = inst->getOperands()[1];                                    \
      output->deduceType(ToFloat());                                           \
      input0->deduceType(ToFloat());                                           \
      input1->deduceType(ToFloat());                                           \
    }                                                                          \
  };

#define CREATE_FLOAT_UNARY_OPERATION(NAME, OP_NAME)                            \
  struct NAME : Operation {                                                    \
    bool _sanityCheck(Instruction *inst) final {                               \
      return inst->getOp() == #OP_NAME && inst->getResult() != nullptr &&      \
             inst->getOperands().size() == 1;                                  \
    }                                                                          \
                                                                               \
    void _roughDeduce(Instruction *inst) final {                               \
      auto output = inst->getResult();                                         \
      auto input0 = inst->getOperands()[0];                                    \
      output->deduceType(ToFloat());                                           \
      input0->deduceType(ToFloat());                                           \
    }                                                                          \
  };

#define CREATE_FLOAT_COMPARISON_OPERATION(NAME, OP_NAME)                       \
  struct NAME : Operation {                                                    \
    bool _sanityCheck(Instruction *inst) final {                               \
      return inst->getOp() == #OP_NAME && inst->getResult() != nullptr &&      \
             inst->getOperands().size() == 2;                                  \
    }                                                                          \
                                                                               \
    void _roughDeduce(Instruction *inst) final {                               \
      auto output = inst->getResult();                                         \
      auto input0 = inst->getOperands()[0];                                    \
      auto input1 = inst->getOperands()[1];                                    \
      output->deduceType(ToBool());                                            \
      input0->deduceType(ToFloat());                                           \
      input1->deduceType(ToFloat());                                           \
    }                                                                          \
  };

#define CREATE_BOOL_UNARY_OPERATION(NAME, OP_NAME)                             \
  struct NAME : Operation {                                                    \
    bool _sanityCheck(Instruction *inst) final {                               \
      return inst->getOp() == #OP_NAME && inst->getResult() != nullptr &&      \
             inst->getOperands().size() == 1;                                  \
    }                                                                          \
                                                                               \
    void _roughDeduce(Instruction *inst) final {                               \
      auto output = inst->getResult();                                         \
      auto input0 = inst->getOperands()[0];                                    \
      output->deduceType(ToBool());                                            \
      input0->deduceType(ToBool());                                            \
    }                                                                          \
  };

#define CREATE_BOOL_BINARY_OPERATION(NAME, OP_NAME)                            \
  struct NAME : Operation {                                                    \
    bool _sanityCheck(Instruction *inst) final {                               \
      return inst->getOp() == #OP_NAME && inst->getResult() != nullptr &&      \
             inst->getOperands().size() == 2;                                  \
    }                                                                          \
                                                                               \
    void _roughDeduce(Instruction *inst) final {                               \
      auto output = inst->getResult();                                         \
      auto input0 = inst->getOperands()[0];                                    \
      auto input1 = inst->getOperands()[1];                                    \
      output->deduceType(ToBool());                                            \
      input0->deduceType(ToBool());                                            \
      input1->deduceType(ToBool());                                            \
    }                                                                          \
  };

#define TO_POINTER_GUARD(VAL)                                                  \
  {                                                                            \
    if ((VAL)->getSize() == 8) {                                               \
      (VAL)->deduceType(ToPointer());                                          \
    }                                                                          \
  }

namespace pointer_solver {

struct Operation {
  virtual bool _sanityCheck(Instruction *inst) {
    return false;
  }
  virtual void _roughDeduce(Instruction *inst){};
  virtual void _preciseDeduceStage1(Instruction *inst){};
  virtual void _preciseDeduceStage2(Instruction *inst){};

  // Make unknows to int, bool, float as many as possible
  void roughDeduce(Instruction *inst) {
    if (!_sanityCheck(inst)) {
      return;
    }

    _roughDeduce(inst);
  }

  void preciseDeduceStage1(Instruction *inst) {
    if (!_sanityCheck(inst)) {
      return;
    }

    _preciseDeduceStage1(inst);
  }

  void preciseDeduceStage2(Instruction *inst) {
    if (!_sanityCheck(inst)) {
      return;
    }

    _preciseDeduceStage2(inst);
  }
};

struct IntLogicOperation : Operation {
  bool _sanityCheck(Instruction *inst) override {
    return inst->getResult() != nullptr && inst->getOperands().size() == 2;
  }

  void _roughDeduce(Instruction *inst) override {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    input0->deduceType(ToInt());
    input1->deduceType(ToInt());
    output->deduceType(ToBool());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    if (input0->getValueType() == "Pointer" ||
        input1->getValueType() == "Pointer") {
      TO_POINTER_GUARD(input0);
      TO_POINTER_GUARD(input1);
    }
  }

  void _preciseDeduceStage2(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    if (output->getValueType() == "PointerOfPointer" ||
        input0->getValueType() == "PointerOfPointer" ||
        input1->getValueType() == "PointerOfPointer") {
      output->deduceType(ToPointerOfPointer());
      input0->deduceType(ToPointerOfPointer());
      input1->deduceType(ToPointerOfPointer());
    }
  }
};

struct IntBinaryOperation : Operation {
  bool _sanityCheck(Instruction *inst) override {
    return inst->getResult() != nullptr && inst->getOperands().size() == 2;
  }

  void _roughDeduce(Instruction *inst) override {
    Value *output = inst->getResult();
    Value *input0 = inst->getOperands()[0];
    Value *input1 = inst->getOperands()[1];

    output->deduceType(ToInt());
    input0->deduceType(ToInt());
    input1->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    if (output->getValueType() == "Pointer" ||
        input0->getValueType() == "Pointer" ||
        input1->getValueType() == "Pointer") {
      TO_POINTER_GUARD(output);
      TO_POINTER_GUARD(input0);
      TO_POINTER_GUARD(input1);
    }
  }

  void _preciseDeduceStage2(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    if (output->getValueType() == "PointerOfPointer" ||
        input0->getValueType() == "PointerOfPointer" ||
        input1->getValueType() == "PointerOfPointer") {
      output->deduceType(ToPointerOfPointer());
      input0->deduceType(ToPointerOfPointer());
      input1->deduceType(ToPointerOfPointer());
    }
  }
};

struct IntUnaryOperation : Operation {
  bool _sanityCheck(Instruction *inst) override {
    return inst->getResult() != nullptr && inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) override {
    Value *output = inst->getResult();
    Value *input0 = inst->getOperands()[0];

    output->deduceType(ToInt());
    input0->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];

    if (output->getValueType() == "Pointer" ||
        input0->getValueType() == "Pointer") {
      TO_POINTER_GUARD(output);
      TO_POINTER_GUARD(input0);
    }
  }

  void _preciseDeduceStage2(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];

    if (output->getValueType() == "PointerOfPointer" ||
        input0->getValueType() == "PointerOfPointer") {
      output->deduceType(ToPointerOfPointer());
      input0->deduceType(ToPointerOfPointer());
    }
  }
};

CREATE_INT_LOGIC_OPERATION(IntEqual, INT_EQUAL)
CREATE_INT_LOGIC_OPERATION(IntNotEqual, INT_NOTEQUAL)
CREATE_INT_LOGIC_OPERATION(IntLess, INT_LESS)
CREATE_INT_LOGIC_OPERATION(IntSLess, INT_SLESS)
CREATE_INT_LOGIC_OPERATION(IntLessEqual, INT_LESSEQUAL)
CREATE_INT_LOGIC_OPERATION(IntSLessEqual, INT_SLESSEQUAL)
CREATE_INT_LOGIC_OPERATION(IntCarry, INT_CARRY)
CREATE_INT_LOGIC_OPERATION(IntSCarry, INT_SCARRY)
CREATE_INT_LOGIC_OPERATION(IntSBorrow, INT_SBORROW)

CREATE_INT_BINARY_OPERATION(IntAdd, INT_ADD)
CREATE_INT_BINARY_OPERATION(IntSub, INT_SUB)
CREATE_INT_BINARY_OPERATION(IntXor, INT_XOR)
CREATE_INT_BINARY_OPERATION(IntAnd, INT_AND)
CREATE_INT_BINARY_OPERATION(IntOr, INT_OR)
CREATE_INT_BINARY_OPERATION(IntLeft, INT_LEFT)
CREATE_INT_BINARY_OPERATION(IntRight, INT_RIGHT)
CREATE_INT_BINARY_OPERATION(IntSRight, INT_SRIGHT)
CREATE_INT_BINARY_OPERATION(IntMult, INT_MULT)
CREATE_INT_BINARY_OPERATION(IntDiv, INT_DIV)
CREATE_INT_BINARY_OPERATION(IntRem, INT_REM)
CREATE_INT_BINARY_OPERATION(IntSDiv, INT_SDIV)
CREATE_INT_BINARY_OPERATION(IntSRem, INT_SREM)

CREATE_INT_UNARY_OPERATION(IntZExt, INT_ZEXT)
CREATE_INT_UNARY_OPERATION(IntSExt, INT_SEXT)
CREATE_INT_UNARY_OPERATION(Int2Comp, INT_2COMP)
CREATE_INT_UNARY_OPERATION(IntNegate, INT_NEGATE)

CREATE_FLOAT_COMPARISON_OPERATION(FloatEqual, FLOAT_EQUAL)
CREATE_FLOAT_COMPARISON_OPERATION(FloatNotEqual, FLOAT_NOT_EQUAL)
CREATE_FLOAT_COMPARISON_OPERATION(FloatLess, FLOAT_LESS)
CREATE_FLOAT_COMPARISON_OPERATION(FloatLessEqual, FLOAT_LESS_EQUAL)

CREATE_FLOAT_BINARY_OPERATION(FloatAdd, FLOAT_ADD)
CREATE_FLOAT_BINARY_OPERATION(FloatSub, FLOAT_SUB)
CREATE_FLOAT_BINARY_OPERATION(FloatMult, FLOAT_MULT)
CREATE_FLOAT_BINARY_OPERATION(FloatDiv, FLOAT_DIV)

CREATE_FLOAT_UNARY_OPERATION(FloatNeg, FLOAT_NEG)
CREATE_FLOAT_UNARY_OPERATION(FloatAbs, FLOAT_ABS)
CREATE_FLOAT_UNARY_OPERATION(FloatSqrt, FLOAT_SQRT)
CREATE_FLOAT_UNARY_OPERATION(FloatCeil, FLOAT_CEIL)
CREATE_FLOAT_UNARY_OPERATION(FloatFloor, FLOAT_FLOOR)
CREATE_FLOAT_UNARY_OPERATION(FloatRound, FLOAT_ROUND)
CREATE_FLOAT_UNARY_OPERATION(FloatNan, FLOAT_NAN)

CREATE_BOOL_UNARY_OPERATION(BoolNegate, BOOL_NEGATE)
CREATE_BOOL_BINARY_OPERATION(BoolXor, BOOL_XOR)
CREATE_BOOL_BINARY_OPERATION(BoolAnd, BOOL_AND)
CREATE_BOOL_BINARY_OPERATION(BoolOr, BOOL_OR)

#undef CREATE_INT_LOGIC_OPERATION
#undef CREATE_INT_BINARY_OPERATION
#undef CREATE_INT_UNARY_OPERATION
#undef CREATE_FLOAT_COMPARISON_OPERATION
#undef CREATE_FLOAT_BINARY_OPERATION
#undef CREATE_FLOAT_UNARY_OPERATION
#undef CREATE_BOOL_UNARY_OPERATION
#undef CREATE_BOOL_BINARY_OPERATION

struct Copy : Operation {
  // output = COPY input0
  // output: should be the same type as input0
  // input0: should be the same type as output
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "COPY" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    // if input is some of int, bool or float, then output is the same, vise
    // versa
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];

    if (input0->getValueType() == "Int" || input0->getValueType() == "Bool" ||
        input0->getValueType() == "Float") {
      output->deduceType(*ToSome(input0->getValueType()));
    } else if (output->getValueType() == "Int" ||
               output->getValueType() == "Bool" ||
               output->getValueType() == "Float") {
      input0->deduceType(*ToSome(output->getValueType()));
    }
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];

    if (input0->getValueType() == "Pointer") {
      TO_POINTER_GUARD(output);
    } else if (output->getValueType() == "Pointer") {
      TO_POINTER_GUARD(input0);
    }
  }

  void _preciseDeduceStage2(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];

    if (input0->getValueType() == "PointerOfPointer") {
      output->deduceType(ToPointerOfPointer());
    } else if (output->getValueType() == "PointerOfPointer") {
      output->deduceType(ToPointerOfPointer());
    }
  }
};

struct Load : Operation {
  // output = LOAD input0
  // output: cannot deduce the type
  // input0: should be a pointer

  // output = LOAD input0, input1
  // output: cannot deduce the type
  // input0: should be a pointer
  // input1: should be a pointer
  bool _sanityCheck(Instruction *inst) final {
    return (inst->getOp() == "LOAD" && inst->getResult() != nullptr &&
            inst->getOperands().size() == 1) ||
           (inst->getOp() == "LOAD" && inst->getResult() != nullptr &&
            inst->getOperands().size() == 2);
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    input0->deduceType(ToInt());

    if (inst->getOperands().size() == 2) {
      auto input1 = inst->getOperands()[1];
      input1->deduceType(ToInt());
    }
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);

    if (inst->getOperands().size() == 2) {
      auto input1 = inst->getOperands()[1];
      TO_POINTER_GUARD(input1);
    }
  }

  void _preciseDeduceStage2(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];

    if (output->getValueType() == "Pointer") {
      input0->deduceType(ToPointerOfPointer());
      if (inst->getOperands().size() == 2) {
        auto input1 = inst->getOperands()[1];
        input1->deduceType(ToPointerOfPointer());
      }
    }
  }
};

struct Store : Operation {
  // STORE input0, input1
  // input0: should be a pointer
  // input1: cannot deduce the type

  // STORE input0, input1, input2
  // input0: should be a pointer
  // input1: should be an integer offset
  // input2: cannot deduce the type
  bool _sanityCheck(Instruction *inst) final {
    return (inst->getOp() == "STORE" && inst->getOperands().size() == 2) ||
           (inst->getOp() == "STORE" && inst->getOperands().size() == 3);
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    input0->deduceType(ToInt());

    if (inst->getOperands().size() == 3) {
      input1->deduceType(ToInt());
    }
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    TO_POINTER_GUARD(input0);

    if (inst->getOperands().size() == 3) {
      TO_POINTER_GUARD(input1);
    }
  }

  void _preciseDeduceStage2(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];

    if (inst->getOperands().size() == 3) {
      auto input2 = inst->getOperands()[2];
      if (input2->getValueType() == "Pointer") {
        input0->deduceType(ToPointerOfPointer());
        input1->deduceType(ToPointerOfPointer());
      }
    } else {
      if (input1->getValueType() == "Pointer") {
        input0->deduceType(ToPointerOfPointer());
      }
    }
  }
};

struct Branch : Operation {
  // BRANCH input0
  // input0: should be a pointer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "BRANCH" && inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    input0->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);
  }
};

struct CBranch : Operation {
  // CBRANCH input0, input1
  // input0: should be a pointer
  // input1: should be a boolean
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "CBRANCH" && inst->getOperands().size() == 2;
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];
    input0->deduceType(ToInt());
    input1->deduceType(ToBool());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);
  }
};

struct BranchIndirect : Operation {
  // BRANCHIND input0
  // input0: should be a pointer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "BRANCHIND" && inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    input0->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);
  }
};

struct Call : Operation {
  // CALL input0
  // input0: should be a pointer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "CALL" && inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    input0->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);
  }
};

struct CallIndirect : Operation {
  // CALLIND input0
  // input0: should be a pointer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "CALLIND" && inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    input0->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);
  }
};

struct Return : Operation {
  // RETURN input0
  // input0: cannot deduce the type
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "RETURN" && inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    input0->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(input0);
  }
};

struct Piece : Operation {
  // output = PIECE input0, input1
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "PIECE" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 2;
  }
};

struct SubPiece : Operation {
  // output = SUBPIECE input0, input1, input2
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "SUBPIECE" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 3;
  }
};

struct Int2Float : Operation {
  // output = INT2FLOAT input0
  // output: should be a float
  // input0: should be an integer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "INT2FLOAT" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    output->deduceType(ToFloat());
    input0->deduceType(ToInt());
  }
};

struct Float2Float : Operation {
  // output = FLOAT2FLOAT input0
  // output: should be a float
  // input0: should be a float
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "FLOAT2FLOAT" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct Trunc : Operation {
  // output = TRUNC input0
  // output: should be an integer
  // input0: should be a float
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "TRUNC" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 1;
  }

  void _roughDeduce(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    output->deduceType(ToInt());
    input0->deduceType(ToFloat());
  }
};

struct PtrAdd : Operation {
  // output = PTRADD input0, input1, input2
  // output: should be a pointer
  // input0: should be a pointer
  // input1: should be an integer
  // input2: should be an integer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "PTRADD" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 3;
  }

  void _roughDeduce(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];
    auto input2 = inst->getOperands()[2];
    output->deduceType(ToInt());
    input0->deduceType(ToInt());
    input1->deduceType(ToInt());
    input2->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(output);
    TO_POINTER_GUARD(input0);
  }
};

struct PtrSub : Operation {
  // output = PTRSUB input0, input1
  // output: should be a pointer
  // input0: should be a pointer
  // input1: should be an integer
  bool _sanityCheck(Instruction *inst) final {
    return inst->getOp() == "PTRSUB" && inst->getResult() != nullptr &&
           inst->getOperands().size() == 2;
  }

  void _roughDeduce(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    auto input1 = inst->getOperands()[1];
    output->deduceType(ToInt());
    input0->deduceType(ToInt());
    input1->deduceType(ToInt());
  }

  void _preciseDeduceStage1(Instruction *inst) final {
    auto output = inst->getResult();
    auto input0 = inst->getOperands()[0];
    TO_POINTER_GUARD(output);
    TO_POINTER_GUARD(input0);
  }
};

// TODO: Maybe support CAST, INDIRECT, MULTIEQUAL.

} // namespace pointer_solver
