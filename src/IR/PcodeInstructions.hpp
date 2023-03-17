#pragma once

#include "Value.hpp"

namespace pointer_solver {

inline void deduceTypeIntLogicGeneric(Value *output, Value *input0,
                                      Value *input1) {
  if (input0->getValueType() == "PointerOfPointer" ||
      input1->getValueType() == "PointerOfPointer") {
    input0->deduceType(ToPointerOfPointer());
    input1->deduceType(ToPointerOfPointer());
  } else if (input0->getValueType() == "Pointer" ||
             input1->getValueType() == "Pointer") {
    input0->deduceType(ToPointer());
    input1->deduceType(ToPointer());
  } else {
    input0->deduceType(ToInt());
    input1->deduceType(ToInt());
  }

  output->deduceType(ToBool());
}

inline void deduceTypeIntBinaryGeneric(Value *output, Value *input0,
                                       Value *input1) {
  if (output->getValueType() == "PointerOfPointer" ||
      input0->getValueType() == "PointerOfPointer" ||
      input1->getValueType() == "PointerOfPointer") {
    output->deduceType(ToPointerOfPointer());
    input0->deduceType(ToPointerOfPointer());
    input1->deduceType(ToPointerOfPointer());
  } else if (output->getValueType() == "Pointer" ||
             input0->getValueType() == "Pointer" ||
             input1->getValueType() == "Pointer") {
    output->deduceType(ToPointer());
    input0->deduceType(ToPointer());
    input1->deduceType(ToPointer());
  } else {
    output->deduceType(ToInt());
    input0->deduceType(ToInt());
    input1->deduceType(ToInt());
  }
}

inline void deduceTypeIntUnaryGeneric(Value *output, Value *input0) {
  if (output->getValueType() == "PointerOfPointer" ||
      input0->getValueType() == "PointerOfPointer") {
    output->deduceType(ToPointerOfPointer());
    input0->deduceType(ToPointerOfPointer());
  } else if (output->getValueType() == "Pointer" ||
             input0->getValueType() == "Pointer") {
    output->deduceType(ToPointer());
    input0->deduceType(ToPointer());
  } else {
    output->deduceType(ToInt());
    input0->deduceType(ToInt());
  }
}

struct Copy {
  // output = COPY input0
  // output: should be the same type as input0
  // input0: should be the same type as output
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToSome(input0->getValueType()));
    input0->deduceType(ToSome(output->getValueType()));
  }
};

struct Load {
  // output = LOAD input0
  // output: cannot deduce the type
  // input0: should be a pointer
  void deduceType(Value *output, Value *input0) {
    if (output->getValueType() == "Pointer") {
      input0->deduceType(ToPointerOfPointer());
    } else {
      input0->deduceType(ToPointer());
    }
  }

  // output = LOAD input0, input1
  // output: cannot deduce the type
  // input0: should be a pointer
  // input1: should be an integer offset
  void deduceType(Value *output, Value *input0, Value *input1) {
    if (output->getValueType() == "Pointer") {
      input0->deduceType(ToPointerOfPointer());
      input1->deduceType(ToPointerOfPointer());
    } else {
      input0->deduceType(ToPointer());
      input1->deduceType(ToPointer());
    }
  }
};

struct Store {
  // STORE input0, input1
  // input0: should be a pointer
  // input1: cannot deduce the type
  void deduceType(Value *input0, Value *input1) {
    if (input1->getValueType() == "Pointer") {
      input0->deduceType(ToPointerOfPointer());
    } else {
      input0->deduceType(ToPointer());
    }
  }

  // STORE input0, input1, input2
  // input0: should be a pointer
  // input1: should be an integer offset
  // input2: cannot deduce the type
  void deduceType(Value *input0, Value *input1, Value *input2) {
    if (input2->getValueType() == "Pointer") {
      input0->deduceType(ToPointerOfPointer());
      input1->deduceType(ToPointerOfPointer());
    } else {
      input0->deduceType(ToPointer());
      input1->deduceType(ToPointer());
    }
  }
};

struct Branch {

  // BRANCH input0
  // input0: should be a pointer
  void deduceType(Value *input0) {
    input0->deduceType(ToPointer());
  }
};

struct CBranch {

  // CBRANCH input0, input1
  // input0: should be a pointer
  // input1: should be a boolean
  void deduceType(Value *input0, Value *input1) {
    input0->deduceType(ToPointer());
    input1->deduceType(ToBool());
  }
};

struct BranchIndirect {

  // BRANCHIND input0
  // input0: should be a pointer
  void deduceType(Value *input0) {
    input0->deduceType(ToPointer());
  }
};

struct Call {

  // CALL input0
  // input0: should be a pointer
  void deduceType(Value *input0) {
    input0->deduceType(ToPointer());
  }
};

struct CallIndirect {

  // CALLIND input0
  // input0: should be a pointer
  void deduceType(Value *input0) {
    input0->deduceType(ToPointer());
  }
};

struct Return {

  // RETURN input0
  // input0: cannot deduce the type
  void deduceType(Value *input0) {
    input0->deduceType(ToPointer());
  }
};

struct Piece {
  // output = PIECE input0, input1
  void deduceType(Value *output, Value *input0, Value *input1) {
    // dummy
  }
};

struct SubPiece {
  // output = SUBPIECE input0, input1, input2
  void deduceType(Value *output, Value *input0, Value *input1, Value *input2) {
    // dummy
  }
};

struct IntEqual {
  // output = INT_EQUAL input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntNotEqual {
  // output = INT_NOTEQUAL input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntLess {
  // output = INT_LESS input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntSLess {
  // output = INT_SLESS input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntLessEqual {
  // output = INT_LESSEQUAL input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntSLessEqual {
  // output = INT_SLESSEQUAL input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntZExt {
  // output = INT_ZEXT input0
  // output: should be an integer
  // input0: should be an integer
  void deduceType(Value *output, Value *input0) {
    deduceTypeIntUnaryGeneric(output, input0);
  }
};

struct IntSExt {
  // output = INT_SEXT input0
  // output: should be an integer
  // input0: should be an integer
  void deduceType(Value *output, Value *input0) {
    deduceTypeIntUnaryGeneric(output, input0);
  }
};

struct IntAdd {
  // output = INT_ADD input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntSub {
  // output = INT_SUB input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntCarry {
  // output = INT_CARRY input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntSCarry {
  // output = INT_SCARRY input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct IntSBorrow {
  // output = INT_SBORROW input0, input1
  // output: should be a boolean
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntLogicGeneric(output, input0, input1);
  }
};

struct Int2Comp {
  // output = INT_2COMP input0
  // output: should be an integer
  // input0: should be an integer
  void deduceType(Value *output, Value *input0) {
    deduceTypeIntUnaryGeneric(output, input0);
  }
};

struct IntNegate {
  // output = INT_NEGATE input0
  // output: should be an integer
  // input0: should be an integer
  void deduceType(Value *output, Value *input0) {
    deduceTypeIntUnaryGeneric(output, input0);
  }
};

struct IntXor {
  // output = INT_XOR input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntAnd {
  // output = INT_AND input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntOr {
  // output = INT_OR input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntLeft {
  // output = INT_LEFT input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntRight {
  // output = INT_RIGHT input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntSRight {
  // output = INT_SRIGHT input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntMult {
  // output = INT_MULT input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntDiv {
  // output = INT_DIV input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntRem {
  // output = INT_REM input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntSDiv {
  // output = INT_SDIV input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct IntSRem {
  // output = INT_SREM input0, input1
  // output: should be an integer
  // input0: should be an integer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    deduceTypeIntBinaryGeneric(output, input0, input1);
  }
};

struct BoolNegate {
  // output = BOOL_NEGATE input0
  // output: should be a boolean
  // input0: should be a boolean
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToBool());
    input0->deduceType(ToBool());
  }
};

struct BoolXor {
  // output = BOOL_XOR input0, input1
  // output: should be a boolean
  // input0: should be a boolean
  // input1: should be a boolean
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToBool());
    input1->deduceType(ToBool());
  }
};

struct BoolAnd {
  // output = BOOL_AND input0, input1
  // output: should be a boolean
  // input0: should be a boolean
  // input1: should be a boolean
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToBool());
    input1->deduceType(ToBool());
  }
};

struct BoolOr {
  // output = BOOL_OR input0, input1
  // output: should be a boolean
  // input0: should be a boolean
  // input1: should be a boolean
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToBool());
    input1->deduceType(ToBool());
  }
};

struct FloatEqual {
  // output = FLOAT_EQUAL input0, input1
  // output: should be a boolean
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatNotEqual {
  // output = FLOAT_NOT_EQUAL input0, input1
  // output: should be a boolean
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatLess {
  // output = FLOAT_LESS input0, input1
  // output: should be a boolean
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatLessEqual {
  // output = FLOAT_LESS_EQUAL input0, input1
  // output: should be a boolean
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToBool());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatAdd {
  // output = FLOAT_ADD input0, input1
  // output: should be a float
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatSub {
  // output = FLOAT_SUB input0, input1
  // output: should be a float
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatMult {
  // output = FLOAT_MULT input0, input1
  // output: should be a float
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatDiv {
  // output = FLOAT_DIV input0, input1
  // output: should be a float
  // input0: should be a float
  // input1: should be a float
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
    input1->deduceType(ToFloat());
  }
};

struct FloatNeg {
  // output = FLOAT_NEG input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct FloatAbs {
  // output = FLOAT_ABS input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct FloatSqrt {
  // output = FLOAT_SQRT input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct FloatCeil {
  // output = FLOAT_CEIL input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct FloatFloor {
  // output = FLOAT_FLOOR input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct FloatRound {
  // output = FLOAT_ROUND input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct FloatNan {
  // output = FLOAT_NAN input0
  // output: should be a boolean
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToBool());
    input0->deduceType(ToFloat());
  }
};

struct Int2Float {
  // output = INT2FLOAT input0
  // output: should be a float
  // input0: should be an integer
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToInt());
  }
};

struct Float2Float {
  // output = FLOAT2FLOAT input0
  // output: should be a float
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToFloat());
    input0->deduceType(ToFloat());
  }
};

struct Trunc {
  // output = TRUNC input0
  // output: should be an integer
  // input0: should be a float
  void deduceType(Value *output, Value *input0) {
    output->deduceType(ToInt());
    input0->deduceType(ToFloat());
  }
};

struct PtrAdd {
  // output = PTRADD input0, input1, input2
  // output: should be a pointer
  // input0: should be a pointer
  // input1: should be an integer
  // input2: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1, Value *input2) {
    output->deduceType(ToPointer());
    input0->deduceType(ToPointer());
    input1->deduceType(ToInt());
    input2->deduceType(ToInt());
  }
};

struct PtrSub {

  // output = PTRSUB input0, input1
  // output: should be a pointer
  // input0: should be a pointer
  // input1: should be an integer
  void deduceType(Value *output, Value *input0, Value *input1) {
    output->deduceType(ToPointer());
    input0->deduceType(ToPointer());
    input1->deduceType(ToInt());
  }
};

// TODO: Maybe support CAST, INDIRECT, MULTIEQUAL.

} // namespace pointer_solver
