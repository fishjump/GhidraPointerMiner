// Instruction.hpp
#pragma once

#include "_typ_dcl.hpp"

#include "Function.hpp"

#include <map>
#include <string>
#include <vector>

#include <boost/json.hpp>

namespace pointer_solver {

class Instruction {
  using OperandContainerType = std::vector<Value *>;
  using DefMapContainerType = std::map<Value *, std::vector<Instruction *>>;

  const boost::json::object meta_;

  std::string type_;
  size_t id_;
  std::string op_;

  Function *func_;
  BasicBlock *block_;

  std::vector<Instruction *> prev_;
  std::vector<Instruction *> next_;

  Value *result_;
  OperandContainerType operands_;

  DefMapContainerType defs_;

  bool is_built_;

public:
  Instruction(Function *func, const boost::json::object &json_obj);

  void build();

  const std::string &getType();
  size_t getId();
  const std::string &getOp();

  Function *getFunction();
  BasicBlock *getBlock();

  std::vector<Instruction *> getPreds();
  std::vector<Instruction *> getSuccs();

  OperandContainerType &getOperands();
  Value *getResult();

  DefMapContainerType &getDefs();

  operator std::string();
};
} // namespace pointer_solver
