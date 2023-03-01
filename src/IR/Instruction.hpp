// Instruction.hpp
#pragma once

#include "_typ_dcl.hpp"

#include "Function.hpp"

#include <string>
#include <vector>

#include <boost/json.hpp>

namespace pointer_solver {

class Instruction {
  const boost::json::object meta_;

  const Function *func_;
  const BasicBlock *block_;
  const Instruction *prev_;
  const Instruction *next_;

  size_t id_;
  std::string type_;
  std::string op_;
  std::vector<std::string> operands_;

  bool is_built_;

public:
  static size_t parseId(const boost::json::object &json_obj);

  Instruction(const boost::json::object &json_obj);

  void build(const Function *func);

  const Function *getFunction() const;
  const size_t getId() const;
  const std::string &getType() const;
  const std::string &getOp() const;
  const std::vector<std::string> &getOperands() const;
  const Instruction *getPrev() const;
  const Instruction *getNext() const;
};

} // namespace pointer_solver
