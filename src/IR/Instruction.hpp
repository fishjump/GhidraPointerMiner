// Instruction.hpp
#pragma once

#include <string>
#include <vector>

#include <boost/json.hpp>

#include "_typ_dcl.hpp"

#include "Function.hpp"

namespace pointer_solver {

class Instruction {

  const Function *func_;

  size_t id_;
  std::string type_;
  std::string op_;
  std::vector<std::string> operands_;

public:
  Instruction(const Function *func, const boost::json::object &json_obj);

  const Function *getFunction() const;
  const size_t getId() const;
  const std::string &getType() const;
  const std::string &getOp() const;
  const std::vector<std::string> &getOperands() const;
};

} // namespace pointer_solver
