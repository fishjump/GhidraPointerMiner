// Instruction.hpp
#pragma once

#include <string>
#include <vector>

#include <boost/json.hpp>

namespace pointer_solver {

class Instruction {

  std::string type_;
  std::string op_;
  std::vector<std::string> operands_;

public:
  Instruction(const boost::json::object &json_obj);

  const std::string &getType() const;
  const std::string &getOp() const;
  const std::vector<std::string> &getOperands() const;
};

} // namespace pointer_solver
