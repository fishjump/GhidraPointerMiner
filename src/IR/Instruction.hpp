// Instruction.hpp
#pragma once

#include <boost/assert.hpp>
#include <boost/json.hpp>
#include <string>
#include <vector>

namespace pointer_solver {

class Instruction {

  std::string type_;
  std::string op_;
  std::vector<std::string> operands_;

public:
  Instruction(const boost::json::object &json_obj) {
    BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
    BOOST_ASSERT_MSG(json_obj.contains("operation"),
                     "expect 'operation' field");
    BOOST_ASSERT_MSG(json_obj.contains("operands"), "expect 'operands' field");

    auto type = json_obj.at("type");
    auto op = json_obj.at("operation");
    auto operands = json_obj.at("operands");

    BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
    BOOST_ASSERT_MSG(op.is_string(), "expect string for 'operation' field");
    BOOST_ASSERT_MSG(operands.is_array(), "expect array for 'operands' field");

    type_ = type.as_string();
    op_ = op.as_string();

    for (const auto &operand : operands.as_array()) {
      BOOST_ASSERT_MSG(operand.is_string(),
                       "expect string for elements of array 'operands'");

      operands_.emplace_back(operand.as_string());
    }
  }

  const std::string &getType() const { return type_; }
  const std::string &getOp() const { return op_; }
  const std::vector<std::string> &getOperands() const { return operands_; }
};

} // namespace pointer_solver
