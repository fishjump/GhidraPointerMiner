#include "Instruction.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

Instruction::Instruction(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("operation"), "expect 'operation' field");
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

const std::string &Instruction::getType() const { return type_; }
const std::string &Instruction::getOp() const { return op_; }
const std::vector<std::string> &Instruction::getOperands() const {
  return operands_;
}
