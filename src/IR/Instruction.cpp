#include "Instruction.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

namespace {

void sanity_guard(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("id"), "expect 'id' field");
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("operation"), "expect 'operation' field");
  BOOST_ASSERT_MSG(json_obj.contains("operands"), "expect 'operands' field");

  auto id = json_obj.at("id");
  auto type = json_obj.at("type");
  auto op = json_obj.at("operation");
  auto operands = json_obj.at("operands");

  BOOST_ASSERT_MSG(type.is_uint64(), "expect uint64 for 'id' field");
  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(op.is_string(), "expect string for 'operation' field");
  BOOST_ASSERT_MSG(operands.is_array(), "expect array for 'operands' field");

  for (const auto &operand : operands.as_array()) {
    BOOST_ASSERT_MSG(operand.is_string(),
                     "expect string for elements of array 'operands'");
  }
}

} // namespace

Instruction::Instruction(const Function *func,
                         const boost::json::object &json_obj)
    : func_(func) {
  sanity_guard(json_obj);

  id_ = json_obj.at("id").as_uint64();
  op_ = json_obj.at("operation").as_string();

  for (const auto &operand : json_obj.at("operands").as_array()) {
    BOOST_ASSERT_MSG(operand.is_string(),
                     "expect string for elements of array 'operands'");

    operands_.emplace_back(operand.as_string());
  }
}

const Function *Instruction::getFunction() const { return func_; }

const size_t Instruction::getId() const { return id_; }

const std::string &Instruction::getType() const { return type_; }

const std::string &Instruction::getOp() const { return op_; }

const std::vector<std::string> &Instruction::getOperands() const {
  return operands_;
}
