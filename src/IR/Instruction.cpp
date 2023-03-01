#include "Instruction.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

namespace {

void sanity_guard(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("id"), "expect 'id' field");
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("parent"), "expect 'parent' field");
  BOOST_ASSERT_MSG(json_obj.contains("operation"), "expect 'operation' field");
  BOOST_ASSERT_MSG(json_obj.contains("operands"), "expect 'operands' field");

  auto id = json_obj.at("id");
  auto type = json_obj.at("type");
  auto parent = json_obj.at("parent");
  auto op = json_obj.at("operation");
  auto operands = json_obj.at("operands");

  BOOST_ASSERT_MSG(id.is_int64(), "expect int64 for 'id' field");
  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(parent.is_string(), "expect string for 'parent' field");
  BOOST_ASSERT_MSG(op.is_string(), "expect string for 'operation' field");
  BOOST_ASSERT_MSG(operands.is_array(), "expect array for 'operands' field");

  for (const auto &operand : operands.as_array()) {
    BOOST_ASSERT_MSG(operand.is_string(),
                     "expect string for elements of array 'operands'");
  }
}

} // namespace

size_t Instruction::parseId(const boost::json::object &json_obj) {
  sanity_guard(json_obj);

  return json_obj.at("id").as_int64();
}

Instruction::Instruction(const Function *func,
                         const boost::json::object &json_obj)
    : meta_(json_obj), func_(func), is_built_(false) {
  sanity_guard(meta_);

  id_ = meta_.at("id").is_int64();
  op_ = meta_.at("operation").as_string();
}

void Instruction::build() {
  if (is_built_) {
    return;
  }

  auto b_it = func_->find(std::string(meta_.at("parent").as_string()));
  BOOST_ASSERT_MSG(b_it != func_->cend(),
                   "reference a basicblock which does not exist");
  block_ = &b_it->second;

  auto prev_it = func_->inst_find(id_ - 1);
  prev_ = prev_it == func_->inst_cend() ? nullptr : &prev_it->second;

  auto next_it = func_->inst_find(id_ + 1);
  next_ = next_it == func_->inst_cend() ? nullptr : &next_it->second;

  for (const auto &operand : meta_.at("operands").as_array()) {
    auto it = func_->var_find(operand.as_string());
    BOOST_ASSERT_MSG(it != func_->var_cend(),
                     "reference a variable which does not exist");
    operands_.emplace_back(&*it);
  }

  is_built_ = true;
}

const Function *Instruction::getFunction() const { return func_; }

const size_t Instruction::getId() const { return id_; }

const std::string &Instruction::getType() const { return type_; }

const std::string &Instruction::getOp() const { return op_; }

const std::vector<const Value *> &Instruction::getOperands() const {
  return operands_;
}

const Instruction *Instruction::getPrev() const { return prev_; }

const Instruction *Instruction::getNext() const { return next_; }
