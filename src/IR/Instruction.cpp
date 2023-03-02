#include "Instruction.hpp"

#include <boost/assert.hpp>
#include <boost/log/trivial.hpp>

using namespace pointer_solver;

namespace {

void sanity_guard(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("id"), "expect 'id' field");
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("parent"), "expect 'parent' field");
  BOOST_ASSERT_MSG(json_obj.contains("operation"), "expect 'operation' field");
  BOOST_ASSERT_MSG(json_obj.contains("operands"), "expect 'operands' field");
  BOOST_ASSERT_MSG(json_obj.contains("preds"), "expect 'preds' field");
  BOOST_ASSERT_MSG(json_obj.contains("succs"), "expect 'succs' field");

  auto id = json_obj.at("id");
  auto type = json_obj.at("type");
  auto parent = json_obj.at("parent");
  auto op = json_obj.at("operation");
  auto operands = json_obj.at("operands");
  auto preds = json_obj.at("preds");
  auto succs = json_obj.at("succs");

  BOOST_ASSERT_MSG(id.is_int64(), "expect int64 for 'id' field");
  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(parent.is_string(), "expect string for 'parent' field");
  BOOST_ASSERT_MSG(op.is_string(), "expect string for 'operation' field");
  BOOST_ASSERT_MSG(operands.is_array(), "expect array for 'operands' field");
  BOOST_ASSERT_MSG(preds.is_array(), "expect array for 'preds' field");
  BOOST_ASSERT_MSG(succs.is_array(), "expect array for 'succs' field");

  BOOST_ASSERT_MSG(type.as_string() == "instruction",
                   "expect value 'instruction' in 'type' field");

  for (const auto &operand : operands.as_array()) {
    BOOST_ASSERT_MSG(operand.is_string(),
                     "expect string for elements of array 'operands'");
  }

  for (const auto &pred : preds.as_array()) {
    BOOST_ASSERT_MSG(pred.is_int64(),
                     "expect int64 for elements of array 'preds'");
  }

  for (const auto &succ : succs.as_array()) {
    BOOST_ASSERT_MSG(succ.is_int64(),
                     "expect int64 for elements of array 'succs'");
  }
}

} // namespace

Instruction::Instruction(Function *func, const boost::json::object &json_obj)
    : meta_(json_obj), is_built_(false) {
  sanity_guard(meta_);

  type_ = meta_.at("type").as_string();
  id_ = meta_.at("id").as_int64();
  op_ = meta_.at("operation").as_string();

  func_ = func;
}

void Instruction::build() {
  if (is_built_) {
    return;
  }

  auto b_it = func_->find(std::string(meta_.at("parent").as_string()));
  BOOST_ASSERT_MSG(b_it != func_->end(),
                   "reference a basicblock which does not exist");
  block_ = &b_it->second;

  for (const auto &pred : meta_.at("preds").as_array()) {
    auto it = func_->inst_find(pred.as_int64());
    BOOST_ASSERT_MSG(it != func_->inst_end(),
                     "reference a instruction which does not exist");
    prev_.emplace_back(&it->second);
  }

  for (const auto &succ : meta_.at("succs").as_array()) {
    auto it = func_->inst_find(succ.as_int64());
    BOOST_ASSERT_MSG(it != func_->inst_end(),
                     "reference a instruction which does not exist");
    next_.emplace_back(&it->second);
  }

  for (const auto &operand : meta_.at("operands").as_array()) {
    auto it = func_->var_find(operand.as_string());
    BOOST_ASSERT_MSG(it != func_->var_end(),
                     "reference a variable which does not exist");
    operands_.emplace_back(&*it);
  }

  if (!meta_.contains("result")) {
    is_built_ = true;
    result_ = nullptr;
    return;
  }

  if (meta_.at("result").is_null()) {
    is_built_ = true;
    result_ = nullptr;
    return;
  }

  auto res_it = func_->var_find(meta_.at("result").as_string());
  result_ = res_it == func_->var_end() ? nullptr : &*res_it;

  is_built_ = true;
}

const std::string &Instruction::getType() { return type_; }
size_t Instruction::getId() { return id_; }
const std::string &Instruction::getOp() { return op_; }

Function *Instruction::getFunction() { return func_; }
BasicBlock *Instruction::getBlock() { return block_; }

std::vector<Instruction *> Instruction::getPrev() { return prev_; }
std::vector<Instruction *> Instruction::getNext() { return next_; }

Instruction::OperandContainerType &Instruction::getOperands() {
  return operands_;
}
const Value *Instruction::getResult() { return result_; }

Instruction::DefMapContainerType &Instruction::getDefs() { return defs_; }
