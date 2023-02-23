#include "BasicBlock.hpp"

#include <boost/assert.hpp>

#include "Instruction.hpp"

using namespace pointer_solver;

BasicBlock::BasicBlock(const Function *func,
                       const boost::json::object &json_obj)
    : func_(func) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("id"), "expect 'id' field");
  BOOST_ASSERT_MSG(json_obj.contains("preds"), "expect 'preds' field");
  BOOST_ASSERT_MSG(json_obj.contains("succs"), "expect 'succs' field");
  BOOST_ASSERT_MSG(json_obj.contains("instructions"),
                   "expect 'instructions' field");

  auto type = json_obj.at("type");
  auto id = json_obj.at("id");
  auto preds = json_obj.at("preds");
  auto succs = json_obj.at("succs");
  auto instructions = json_obj.at("instructions");

  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(id.is_string(), "expect string for 'id' field");
  BOOST_ASSERT_MSG(preds.is_array(), "expect array for 'preds' field");
  BOOST_ASSERT_MSG(succs.is_array(), "expect array for 'succs' field");
  BOOST_ASSERT_MSG(instructions.is_array(),
                   "expect array for 'instructions' field");

  BOOST_ASSERT_MSG(type.as_string() == "basic-block",
                   "expect value 'basic-block' in 'type' field");

  id_ = id.as_string();

  for (const auto &pred : preds.as_array()) {
    BOOST_ASSERT_MSG(pred.is_string(),
                     "expect string for elements of array 'preds'");
    preds_.emplace(pred.as_string());
  }

  for (const auto &succ : succs.as_array()) {
    BOOST_ASSERT_MSG(succ.is_string(),
                     "expect string for elements of array 'succs'");
    succs_.emplace(succ.as_string());
  }

  for (const auto &inst : instructions.as_array()) {
    BOOST_ASSERT_MSG(inst.is_object(),
                     "expect object for elements of array 'instructions'");
    instructions_.emplace_back(
        std::make_shared<Instruction>(func_, inst.as_object()));
  }
}

const std::string &BasicBlock::getId() const { return id_; }

const Function *BasicBlock::getFunction() const { return func_; }

BasicBlock::InstructionContainerType::iterator BasicBlock::begin() {
  return instructions_.begin();
}
BasicBlock::InstructionContainerType::iterator BasicBlock::end() {
  return instructions_.end();
}

const std::set<std::string> &BasicBlock::getPredecessors() { return preds_; }
const std::set<std::string> &BasicBlock::getSuccessors() { return succs_; }
