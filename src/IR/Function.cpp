#include "Function.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

namespace {

void sanity_guard(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("name"), "expect 'name' field");
  BOOST_ASSERT_MSG(json_obj.contains("basic-blocks"),
                   "expect 'basic-blocks' field");
  BOOST_ASSERT_MSG(json_obj.contains("variables"), "expect 'variables' field");
  BOOST_ASSERT_MSG(json_obj.contains("instructions"),
                   "expect 'variables' field");

  auto type = json_obj.at("type");
  auto name = json_obj.at("name");
  auto blocks = json_obj.at("basic-blocks");
  auto variables = json_obj.at("variables");
  auto insts = json_obj.at("instructions");

  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(name.is_string(), "expect string for 'name' field");
  BOOST_ASSERT_MSG(blocks.is_array(), "expect array for 'basic-blocks' field");
  BOOST_ASSERT_MSG(variables.is_array(), "expect array for 'variables' field");
  BOOST_ASSERT_MSG(insts.is_array(), "expect array for 'instructions' field");

  BOOST_ASSERT_MSG(type.as_string() == "function",
                   "expect value 'function' in 'type' field");

  for (const auto &block : blocks.as_array()) {
    BOOST_ASSERT_MSG(block.is_object(),
                     "expect object for elements of array 'basic-blocks'");
  }

  for (const auto &var : variables.as_array()) {
    BOOST_ASSERT_MSG(var.is_string(),
                     "expect string for elements of array 'variables'");
  }

  for (const auto &inst : insts.as_array()) {
    BOOST_ASSERT_MSG(inst.is_object(),
                     "expect object for elements of array 'instructions'");
  }
}

} // namespace

Function::Function(const boost::json::object &json_obj) {
  sanity_guard(json_obj);

  name_ = json_obj.at("name").as_string();

  for (const auto &var : json_obj.at("variables").as_array()) {
    variables_.emplace(var.as_string());
  }

  for (const auto &inst : json_obj.at("instructions").as_array()) {
    insts_.emplace(Instruction::parseId(inst.as_object()),
                   Instruction(inst.as_object()));
  }

  for (const auto &block : json_obj.at("basic-blocks").as_array()) {
    blocks_.emplace(BasicBlock::parseId(block.as_object()),
                    BasicBlock(this, block.as_object()));
  }

  for (auto &[_, inst] : insts_) {
    inst.build(this);
  }

  for (auto &[_, block] : blocks_) {
    block.build();
  }
}

const std::string &Function::getName() { return name_; }

Function::BasicBlockContainerType::iterator Function::begin() {
  return blocks_.begin();
}

Function::BasicBlockContainerType::const_iterator Function::cbegin() const {
  return blocks_.cbegin();
}

Function::BasicBlockContainerType::iterator Function::end() {
  return blocks_.end();
}

Function::BasicBlockContainerType::const_iterator Function::cend() const {
  return blocks_.cend();
}

Function::BasicBlockContainerType::iterator
Function::find(const std::string &key) {
  return blocks_.find(key);
}

Function::BasicBlockContainerType::const_iterator
Function::find(const std::string &key) const {
  return blocks_.find(key);
}

Function::InstructionContainerType::iterator Function::inst_begin() {
  return insts_.begin();
}

Function::InstructionContainerType::const_iterator
Function::inst_cbegin() const {
  return insts_.cbegin();
}

Function::InstructionContainerType::iterator Function::inst_end() {
  return insts_.end();
}

Function::InstructionContainerType::const_iterator Function::inst_cend() const {
  return insts_.cend();
}

Function::InstructionContainerType::iterator Function::inst_find(size_t key) {
  return insts_.find(key);
}

Function::InstructionContainerType::const_iterator
Function::inst_find(size_t key) const {
  return insts_.find(key);
}
