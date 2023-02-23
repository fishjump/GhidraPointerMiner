#include "Function.hpp"

#include <boost/assert.hpp>

#include "BasicBlock.hpp"
#include "Value.hpp"

using namespace pointer_solver;

Function::Function(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("name"), "expect 'name' field");
  BOOST_ASSERT_MSG(json_obj.contains("basic-blocks"),
                   "expect 'basic-blocks' field");
  BOOST_ASSERT_MSG(json_obj.contains("variables"), "expect 'variables' field");

  auto type = json_obj.at("type");
  auto name = json_obj.at("name");
  auto blocks = json_obj.at("basic-blocks");
  auto variables = json_obj.at("variables");

  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(name.is_string(), "expect string for 'name' field");
  BOOST_ASSERT_MSG(blocks.is_array(), "expect array for 'basic-blocks' field");
  BOOST_ASSERT_MSG(variables.is_array(), "expect array for 'variables' field");

  BOOST_ASSERT_MSG(type.as_string() == "function",
                   "expect value 'function' in 'type' field");

  name_ = name.as_string();

  for (const auto &block : blocks.as_array()) {
    BOOST_ASSERT_MSG(block.is_object(),
                     "expect object for elements of array 'basic-blocks'");

    blocks_.emplace_back(std::make_shared<BasicBlock>(this, block.as_object()));
  }

  for (const auto &var : variables.as_array()) {
    BOOST_ASSERT_MSG(var.is_string(),
                     "expect string for elements of array 'variables'");

    variables_.emplace(std::make_shared<Value>(var.as_string()));
  }
}

const std::string &Function::getName() { return name_; }

Function::BasicBlockContainerType::iterator Function::begin() {
  return blocks_.begin();
}

Function::BasicBlockContainerType::iterator Function::end() {
  return blocks_.end();
}
