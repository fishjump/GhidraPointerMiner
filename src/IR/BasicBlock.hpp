#pragma once

#include "Instruction.hpp"
#include <boost/assert.hpp>
#include <boost/json.hpp>
#include <set>
#include <vector>

namespace pointer_solver {

class BasicBlock {

  using InstructionContainerType =
      std::vector<const std::shared_ptr<Instruction>>;

  std::string id_;
  std::set<std::string> preds_;
  std::set<std::string> succs_;
  InstructionContainerType instructions_;

public:
  BasicBlock(const boost::json::object &json_obj) {
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

    BOOST_ASSERT_MSG(type.as_string() == "basic-blocks",
                     "expect value 'basic-blocks' in 'type' field");

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
          std::make_shared<Instruction>(inst.as_object()));
    }
  }

  const std::string &getId() { return id_; }

  InstructionContainerType::iterator begin() { return instructions_.begin(); }
  InstructionContainerType::iterator end() { return instructions_.end(); }

  const std::set<std::string> &getPredecessors() { return preds_; }
  const std::set<std::string> &getSuccessors() { return succs_; }
};

} // namespace pointer_solver
