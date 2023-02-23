#pragma once

#include <set>
#include <vector>

#include <boost/json.hpp>

#include "_typ_dcl.hpp"

namespace pointer_solver {

class BasicBlock {

  using InstructionContainerType =
      std::vector<const std::shared_ptr<Instruction>>;

  const Function *func_;
  std::string id_;
  std::set<std::string> preds_;
  std::set<std::string> succs_;
  InstructionContainerType instructions_;

public:
  BasicBlock(const Function *func, const boost::json::object &json_obj);

  const std::string &getId() const;
  const Function *getFunction() const;

  InstructionContainerType::iterator begin();
  InstructionContainerType::iterator end();

  const std::set<std::string> &getPredecessors();
  const std::set<std::string> &getSuccessors();
};

} // namespace pointer_solver
