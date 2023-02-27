#pragma once

#include <set>
#include <vector>

#include <boost/json.hpp>

#include "_typ_dcl.hpp"

#include "Function.hpp"
#include "Instruction.hpp"

namespace pointer_solver {

class BasicBlock {

  using InstructionContainerType =
      std::vector<const std::shared_ptr<Instruction>>;

  const boost::json::object &meta_;

  const Function *func_;
  std::string id_;
  std::set<const BasicBlock *> preds_;
  std::set<const BasicBlock *> succs_;
  InstructionContainerType instructions_;

  bool isControlflowBuilt_;

public:
  static std::string parseId(const boost::json::object &json_obj);

  BasicBlock(const Function *func, const boost::json::object &json_obj);

  void buildControlflow();

  const std::string &getId() const;
  const Function *getFunction() const;

  InstructionContainerType::iterator begin();
  InstructionContainerType::iterator end();

  const std::set<const BasicBlock *> &getPredecessors();
  const std::set<const BasicBlock *> &getSuccessors();

  bool operator==(const BasicBlock &rhs) const;
  bool operator==(const std::string &rhs) const;

  bool operator<(const BasicBlock &rhs) const;
  bool operator<(const std::string &rhs) const;
};

} // namespace pointer_solver
