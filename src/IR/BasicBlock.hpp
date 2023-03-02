#pragma once

#include "_typ_dcl.hpp"

#include "Function.hpp"
#include "Instruction.hpp"

#include <map>
#include <set>

#include <boost/json.hpp>

namespace pointer_solver {

class BasicBlock {
  using InstructionContainerType = std::map<size_t, Instruction *>;
  using BasicBlockContainerType = std::set<BasicBlock *>;

  const boost::json::object meta_;

  Function *func_;

  std::string id_;

  BasicBlockContainerType preds_;
  BasicBlockContainerType succs_;

  InstructionContainerType instructions_;

  bool is_built_;

public:
  static std::string parseId(const boost::json::object &json_obj);

  BasicBlock(Function *func, const boost::json::object &json_obj);

  void build();

  const std::string &getId() const;
  const Function *getFunction() const;

  InstructionContainerType::iterator begin();
  InstructionContainerType::iterator end();

  InstructionContainerType &getInsts();

  const Instruction *find(size_t id) const;

  BasicBlockContainerType &getPredecessors();
  BasicBlockContainerType &getSuccessors();

  bool operator==(const BasicBlock &rhs) const;
  bool operator==(const std::string &rhs) const;

  bool operator<(const BasicBlock &rhs) const;
  bool operator<(const std::string &rhs) const;
};

} // namespace pointer_solver
