#pragma once

#include "_typ_dcl.hpp"

#include "Function.hpp"
#include "Instruction.hpp"

#include <map>
#include <set>

#include <boost/json.hpp>

namespace pointer_solver {

class BasicBlock {
  using InstructionContainerType = std::map<size_t, const Instruction *>;
  using BasicBlockContainerType = std::set<const BasicBlock *>;

  const boost::json::object meta_;

  std::string id_;

  const Function *func_;
  BasicBlockContainerType preds_;
  BasicBlockContainerType succs_;

  InstructionContainerType instructions_;

  bool is_built_;

public:
  static std::string parseId(const boost::json::object &json_obj);

  BasicBlock(const Function *func, const boost::json::object &json_obj);

  void build();

  const std::string &getId() const;
  const Function *getFunction() const;

  InstructionContainerType::iterator begin();
  InstructionContainerType::iterator end();
  const Instruction *find(size_t id) const;

  const BasicBlockContainerType &getPredecessors();
  const BasicBlockContainerType &getSuccessors();

  bool operator==(const BasicBlock &rhs) const;
  bool operator==(const std::string &rhs) const;

  bool operator<(const BasicBlock &rhs) const;
  bool operator<(const std::string &rhs) const;
};

} // namespace pointer_solver
