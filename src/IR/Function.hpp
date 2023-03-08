#pragma once

#include "_typ_dcl.hpp"

#include "BasicBlock.hpp"
#include "Value.hpp"

#include <map>
#include <memory>
#include <set>
#include <string>

#include <boost/json.hpp>

namespace pointer_solver {

class Function {
  using BasicBlockContainerType = std::map</* id: */ std::string, BasicBlock>;
  using InstructionContainerType = std::map</* id: */ size_t, Instruction>;
  using ValueContainerType = std::map</* id: */ std::string, Value>;

  std::string name_;
  BasicBlockContainerType blocks_;
  InstructionContainerType insts_;
  ValueContainerType variables_;

public:
  Function(const boost::json::object &json_obj);

  const std::string &getName();

  std::shared_ptr<std::map<Value *, std::vector<Instruction *>>> getUseDefChain(
      Instruction *inst, std::set<const Instruction *> visited,
      std::shared_ptr<std::map<Value *, std::vector<Instruction *>>> ud_chain);

  std::shared_ptr<std::map<Value *, std::vector<Instruction *>>>
  getUseDefChain(Instruction *inst);

  void deduceType(Instruction *inst);

  BasicBlockContainerType::iterator begin();
  BasicBlockContainerType::const_iterator cbegin() const;

  BasicBlockContainerType::iterator end();
  BasicBlockContainerType::const_iterator cend() const;

  BasicBlockContainerType::iterator find(const std::string &key);
  BasicBlockContainerType::const_iterator find(const std::string &key) const;

  InstructionContainerType::iterator inst_begin();
  InstructionContainerType::const_iterator inst_cbegin() const;

  InstructionContainerType::iterator inst_end();
  InstructionContainerType::const_iterator inst_cend() const;

  InstructionContainerType::iterator inst_find(size_t key);
  InstructionContainerType::const_iterator inst_find(size_t key) const;

  ValueContainerType::iterator var_begin();
  ValueContainerType::const_iterator var_cbegin() const;

  ValueContainerType::iterator var_end();
  ValueContainerType::const_iterator var_cend() const;

  ValueContainerType::iterator var_find(const std::string &key);
  ValueContainerType::const_iterator var_find(const std::string &key) const;

  ValueContainerType::iterator var_find(const boost::json::string &key);
  ValueContainerType::const_iterator
  var_find(const boost::json::string &key) const;
};

} // namespace pointer_solver
