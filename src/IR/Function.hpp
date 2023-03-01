#pragma once

#include "_typ_dcl.hpp"

#include "BasicBlock.hpp"
#include "Value.hpp"

#include <map>
#include <set>
#include <string>

#include <boost/json.hpp>

namespace pointer_solver {

class Function {
  using BasicBlockContainerType = std::map</* id: */ std::string, BasicBlock>;
  using InstructionContainerType = std::map</* id: */ size_t, Instruction>;
  using ValueContainerType = std::set<Value>;

  std::string name_;
  BasicBlockContainerType blocks_;
  InstructionContainerType insts_;
  ValueContainerType variables_;

public:
  Function(const boost::json::object &json_obj);

  const std::string &getName();

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
};

} // namespace pointer_solver
