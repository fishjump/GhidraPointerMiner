#pragma once

#include <map>
#include <set>
#include <string>

#include <boost/json.hpp>

#include "_typ_dcl.hpp"

#include "BasicBlock.hpp"
#include "Value.hpp"

namespace pointer_solver {

class Function {

  using BasicBlockContainerType = std::map<std::string, BasicBlock>;
  using ValueContainerType = std::set<Value>;

  std::string name_;
  BasicBlockContainerType blocks_;
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
};

} // namespace pointer_solver
