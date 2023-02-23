#pragma once

#include <set>
#include <vector>

#include <boost/json.hpp>

#include "_typ_dcl.hpp"

namespace pointer_solver {

class Function {

  using BasicBlockContainerType =
      std::vector<const std::shared_ptr<BasicBlock>>;
  using ValueContainerType = std::set<const std::shared_ptr<Value>>;

  std::string name_;
  BasicBlockContainerType blocks_;
  ValueContainerType variables_;

public:
  Function(const boost::json::object &json_obj);

  const std::string &getName();
  BasicBlockContainerType::iterator begin();
  BasicBlockContainerType::iterator end();
};

} // namespace pointer_solver
