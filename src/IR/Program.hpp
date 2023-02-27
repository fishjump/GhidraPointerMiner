#pragma once

#include <memory>
#include <vector>

#include <boost/json.hpp>

#include "_typ_dcl.hpp"

#include "Function.hpp"

namespace pointer_solver {

class Program {

  using FunctionContainerType = std::vector<const std::shared_ptr<Function>>;

  FunctionContainerType funcs_;

public:
  Program(const boost::json::object &json_obj);

  FunctionContainerType::iterator begin();
  FunctionContainerType::iterator end();
};

} // namespace pointer_solver
