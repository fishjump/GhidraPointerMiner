#pragma once

#include "_typ_dcl.hpp"

#include "Function.hpp"

#include <memory>
#include <vector>

#include <boost/json.hpp>

namespace pointer_solver {

class Program {
  using FunctionContainerType = std::vector<std::shared_ptr<Function>>;

  FunctionContainerType funcs_;

public:
  Program(const boost::json::object &json_obj);

  FunctionContainerType::iterator begin();
  FunctionContainerType::iterator end();
};

} // namespace pointer_solver
