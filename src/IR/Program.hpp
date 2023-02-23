#pragma once

#include "Function.hpp"
#include <boost/assert.hpp>
#include <boost/json.hpp>
#include <memory>

namespace pointer_solver {

class Program {

  using FunctionContainerType = std::vector<const std::shared_ptr<Function>>;

  FunctionContainerType funcs_;

public:
  Program(const boost::json::object &json_obj) {
    BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
    BOOST_ASSERT_MSG(json_obj.contains("functions"),
                     "expect 'functions' field");

    auto type = json_obj.at("type");
    auto funcs = json_obj.at("functions");

    BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
    BOOST_ASSERT_MSG(funcs.is_array(), "expect array for 'functions' field");

    BOOST_ASSERT_MSG(type.as_string() == "program",
                     "expect value 'program' in 'type' field");

    for (const auto &func : funcs.as_array()) {
      BOOST_ASSERT_MSG(func.is_object(),
                       "expect an object for elements of array 'functions'");

      funcs_.emplace_back(std::make_shared<Function>(func.as_object()));
    }
  }

  FunctionContainerType::iterator begin() { return funcs_.begin(); }
  FunctionContainerType::iterator end() { return funcs_.end(); }
};

} // namespace pointer_solver
