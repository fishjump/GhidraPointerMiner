#include "Program.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

Program::Program(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("functions"), "expect 'functions' field");

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

Program::FunctionContainerType::iterator Program::begin() {
  return funcs_.begin();
}

Program::FunctionContainerType::iterator Program::end() { return funcs_.end(); }
