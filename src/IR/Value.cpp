#include "Value.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

Value::Value(const boost::json::string &name) : name_(name) {
  BOOST_ASSERT_MSG(!name.empty(), "name cannot be empty");
}

const std::string &Value::getName() const { return name_; }
