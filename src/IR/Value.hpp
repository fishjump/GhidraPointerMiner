#pragma once

#include <boost/assert.hpp>
#include <boost/json.hpp>
#include <string>

namespace pointer_solver {

class Value {
  std::string name_;

public:
  Value(const boost::json::string &name) : name_(name) {
    BOOST_ASSERT_MSG(!name.empty(), "name cannot be empty");
  }

  const std::string &getName() const { return name_; }
};

} // namespace pointer_solver
