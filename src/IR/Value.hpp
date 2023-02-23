#pragma once

#include <string>

#include <boost/json.hpp>

namespace pointer_solver {

class Value {
  std::string name_;

public:
  Value(const boost::json::string &name);

  const std::string &getName() const;
};

} // namespace pointer_solver
