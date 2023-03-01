#pragma once

#include "_typ_dcl.hpp"

#include <string>

#include <boost/json.hpp>

namespace pointer_solver {

enum ValueType { CONST, RAM, REGISTER, STACK, UNIQUE };

class Value {
  std::string name_;
  // TODO: implement string to ValueType conversion
  // ValueType type_;
  std::string type_;
  size_t id_;
  size_t size_;

public:
  Value(const boost::json::string &name);

  const std::string &getName() const;
  const std::vector<const Instruction *> users() const;
  const std::vector<const Value *> uses() const;

  bool operator==(const Value &rhs) const;
  bool operator<(const Value &rhs) const;
};

} // namespace pointer_solver
