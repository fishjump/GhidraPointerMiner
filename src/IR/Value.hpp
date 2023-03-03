#pragma once

#include "_typ_dcl.hpp"

#include <memory>
#include <string>

#include <boost/json.hpp>

namespace pointer_solver {

enum ValueStorageType { CONST, RAM, REGISTER, STACK, UNIQUE };
enum ValueType { INT, FLOAT, POINTER, BOOL, UNKNOWN };

class Value {
  const std::string meta_;
  // TODO: implement string to ValueType conversion
  // ValueType type_;
  std::string type_;
  size_t id_;
  size_t size_;

  ValueType value_type_;

public:
  Value(const std::string &meta);
  Value(const boost::json::string &meta);

  const std::string &getType() const;
  size_t getId() const;
  size_t getSize() const;

  bool operator==(const Value &rhs) const;
  bool operator<(const Value &rhs) const;

  operator std::string() const;
};

} // namespace pointer_solver
