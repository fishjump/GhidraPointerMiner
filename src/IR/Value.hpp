#pragma once

#include "_typ_dcl.hpp"

#include "TypeDeducer.hpp"

#include <map>
#include <memory>
#include <string>

#include <boost/json.hpp>

namespace pointer_solver {

class Value {
  const std::string meta_;

  std::string type_;
  size_t id_;
  size_t size_;

  std::map<Instruction *, std::vector<Instruction *>> defs_;

  TypeDeducer value_type_;

public:
  Value(const std::string &meta);
  Value(const boost::json::string &meta);

  const std::string &getType() const;
  size_t getId() const;
  size_t getSize() const;

  void propagateTo(Value *value);
  void deduceType(const boost::statechart::event_base &event);
  std::string getValueType() const;

  void addDef(Instruction *user, Instruction *def);
  const std::map<Instruction *, std::vector<Instruction *>> &getDefs();

  bool operator==(const Value &rhs) const;
  bool operator<(const Value &rhs) const;

  operator std::string() const;
};

} // namespace pointer_solver
