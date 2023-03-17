#pragma once

#include <boost/mpl/list.hpp>
#include <boost/statechart/state.hpp>
#include <boost/statechart/state_machine.hpp>
#include <boost/statechart/transition.hpp>

namespace pointer_solver {

struct Int;
struct Bool;
struct Float;
struct Pointer;
struct PointerOfPointer;
struct Unknown;

// The initial state
struct TypeDeducer : boost::statechart::state_machine<TypeDeducer, Unknown> {
  std::string type() const;
  void propagateTo(TypeDeducer *target) const;
};

// Events
struct ToInt : boost::statechart::event<ToInt> {};
struct ToBool : boost::statechart::event<ToBool> {};
struct ToFloat : boost::statechart::event<ToFloat> {};
struct ToPointer : boost::statechart::event<ToPointer> {};
struct ToPointerOfPointer : boost::statechart::event<ToPointerOfPointer> {};
struct Idle : boost::statechart::event<Idle> {};

inline const boost::statechart::event_base &&ToSome(const std::string &type) {
  if (type == "Int") {
    return std::move(ToInt());
  } else if (type == "Bool") {
    return std::move(ToBool());
  } else if (type == "Float") {
    return std::move(ToFloat());
  } else if (type == "Pointer") {
    return std::move(ToPointer());
  }

  return std::move(Idle());
}

// States
struct Int : boost::statechart::simple_state<Int, TypeDeducer> {
  typedef boost::mpl::list<
      boost::statechart::transition<ToPointer, Pointer>,
      boost::statechart::transition<ToPointerOfPointer, PointerOfPointer>>
      reactions;
};

struct Bool : boost::statechart::simple_state<Bool, TypeDeducer> {
  // no reactions
};

struct Float : boost::statechart::simple_state<Float, TypeDeducer> {
  typedef boost::statechart::transition<ToInt, Int> reactions;
};

struct Pointer : boost::statechart::simple_state<Pointer, TypeDeducer> {
  typedef boost::statechart::transition<ToPointerOfPointer, PointerOfPointer>
      reactions;
};

struct PointerOfPointer
    : boost::statechart::simple_state<PointerOfPointer, TypeDeducer> {
  // no reactions
};

struct Unknown : boost::statechart::simple_state<Unknown, TypeDeducer> {
  typedef boost::mpl::list<
      boost::statechart::transition<ToInt, Int>,
      boost::statechart::transition<ToBool, Bool>,
      boost::statechart::transition<ToFloat, Float>,
      boost::statechart::transition<ToPointer, Pointer>,
      boost::statechart::transition<ToPointerOfPointer, PointerOfPointer>>
      reactions;
};

} // namespace pointer_solver