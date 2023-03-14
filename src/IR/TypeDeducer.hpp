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
struct Idle : boost::statechart::event<Idle> {};

// States
struct Int : boost::statechart::simple_state<Int, TypeDeducer> {
  typedef boost::statechart::transition<ToPointer, Pointer> reactions;
};

struct Bool : boost::statechart::simple_state<Bool, TypeDeducer> {
  // no reactions, bool can only be deduced to bool
};

struct Float : boost::statechart::simple_state<Float, TypeDeducer> {
  typedef boost::statechart::transition<ToInt, Int> reactions;
};

struct Pointer : boost::statechart::simple_state<Pointer, TypeDeducer> {
  // no reactions, pointer can only be deduced to pointer
};

struct Unknown : boost::statechart::simple_state<Unknown, TypeDeducer> {
  typedef boost::mpl::list<boost::statechart::transition<ToInt, Int>,
                           boost::statechart::transition<ToBool, Bool>,
                           boost::statechart::transition<ToFloat, Float>,
                           boost::statechart::transition<ToPointer, Pointer>>
      reactions;
};

} // namespace pointer_solver