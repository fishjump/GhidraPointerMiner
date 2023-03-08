#pragma once

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
struct TypeDeducer : boost::statechart::state_machine<TypeDeducer, Unknown> {};

// Events
struct ToInt : boost::statechart::event<ToInt> {};
struct ToBool : boost::statechart::event<ToBool> {};
struct ToFloat : boost::statechart::event<ToFloat> {};
struct ToPointer : boost::statechart::event<ToPointer> {};

// States
struct Int : boost::statechart::state<Int, TypeDeducer> {
  typedef boost::statechart::transition<ToPointer, Pointer> reactions;
};

struct Bool : boost::statechart::state<Bool, TypeDeducer> {
  // no reactions, bool can only be deduced to bool
};

struct Float : boost::statechart::state<Float, TypeDeducer> {
  typedef boost::statechart::transition<ToInt, Int> reactions;
};

struct Pointer : boost::statechart::state<Pointer, TypeDeducer> {
  // no reactions, pointer can only be deduced to pointer
};

struct Unknown : boost::statechart::state<Unknown, TypeDeducer> {
  typedef boost::mpl::list<boost::statechart::transition<ToInt, Int>,
                           boost::statechart::transition<ToBool, Bool>,
                           boost::statechart::transition<ToFloat, Float>,
                           boost::statechart::transition<ToPointer, Pointer>>
      reactions;
};

} // namespace pointer_solver