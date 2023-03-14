#include "TypeDeducer.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

std::string TypeDeducer::type() const {
  if (state_downcast<const Int *>()) {
    return "Int";
  } else if (state_downcast<const Bool *>()) {
    return "Bool";
  } else if (state_downcast<const Float *>()) {
    return "Float";
  } else if (state_downcast<const Pointer *>()) {
    return "Pointer";
  } else if (state_downcast<const Unknown *>()) {
    return "Unknown";
  }

  BOOST_ASSERT_MSG(false, "shouldn't reach here");
  return "Unknown";
}

void TypeDeducer::propagateTo(TypeDeducer *target) const {
  if (state_downcast<const Int *>()) {
    target->process_event(ToInt());
    return;
  } else if (state_downcast<const Bool *>()) {
    target->process_event(ToBool());
    return;
  } else if (state_downcast<const Float *>()) {
    target->process_event(ToFloat());
    return;
  } else if (state_downcast<const Pointer *>()) {
    target->process_event(ToPointer());
    return;
  }

  // Do nothing
  target->process_event(Idle());
}