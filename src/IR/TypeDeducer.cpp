#include "TypeDeducer.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

std::string TypeDeducer::type() const {
  if (state_cast<const Int *>()) {
    return "Int";
  } else if (state_cast<const Bool *>()) {
    return "Bool";
  } else if (state_cast<const Float *>()) {
    return "Float";
  } else if (state_cast<const Pointer *>()) {
    return "Pointer";
  } else if (state_cast<const PointerOfPointer *>()) {
    return "PointerOfPointer";
  } else if (state_cast<const Unknown *>()) {
    return "Unknown";
  }

  BOOST_ASSERT_MSG(false, "shouldn't reach here");
  return "Unknown";
}
