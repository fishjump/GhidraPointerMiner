#include "Value.hpp"

#include <sstream>

#include <boost/assert.hpp>
#include <boost/regex.hpp>

using namespace pointer_solver;

namespace {
constexpr char RE_STR[] =
    R"(\( *?(.*?) *?, *?(0[xX][0-9a-fA-F]+|[0-9]+) *?, *?(0[xX][0-9a-fA-F]+|[0-9]+) *?\))";
const boost::regex pattern(RE_STR);

size_t toU64(const std::string &str) {
  bool isHex =
      str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X');
  std::istringstream ss(str);

  size_t value = 0;
  ss >> (isHex ? std::hex : std::dec) >> value;
  return value;
}

auto parse(const std::string &name) {
  boost::smatch match;

  BOOST_ASSERT_MSG(boost::regex_search(name, match, pattern),
                   "malformed value string");

  BOOST_ASSERT_MSG(match.size() == 4,
                   "expect 4 (1 + 3 sub) matched group: type, id, size");

  // TODO: Use TypeValue instead of string
  struct {
    std::string type;
    size_t id;
    size_t size;
  } res;

  res.type = match[1];
  res.id = toU64(match[2]);
  res.size = toU64(match[3]);

  return res;
}

} // namespace

Value::Value(const boost::json::string &name) : name_(name) {
  auto [type, id, size] = parse(name_);
  type_ = type;
  id_ = id;
  size_ = size;
}

const std::string &Value::getName() const { return name_; }

// TODO: impl users and uses
const std::vector<const Instruction *> Value::users() const { return {}; };

const std::vector<const Value *> Value::uses() const { return {}; };

bool Value::operator==(const Value &rhs) const {
  return type_ == rhs.type_ && id_ == rhs.id_;
}

bool Value::operator<(const Value &rhs) const {
  return this->type_ < rhs.type_ && this->id_ < rhs.id_;
}