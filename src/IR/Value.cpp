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

Value::Value(const std::string &meta)
    : meta_(meta), value_type_(), is_final_(false) {
  const auto [type, id, size] = parse(meta_);
  type_ = type;
  id_ = id;
  size_ = size;

  value_type_.initiate();
}

Value::Value(const boost::json::string &meta) : Value(std::string(meta)) {
}

const std::string &Value::getType() const {
  return type_;
}

size_t Value::getId() const {
  return id_;
}

size_t Value::getSize() const {
  return size_;
}

bool Value::operator==(const Value &rhs) const {
  return type_ == rhs.type_ && id_ == rhs.id_;
}

bool Value::operator<(const Value &rhs) const {
  return this->type_ < rhs.type_ && this->id_ < rhs.id_;
}

Value::operator std::string() const {
  return meta_ + (is_final_ ? " (final)" : "");
}

void Value::addDef(Instruction *user, Instruction *def) {
  BOOST_ASSERT_MSG(user != nullptr, "user cannot be nullptr");
  BOOST_ASSERT_MSG(def != nullptr, "def cannot be nullptr");

  defs_[user].push_back(def);
}

const std::map<Instruction *, std::vector<Instruction *>> &Value::getDefs() {
  return defs_;
}

void Value::deduceType(const boost::statechart::event_base &event) {
  value_type_.process_event(event);
}

void Value::propagateTo(Value *value) {
  value_type_.propagateTo(&value->value_type_);
}
std::string Value::getValueType() const {
  return value_type_.type();
}

void Value::setFinal(bool is_final) {
  is_final_ = is_final;
}