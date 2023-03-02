#include "BasicBlock.hpp"

#include <boost/assert.hpp>

using namespace pointer_solver;

namespace {

void sanity_guard(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("id"), "expect 'id' field");
  BOOST_ASSERT_MSG(json_obj.contains("preds"), "expect 'preds' field");
  BOOST_ASSERT_MSG(json_obj.contains("succs"), "expect 'succs' field");
  BOOST_ASSERT_MSG(json_obj.contains("instructions"),
                   "expect 'instructions' field");

  auto type = json_obj.at("type");
  auto id = json_obj.at("id");
  auto preds = json_obj.at("preds");
  auto succs = json_obj.at("succs");
  auto insts = json_obj.at("instructions");

  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(id.is_string(), "expect string for 'id' field");
  BOOST_ASSERT_MSG(preds.is_array(), "expect array for 'preds' field");
  BOOST_ASSERT_MSG(succs.is_array(), "expect array for 'succs' field");
  BOOST_ASSERT_MSG(insts.is_array(), "expect array for 'instructions' field");

  for (const auto &pred : preds.as_array()) {
    BOOST_ASSERT_MSG(pred.is_string(),
                     "expect string for elements of array 'preds'");
  }

  for (const auto &succ : succs.as_array()) {
    BOOST_ASSERT_MSG(succ.is_string(),
                     "expect string for elements of array 'succs'");
  }

  for (const auto &inst : insts.as_array()) {
    BOOST_ASSERT_MSG(inst.is_int64(),
                     "expect object for elements of array 'instructions'");
  }
}

} // namespace

std::string BasicBlock::parseId(const boost::json::object &json_obj) {
  sanity_guard(json_obj);

  return std::string(json_obj.at("id").as_string());
}

BasicBlock::BasicBlock(Function *func, const boost::json::object &json_obj)
    : meta_(json_obj), func_(func), is_built_(false) {
  sanity_guard(meta_);

  id_ = meta_.at("id").as_string();
}

void BasicBlock::build() {
  if (is_built_) {
    return;
  }

  auto preds = meta_.at("preds");
  auto succs = meta_.at("succs");
  auto insts = meta_.at("instructions");

  for (const auto &pred : preds.as_array()) {
    auto it = func_->find(std::string(pred.as_string()));
    BOOST_ASSERT_MSG(it != func_->cend(),
                     "a predsuccsor doesn't exit in this function");

    preds_.emplace(&it->second);
  }

  for (const auto &succ : succs.as_array()) {
    auto it = func_->find(std::string(succ.as_string()));
    BOOST_ASSERT_MSG(it != func_->cend(),
                     "a successor doesn't exit in this function");

    preds_.emplace(&it->second);
  }

  for (const auto &inst : insts.as_array()) {
    auto it = func_->inst_find(inst.as_int64());
    instructions_.emplace(inst.as_int64(), &it->second);
  }

  is_built_ = true;
}

const std::string &BasicBlock::getId() const { return id_; }

const Function *BasicBlock::getFunction() const { return func_; }

BasicBlock::InstructionContainerType::iterator BasicBlock::begin() {
  return instructions_.begin();
}
BasicBlock::InstructionContainerType::iterator BasicBlock::end() {
  return instructions_.end();
}

BasicBlock::InstructionContainerType &BasicBlock::getInsts() {
  return instructions_;
}

BasicBlock::BasicBlockContainerType &BasicBlock::getPredecessors() {
  return preds_;
}
BasicBlock::BasicBlockContainerType &BasicBlock::getSuccessors() {
  return succs_;
}

const Instruction *BasicBlock::find(size_t id) const {
  auto it = instructions_.find(id);
  return it == instructions_.end() ? nullptr : it->second;
}

bool BasicBlock::operator==(const BasicBlock &rhs) const {
  return this->id_ == rhs.id_;
}

bool BasicBlock::operator<(const BasicBlock &rhs) const {
  return this->id_ < rhs.id_;
}

bool BasicBlock::operator==(const std::string &rhs) const {
  return this->id_ == rhs;
}

bool BasicBlock::operator<(const std::string &rhs) const {
  return this->id_ < rhs;
}
