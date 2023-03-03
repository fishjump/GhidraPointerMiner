#include "Function.hpp"

#include <stack>

#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

using namespace pointer_solver;

namespace {

void sanity_guard(const boost::json::object &json_obj) {
  BOOST_ASSERT_MSG(json_obj.contains("type"), "expect 'type' field");
  BOOST_ASSERT_MSG(json_obj.contains("name"), "expect 'name' field");
  BOOST_ASSERT_MSG(json_obj.contains("basic-blocks"),
                   "expect 'basic-blocks' field");
  BOOST_ASSERT_MSG(json_obj.contains("variables"), "expect 'variables' field");
  BOOST_ASSERT_MSG(json_obj.contains("instructions"),
                   "expect 'variables' field");

  auto type = json_obj.at("type");
  auto name = json_obj.at("name");
  auto blocks = json_obj.at("basic-blocks");
  auto variables = json_obj.at("variables");
  auto insts = json_obj.at("instructions");

  BOOST_ASSERT_MSG(type.is_string(), "expect string for 'type' field");
  BOOST_ASSERT_MSG(name.is_string(), "expect string for 'name' field");
  BOOST_ASSERT_MSG(blocks.is_array(), "expect array for 'basic-blocks' field");
  BOOST_ASSERT_MSG(variables.is_array(), "expect array for 'variables' field");
  BOOST_ASSERT_MSG(insts.is_array(), "expect array for 'instructions' field");

  BOOST_ASSERT_MSG(type.as_string() == "function",
                   "expect value 'function' in 'type' field");

  for (const auto &block : blocks.as_array()) {
    BOOST_ASSERT_MSG(block.is_object(),
                     "expect object for elements of array 'basic-blocks'");
  }

  for (const auto &var : variables.as_array()) {
    BOOST_ASSERT_MSG(var.is_string(),
                     "expect string for elements of array 'variables'");
  }

  for (const auto &inst : insts.as_array()) {
    BOOST_ASSERT_MSG(inst.is_object(),
                     "expect object for elements of array 'instructions'");
  }
}

} // namespace

Function::Function(const boost::json::object &json_obj) {
  sanity_guard(json_obj);

  name_ = json_obj.at("name").as_string();

  for (const auto &var : json_obj.at("variables").as_array()) {
    variables_.emplace(var.as_string(), var.as_string());
  }

  for (const auto &inst : json_obj.at("instructions").as_array()) {
    auto tmp = Instruction(this, inst.as_object());
    insts_.emplace(tmp.getId(), tmp);
  }

  for (const auto &block : json_obj.at("basic-blocks").as_array()) {
    auto tmp = BasicBlock(this, block.as_object());
    blocks_.emplace(tmp.getId(), tmp);
  }

  for (auto &[_, inst] : insts_) {
    inst.build();
  }

  for (auto &[_, block] : blocks_) {
    block.build();
  }
}

const std::string &Function::getName() { return name_; }

void Function::ud_chain(Instruction *inst) {
  // TODO: implement this function
  // init visited set for blocks
  std::set<const Instruction *> visited;

  std::map<Value *, std::vector<Instruction *>> trace_tbl;
  for (const auto &it : inst->getOperands()) {
    BOOST_LOG_TRIVIAL(debug)
        << boost::format("tracing value %1% in inst %2%\n") %
               static_cast<std::string>(*it) % static_cast<std::string>(*inst);
    trace_tbl.insert({it, {}});
  }

  // BFS
  std::vector<Instruction *> worklist = inst->getPreds();
  while (!worklist.empty()) {
    auto *inst = worklist.back();
    worklist.pop_back();

    if (visited.find(inst) != visited.end()) {
      continue;
    }
    visited.emplace(inst);

    auto def = inst->getResult();
    // is a assignment instruction
    if (def != nullptr) {
      // defs of this assignment are what we are interested in
      auto it = trace_tbl.find(def);
      if (it != trace_tbl.end()) {
        BOOST_LOG_TRIVIAL(debug)
            << boost::format("found value %1% in inst %2%") %
                   static_cast<std::string>(*def) %
                   static_cast<std::string>(*inst);
        // add this instruction to the defs (value)
        it->second.push_back(inst);

        // also add the uses into the trace table
        for (const auto &use : inst->getOperands()) {
          trace_tbl.insert({use, {}});
        }
      }
    }

    for (auto *pred : inst->getPreds()) {
      worklist.push_back(pred);
    }
  }

  const auto printChain = [](const auto &tbl) {
    for (const auto &[val, insts] : tbl) {
      BOOST_LOG_TRIVIAL(debug)
          << boost::format("use: value %1%") % static_cast<std::string>(*val);
      for (const auto &inst : insts) {
        BOOST_LOG_TRIVIAL(debug)
            << boost::format("defs:  %1%") % static_cast<std::string>(*inst);
      }
    }
  };

  printChain(trace_tbl);

  const auto dumpToValue = [inst](const auto &tbl) {
    for (const auto &[val, insts] : tbl) {
      for (const auto &def : insts) {
        val->addDef(/* use: */ inst, def);
      }
    }
  };

  dumpToValue(trace_tbl);
}

Function::BasicBlockContainerType::iterator Function::begin() {
  return blocks_.begin();
}

Function::BasicBlockContainerType::const_iterator Function::cbegin() const {
  return blocks_.cbegin();
}

Function::BasicBlockContainerType::iterator Function::end() {
  return blocks_.end();
}

Function::BasicBlockContainerType::const_iterator Function::cend() const {
  return blocks_.cend();
}

Function::BasicBlockContainerType::iterator
Function::find(const std::string &key) {
  return blocks_.find(key);
}

Function::BasicBlockContainerType::const_iterator
Function::find(const std::string &key) const {
  return blocks_.find(key);
}

Function::InstructionContainerType::iterator Function::inst_begin() {
  return insts_.begin();
}

Function::InstructionContainerType::const_iterator
Function::inst_cbegin() const {
  return insts_.cbegin();
}

Function::InstructionContainerType::iterator Function::inst_end() {
  return insts_.end();
}

Function::InstructionContainerType::const_iterator Function::inst_cend() const {
  return insts_.cend();
}

Function::InstructionContainerType::iterator Function::inst_find(size_t key) {
  return insts_.find(key);
}

Function::InstructionContainerType::const_iterator
Function::inst_find(size_t key) const {
  return insts_.find(key);
}

Function::ValueContainerType::iterator Function::var_begin() {
  return variables_.begin();
}

Function::ValueContainerType::const_iterator Function::var_cbegin() const {
  return variables_.cbegin();
}

Function::ValueContainerType::iterator Function::var_end() {
  return variables_.end();
}

Function::ValueContainerType::const_iterator Function::var_cend() const {
  return variables_.cend();
}

Function::ValueContainerType::iterator
Function::var_find(const std::string &key) {
  return variables_.find(Value(key));
}

Function::ValueContainerType::const_iterator
Function::var_find(const std::string &key) const {
  return variables_.find(Value(key));
}

Function::ValueContainerType::iterator
Function::var_find(const boost::json::string &key) {
  return var_find(std::string(key));
}

Function::ValueContainerType::const_iterator
Function::var_find(const boost::json::string &key) const {
  return var_find(std::string(key));
}
