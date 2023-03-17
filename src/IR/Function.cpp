#include "Function.hpp"

#include "PcodeInstructions.hpp"

#include <iostream>

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

void deduceType(Instruction *inst, std::set<Instruction *> visited) {
  if (visited.find(inst) != visited.end()) {
    return;
  }
  visited.insert(inst);

  if (inst->getOp() == "COPY" && inst->getResult() != nullptr &&
      inst->getOperands().size() == 1) {
    Copy().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "LOAD" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    Load().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "LOAD" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    Load().deduceType(inst->getResult(), inst->getOperands()[0],
                      inst->getOperands()[1]);
  } else if (inst->getOp() == "STORE" && inst->getOperands().size() == 2) {
    Store().deduceType(inst->getOperands()[0], inst->getOperands()[1]);
  } else if (inst->getOp() == "STORE" && inst->getOperands().size() == 3) {
    Store().deduceType(inst->getOperands()[0], inst->getOperands()[1],
                       inst->getOperands()[2]);
  } else if (inst->getOp() == "BRANCH" && inst->getOperands().size() == 1) {
    Branch().deduceType(inst->getOperands()[0]);
  } else if (inst->getOp() == "CBRANCH" && inst->getOperands().size() == 2) {
    CBranch().deduceType(inst->getOperands()[0], inst->getOperands()[1]);
  } else if (inst->getOp() == "BRANCHIND" && inst->getOperands().size() == 1) {
    BranchIndirect().deduceType(inst->getOperands()[0]);
  } else if (inst->getOp() == "CALL" && inst->getOperands().size() >= 1) {
    Call().deduceType(inst->getOperands()[0]);
  } else if (inst->getOp() == "CALLIND" && inst->getOperands().size() >= 1) {
    CallIndirect().deduceType(inst->getOperands()[0]);
  } else if (inst->getOp() == "RETURN" && inst->getOperands().size() >= 1) {
    Return().deduceType(inst->getOperands()[0]);
  } else if (inst->getOp() == "PIECE" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    Piece().deduceType(inst->getResult(), inst->getOperands()[0],
                       inst->getOperands()[1]);
  } else if (inst->getOp() == "SUBPIECE" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 3) {
    SubPiece().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1], inst->getOperands()[2]);
  } else if (inst->getOp() == "INT_EQUAL" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_NOTEQUAL" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntNotEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                             inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_LESS" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntLess().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SLESS" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSLess().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_LESSEQUAL" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntLessEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                              inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SLESSEQUAL" &&
             inst->getResult() != nullptr && inst->getOperands().size() == 2) {
    IntSLessEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                               inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_ZEXT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    IntZExt().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "INT_SEXT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    IntSExt().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "INT_ADD" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntAdd().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SUB" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSub().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_CARRY" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntCarry().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SCARRY" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSCarry().deduceType(inst->getResult(), inst->getOperands()[0],
                           inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SBORROW" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSBorrow().deduceType(inst->getResult(), inst->getOperands()[0],
                            inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_2COMP" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    Int2Comp().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "INT_NEGATE" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    IntNegate().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "INT_XOR" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntXor().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_AND" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntAnd().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_OR" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntOr().deduceType(inst->getResult(), inst->getOperands()[0],
                       inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_LEFT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntLeft().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_RIGHT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntRight().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SRIGHT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSRight().deduceType(inst->getResult(), inst->getOperands()[0],
                           inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_MULT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntMult().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_DIV" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntDiv().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_REM" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntRem().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SDIV" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSDiv().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "INT_SREM" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    IntSRem().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "BOOL_NEGATE" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    BoolNegate().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "BOOL_XOR" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    BoolXor().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "BOOL_AND" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    BoolAnd().deduceType(inst->getResult(), inst->getOperands()[0],
                         inst->getOperands()[1]);
  } else if (inst->getOp() == "BOOL_OR" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    BoolOr().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_EQUAL" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    FloatEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                            inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_NOTEQUAL" &&
             inst->getResult() != nullptr && inst->getOperands().size() == 2) {
    FloatNotEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                               inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_LESS" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    FloatLess().deduceType(inst->getResult(), inst->getOperands()[0],
                           inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_LESSEQUAL" &&
             inst->getResult() != nullptr && inst->getOperands().size() == 2) {
    FloatLessEqual().deduceType(inst->getResult(), inst->getOperands()[0],
                                inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_ADD" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    FloatAdd().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_SUB" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    FloatSub().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_MULT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    FloatMult().deduceType(inst->getResult(), inst->getOperands()[0],
                           inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_DIV" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    FloatDiv().deduceType(inst->getResult(), inst->getOperands()[0],
                          inst->getOperands()[1]);
  } else if (inst->getOp() == "FLOAT_NEG" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatNeg().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT_ABS" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatAbs().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT_SQRT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatSqrt().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT_CEIL" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatCeil().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT_FLOOR" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatFloor().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT_ROUND" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatRound().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT_NAN" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    FloatNan().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "INT2FLOAT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    Int2Float().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "FLOAT2FLOAT" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    Float2Float().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "TRUNC" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 1) {
    Trunc().deduceType(inst->getResult(), inst->getOperands()[0]);
  } else if (inst->getOp() == "PTRADD" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 3) {
    PtrAdd().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1], inst->getOperands()[2]);
  } else if (inst->getOp() == "PTRSUB" && inst->getResult() != nullptr &&
             inst->getOperands().size() == 2) {
    PtrSub().deduceType(inst->getResult(), inst->getOperands()[0],
                        inst->getOperands()[1]);
  }

  // propagate type
  for (auto &operand : inst->getOperands()) {
    auto defs = operand->getDefs().find(inst);
    if (defs == operand->getDefs().end()) {
      continue;
    }

    for (auto &def : defs->second) {
      deduceType(def, visited);
    }
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

const std::string &Function::getName() {
  return name_;
}

std::shared_ptr<std::map<Value *, std::vector<Instruction *>>>
Function::getUseDefChain(
    Instruction *inst, std::set<const Instruction *> visited,
    std::shared_ptr<std::map<Value *, std::vector<Instruction *>>> ud_chain) {
  if (visited.find(inst) != visited.end()) {
    return ud_chain;
  }
  visited.insert(inst);

  // is a not assignment instruction, skip
  auto def_val = inst->getResult();
  if (def_val != nullptr && ud_chain->find(def_val) != ud_chain->end()) {
    ud_chain->at(def_val).push_back(inst);
  }

  for (auto p_inst : inst->getPreds()) {
    getUseDefChain(p_inst, visited, ud_chain);
  }

  return ud_chain;
}

std::shared_ptr<std::map<Value *, std::vector<Instruction *>>>
Function::getUseDefChain(Instruction *inst) {
  std::map<Value *, std::vector<Instruction *>> map;
  for (auto &operand : inst->getOperands()) {
    map.insert({operand, {}});
  }

  auto res = std::make_shared<decltype(map)>(map);

  for (auto p_inst : inst->getPreds()) {
    getUseDefChain(p_inst, {}, res);
  }

  for (auto &[val, defs] : *res) {
    for (auto *def : defs) {
      val->addDef(inst, def);
    }
  }

  return res;
}

void Function::deduceType(Instruction *inst) {
  std::set<Instruction *> visited;
  ::deduceType(inst, visited);
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
