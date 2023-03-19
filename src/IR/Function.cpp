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

static const std::map<std::string, std::shared_ptr<Operation>> opHandlers = {
    {"COPY", std::make_shared<Copy>()},
    {"LOAD", std::make_shared<Load>()},
    {"STORE", std::make_shared<Store>()},
    {"BRANCH", std::make_shared<Branch>()},
    {"CBRANCH", std::make_shared<CBranch>()},
    {"BRANCHIND", std::make_shared<BranchIndirect>()},
    {"CALL", std::make_shared<Call>()},
    {"CALLIND", std::make_shared<CallIndirect>()},
    {"RETURN", std::make_shared<Return>()},
    {"PIECE", std::make_shared<Piece>()},
    {"SUBPIECE", std::make_shared<SubPiece>()},
    {"INT2FLOAT", std::make_shared<Int2Float>()},
    {"FLOAT2FLOAT", std::make_shared<Float2Float>()},
    {"TRUNC", std::make_shared<Trunc>()},
    {"PTRADD", std::make_shared<PtrAdd>()},
    {"PTRSUB", std::make_shared<PtrSub>()},

    {"INT_EQUAL", std::make_shared<IntEqual>()},
    {"INT_NOTEQUAL", std::make_shared<IntNotEqual>()},
    {"INT_LESS", std::make_shared<IntLess>()},
    {"INT_SLESS", std::make_shared<IntSLess>()},
    {"INT_LESSEQUAL", std::make_shared<IntLessEqual>()},
    {"INT_SLESSEQUAL", std::make_shared<IntSLessEqual>()},
    {"INT_CARRY", std::make_shared<IntCarry>()},
    {"INT_SCARRY", std::make_shared<IntSCarry>()},
    {"INT_SBORROW", std::make_shared<IntSBorrow>()},
    {"INT_ADD", std::make_shared<IntAdd>()},
    {"INT_SUB", std::make_shared<IntSub>()},
    {"INT_XOR", std::make_shared<IntXor>()},
    {"INT_AND", std::make_shared<IntAnd>()},
    {"INT_OR", std::make_shared<IntOr>()},
    {"INT_LEFT", std::make_shared<IntLeft>()},
    {"INT_RIGHT", std::make_shared<IntRight>()},
    {"INT_SRIGHT", std::make_shared<IntSRight>()},
    {"INT_MULT", std::make_shared<IntMult>()},
    {"INT_DIV", std::make_shared<IntDiv>()},
    {"INT_REM", std::make_shared<IntRem>()},
    {"INT_SDIV", std::make_shared<IntSDiv>()},
    {"INT_SREM", std::make_shared<IntSRem>()},

    {"INT_ZEXT", std::make_shared<IntZExt>()},
    {"INT_SEXT", std::make_shared<IntSExt>()},
    {"INT_2COMP", std::make_shared<Int2Comp>()},
    {"INT_NEGATE", std::make_shared<IntNegate>()},

    {"FLOAT_EQUAL", std::make_shared<FloatEqual>()},
    {"FLOAT_NOT_EQUAL", std::make_shared<FloatNotEqual>()},
    {"FLOAT_LESS", std::make_shared<FloatLess>()},
    {"FLOAT_LESS_EQUAL", std::make_shared<FloatLessEqual>()},

    {"FLOAT_ADD", std::make_shared<FloatAdd>()},
    {"FLOAT_SUB", std::make_shared<FloatSub>()},
    {"FLOAT_MULT", std::make_shared<FloatMult>()},
    {"FLOAT_DIV", std::make_shared<FloatDiv>()},

    {"FLOAT_NEG", std::make_shared<FloatNeg>()},
    {"FLOAT_ABS", std::make_shared<FloatAbs>()},
    {"FLOAT_SQRT", std::make_shared<FloatSqrt>()},
    {"FLOAT_CEIL", std::make_shared<FloatCeil>()},
    {"FLOAT_FLOOR", std::make_shared<FloatFloor>()},
    {"FLOAT_ROUND", std::make_shared<FloatRound>()},
    {"FLOAT_NAN", std::make_shared<FloatNan>()},

    {"BOOL_NEGATE", std::make_shared<BoolNegate>()},
    {"BOOL_XOR", std::make_shared<BoolXor>()},
    {"BOOL_AND", std::make_shared<BoolAnd>()},
    {"BOOL_OR", std::make_shared<BoolOr>()},
};

void roughDeduce(Instruction *inst, std::set<Instruction *> visited) {
  if (visited.find(inst) != visited.end()) {
    return;
  }
  visited.insert(inst);

  if (opHandlers.find(inst->getOp()) != opHandlers.end()) {
    auto handler = opHandlers.at(inst->getOp());
    handler->roughDeduce(inst);
  } else {
    std::cerr << "unsupported operation: " << inst->getOp() << std::endl;
  }

  // propagate type
  for (auto &operand : inst->getOperands()) {
    auto defs = operand->getDefs().find(inst);
    if (defs == operand->getDefs().end()) {
      continue;
    }

    for (auto &def : defs->second) {
      roughDeduce(def, visited);
    }
  }
}

void preciseDeduceStage1(Instruction *inst, std::set<Instruction *> visited) {
  if (visited.find(inst) != visited.end()) {
    return;
  }
  visited.insert(inst);

  if (opHandlers.find(inst->getOp()) != opHandlers.end()) {
    auto handler = opHandlers.at(inst->getOp());
    handler->preciseDeduceStage1(inst);
  } else {
    std::cerr << "unsupported operation: " << inst->getOp() << std::endl;
  }

  // propagate type
  for (auto &operand : inst->getOperands()) {
    auto defs = operand->getDefs().find(inst);
    if (defs == operand->getDefs().end()) {
      continue;
    }

    for (auto &def : defs->second) {
      preciseDeduceStage1(def, visited);
    }
  }
}

void preciseDeduceStage2(Instruction *inst, std::set<Instruction *> visited) {
  if (visited.find(inst) != visited.end()) {
    return;
  }
  visited.insert(inst);

  if (opHandlers.find(inst->getOp()) != opHandlers.end()) {
    auto handler = opHandlers.at(inst->getOp());
    handler->preciseDeduceStage2(inst);
  } else {
    std::cerr << "unsupported operation: " << inst->getOp() << std::endl;
  }

  // propagate type
  for (auto &operand : inst->getOperands()) {
    auto defs = operand->getDefs().find(inst);
    if (defs == operand->getDefs().end()) {
      continue;
    }

    for (auto &def : defs->second) {
      preciseDeduceStage2(def, visited);
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
  roughDeduce(inst, visited);
  preciseDeduceStage1(inst, visited);
  preciseDeduceStage2(inst, visited);
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
