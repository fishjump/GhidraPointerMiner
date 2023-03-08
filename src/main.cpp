#include "IR/Program.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <boost/json.hpp>

namespace {

std::string read(const std::string &path) {
  std::ifstream file(path);
  BOOST_ASSERT_MSG(file, "failed to read file");

  std::stringstream ss;
  ss << file.rdbuf();
  return ss.str();
}

void printUDChain(pointer_solver::Function *f,
                  pointer_solver::Instruction *inst) {
  using namespace std;
  using namespace boost;

  cout << format("Instruction: %1%[%2%]\n") % static_cast<string>(*inst) %
              f->getName();

  if (inst->getOperands().empty()) {
    cout << "  Use: <empty>\n\n";
    return;
  }

  for (const auto &operand : inst->getOperands()) {
    cout << format("  Use: %1%\n") % static_cast<string>(*operand);

    for (auto operand_ = operand; operand_ != nullptr; operand_ = nullptr) {
      if (operand_->getDefs().find(inst) == operand_->getDefs().end()) {
        cout << "    Def: <empty>\n";
        operand_ = nullptr;
        continue;
      }

      const auto &defs = operand_->getDefs().at(inst);
      if (defs.empty()) {
        cout << "    Def: <empty>\n";
        operand_ = nullptr;
        continue;
      }

      for (const auto &def : defs) {
        cout << format("    Def: %1%\n") % static_cast<string>(*def);
      }
    }
  };
}

} // namespace

int main() {
  auto json_str = read("example/example2/dump.json");

  auto json_obj = boost::json::parse(json_str);
  BOOST_ASSERT_MSG(json_obj.is_object(),
                   "input json file must be a json object");

  pointer_solver::Program prog(json_obj.as_object());

  for (const auto &func : prog) {
    for (auto it = func->inst_begin(); it != func->inst_end(); ++it) {
      auto &inst = it->second;

#if 0
      // Let us just do all instructions for now
      if (inst.getOp() != "STORE" && inst.getOp() != "LOAD"
          /* inst doesn't exist in defs */
      ) {
        bool exist = false;
        for (const auto &chain : use_def_chains) {
          for (const auto &[use, defs] : *chain) {
            for (const auto &def : defs) {
              if (def == &inst) {
                exist = true;
                break;
              }
            } // for (const auto &def : defs)

            if (exist) {
              break;
            }
          } // for (const auto &[use, defs] : *chain)

          if (exist) {
            break;
          }
        } // for (const auto &chain : use_def_chains)

        if (!exist) {
          continue;
        }
      } // if (inst.getOp() != "STORE" && inst.getOp() != "LOAD")
#endif

      func->getUseDefChain(&inst);
    }
  }

  for (const auto &func : prog) {
    for (auto it = func->inst_begin(); it != func->inst_end(); ++it) {
      auto &inst = it->second;
      printUDChain(func.get(), &inst);
    }
  }

  for (const auto &func : prog) {
    for (auto it = func->inst_begin(); it != func->inst_end(); ++it) {
      auto &inst = it->second;
      func->deduceType(&inst);
    }
  }

  for (const auto &func : prog) {
    std::cout << func->getName() << std::endl;
    for (auto it = func->var_begin(); it != func->var_end(); ++it) {
      auto &v = it->second;
      std::cout << static_cast<std::string>(v) << " : "
                << toString(v.getValueType()) << std::endl;
    }
  }

  return 0;
}