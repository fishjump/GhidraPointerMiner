#include "IR/Program.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

#include <boost/assert.hpp>
#include <boost/json.hpp>

namespace {

std::string read(const std::string &path) {
  std::ifstream file(path);
  BOOST_ASSERT_MSG(file, "failed to read file");

  std::stringstream ss;
  ss << file.rdbuf();
  return ss.str();
}

} // namespace

int main() {
  auto json_str = read("example/dump.json");

  auto json_obj = boost::json::parse(json_str);
  BOOST_ASSERT_MSG(json_obj.is_object(),
                   "input json file must be a json object");

  pointer_solver::Program prog(json_obj.as_object());
  for (const auto &func : prog) {
    if (func->getName() != "foo") {
      continue;
    }
    std::cout << func->getName() << std::endl;
    func->ud_chain(&func->inst_find(4)->second);
  }
  return 0;
}