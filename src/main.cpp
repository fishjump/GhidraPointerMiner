#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <boost/json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>

#include "IR/Program.hpp"

namespace {

std::string read(const std::string &path) {
  std::ifstream file(path);
  BOOST_ASSERT_MSG(
      file, (boost::format("failed to read file: %1%") % path).str().c_str());

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

  std::cout << json_str << "\n";
  return 0;
}