int foo(bool b) {
  if (b) {
    return 1;
  } else {
    return 2;
  }
}

int main() {
  foo(true);
  foo(false);
  return 0;
}