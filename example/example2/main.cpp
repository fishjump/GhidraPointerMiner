void swap(int *a, int *b) {
  int tmp = *a;
  *a = *b;
  *b = tmp;
}

int main() {
  int a = 1;
  int b = 2;
  int c = a + b;

  swap(&a, &b);
  return 0;
}