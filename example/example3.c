#include <stdlib.h>

int main(int argc, char **argv) {
  int a = 0;

  int *p_a = &a;                         // stack
  int *p_b = (int *)argv;                // stack or register
  int *p_c = (int *)malloc(sizeof(int)); // external
  int *p_d = ((int *)0x1234);            // immediate

  *p_a = 0x10;
  *p_b = 0x20;
  *p_c = 0x30;
  *p_d = 0x40;

  return 0;
}
