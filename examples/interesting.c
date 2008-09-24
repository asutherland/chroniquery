#include <stdio.h>
#include <stdlib.h>

int heap;

int alloc1() {
  return ++heap;
}

int alloc2() {
  return ++heap;
}

int party_up(int x) {
  return alloc1();
}

int party_down(int x) {
  return alloc2();
}

int main(int argc, char **argv) {
  int m = 0;

  m = party_down(party_up(0));
  m = party_up(party_down(0));

  printf("heap is %d at exit\n", heap);
}
