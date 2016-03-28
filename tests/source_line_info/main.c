#include <stdlib.h>

#include "dubious.h"
#include "dubious2.h"

int main(int argc, char **argv) {
  int i;
  int a = 0;
  int b = 1;

  for(i=0; i < 2; ++i) {
    a = rollerblades(b);
  }

  return dubioustar(a);
}
