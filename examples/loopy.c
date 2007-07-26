#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  int i = 1, l = 1;

  while(i < 25)
  {
    int n = i + l;
    l = i;
    i = n;

    printf("%d\n", i);
  }

  return 0;
}
