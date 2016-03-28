#include <cstdio>
#include <cstdlib>

struct Foo {
  int x;
};

Foo Wombat = { 5 };
Foo Punk = { 6 };

void dostuff(Foo *bob) {

}

int main(int argc, char **argv) {
  dostuff(&Wombat);
  dostuff(&Punk);

  return 0;
}
