/* more dubiosity, this time... inlining! */

static __inline__ int rollerblades(int y) __attribute__((always_inline));

int rollerblades(int y) {
  int z;
  z = 2;
  return y + z;
}
