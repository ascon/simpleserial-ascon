#ifdef ASCON_PRINT_STATE

#include "printstate.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "ascon.h"
#include "shares.h"
#include "word.h"

void printword(const char* text, const word_t x, int ns) {
  uint32_t lo, hi, e = 0, o = 0;
  for (int d = 0; d < ns; ++d) {
    e ^= ROR32(x.s[d].w[0], ROT(d));
    o ^= ROR32(x.s[d].w[1], ROT(d));
  }
  BI(lo, hi, e, o);
  printf("%s=%016" PRIx64, text, (uint64_t)hi << 32 | lo);
#ifdef ASCON_PRINTBI32
  printf(" (%08x_%08x)", o, e);
#endif
}

void printstate(const char* text, const state_t* s, int ns) {
  printf("%s:", text);
  for (int i = strlen(text); i < 17; ++i) printf(" ");
  printword(" x0", s->x[0], ns);
  printword(" x1", s->x[1], ns);
  printword(" x2", s->x[2], ns);
  printword(" x3", s->x[3], ns);
  printword(" x4", s->x[4], ns);
  printf("\n");
}

#endif
