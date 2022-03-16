#ifdef ASCON_PRINT_STATE

#include "printstate.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void printword(const char* text, const uint64_t x) {
  printf("%s=%016" PRIx64, text, U64BIG(WORDTOU64(x)));
}

void printstate(const char* text, const state_t* s) {
  printf("%s:", text);
  for (int i = strlen(text); i < 17; ++i) printf(" ");
  printword(" x0", s->x[0]);
  printword(" x1", s->x[1]);
  printword(" x2", s->x[2]);
  printword(" x3", s->x[3]);
  printword(" x4", s->x[4]);
  printf("\n");
}

#endif
