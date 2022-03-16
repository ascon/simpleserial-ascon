#ifndef PRINTSTATE_H_
#define PRINTSTATE_H_

#ifdef ASCON_PRINT_STATE

#include "ascon.h"
#include "word.h"

void printword(const char* text, const word_t x, int ns);
void printstate(const char* text, const state_t* si, int ns);

#else

#define printword(text, w, ns) \
  do {                         \
  } while (0)

#define printstate(text, s, ns) \
  do {                          \
  } while (0)

#endif

#endif /* PRINTSTATE_H_ */
