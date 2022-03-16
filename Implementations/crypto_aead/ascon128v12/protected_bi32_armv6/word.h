#ifndef WORD_H_
#define WORD_H_

#include <stdint.h>
#include <string.h>

#include "asm.h"
#include "config.h"
#include "endian.h"
#include "forceinline.h"
#include "interleave.h"
#include "shares.h"

typedef struct {
  uint32_t w[2];
} share_t;

typedef struct {
  share_t s[NUM_SHARES_KEY];
} word_t;

forceinline uint32_t ROR32(uint32_t x, int n) {
  return x >> n | x << (-n & 31);
}

forceinline uint64_t ROR32x2(uint64_t x, int n) {
  uint32_t lo = x;
  uint32_t hi = x >> 32;
  lo = ROR32(lo, n);
  hi = ROR32(hi, n);
  return (uint64_t)hi << 32 | lo;
}

forceinline uint64_t ROR64(uint64_t x, int n) {
  return x >> n | x << (-n & 63);
}

forceinline word_t MXOR(word_t a, word_t b, int ns) {
  if (ns >= 1) a.s[0].w[0] ^= b.s[0].w[0];
  if (ns >= 1) a.s[0].w[1] ^= b.s[0].w[1];
  if (ns >= 2) a.s[1].w[0] ^= b.s[1].w[0];
  if (ns >= 2) a.s[1].w[1] ^= b.s[1].w[1];
  if (ns >= 3) a.s[2].w[0] ^= b.s[2].w[0];
  if (ns >= 3) a.s[2].w[1] ^= b.s[2].w[1];
  if (ns >= 4) a.s[3].w[0] ^= b.s[3].w[0];
  if (ns >= 4) a.s[3].w[1] ^= b.s[3].w[1];
  return a;
}

forceinline word_t MXORBIC(word_t c, word_t a, word_t b, int i, int ns) {
  uint32_t tmp;
  if (ns == 1) {
    EOR_BIC_ROR(c.s[0].w[i], a.s[0].w[i], b.s[0].w[i], 0, tmp);
  }
  if (ns == 2) {
    EOR_BIC_ROR(c.s[0].w[i], a.s[0].w[i], b.s[0].w[i], 0, tmp);
    EOR_BIC_ROR(c.s[1].w[i], a.s[1].w[i], b.s[0].w[i], 0 - 1, tmp);
    CLEAR();
    EOR_AND_ROR(c.s[1].w[i], a.s[1].w[i], b.s[1].w[i], 0, tmp);
    EOR_AND_ROR(c.s[0].w[i], a.s[0].w[i], b.s[1].w[i], 1 - 0, tmp);
    CLEAR();
  }
  if (ns == 3) {
    EOR_AND_ROR(c.s[0].w[i], b.s[0].w[i], a.s[1].w[i], 1 - 0, tmp);
    EOR_BIC_ROR(c.s[0].w[i], a.s[0].w[i], b.s[0].w[i], 0, tmp);
    EOR_AND_ROR(c.s[0].w[i], b.s[0].w[i], a.s[2].w[i], 2 - 0, tmp);
    EOR_AND_ROR(c.s[1].w[i], b.s[1].w[i], a.s[2].w[i], 2 - 1, tmp);
    EOR_BIC_ROR(c.s[1].w[i], a.s[1].w[i], b.s[1].w[i], 0, tmp);
    EOR_AND_ROR(c.s[1].w[i], b.s[1].w[i], a.s[0].w[i], 0 - 1, tmp);
    EOR_BIC_ROR(c.s[2].w[i], b.s[2].w[i], a.s[0].w[i], 0 - 2, tmp);
    EOR_ORR_ROR(c.s[2].w[i], a.s[2].w[i], b.s[2].w[i], 0, tmp);
    EOR_AND_ROR(c.s[2].w[i], b.s[2].w[i], a.s[1].w[i], 1 - 2, tmp);
  }
  if (ns == 4) {
    EOR_BIC_ROR(c.s[0].w[i], a.s[0].w[i], b.s[0].w[i], 0, tmp);
    EOR_BIC_ROR(c.s[1].w[i], a.s[1].w[i], b.s[0].w[i], 0 - 1, tmp);
    EOR_BIC_ROR(c.s[2].w[i], a.s[2].w[i], b.s[0].w[i], 0 - 2, tmp);
    EOR_BIC_ROR(c.s[3].w[i], a.s[3].w[i], b.s[0].w[i], 0 - 3, tmp);
    EOR_AND_ROR(c.s[1].w[i], a.s[1].w[i], b.s[1].w[i], 0, tmp);
    EOR_AND_ROR(c.s[2].w[i], a.s[2].w[i], b.s[1].w[i], 1 - 2, tmp);
    EOR_AND_ROR(c.s[3].w[i], a.s[3].w[i], b.s[1].w[i], 1 - 3, tmp);
    EOR_AND_ROR(c.s[0].w[i], a.s[0].w[i], b.s[1].w[i], 1 - 0, tmp);
    EOR_AND_ROR(c.s[2].w[i], a.s[2].w[i], b.s[2].w[i], 0, tmp);
    EOR_AND_ROR(c.s[3].w[i], a.s[3].w[i], b.s[2].w[i], 2 - 3, tmp);
    EOR_AND_ROR(c.s[0].w[i], a.s[0].w[i], b.s[2].w[i], 2 - 0, tmp);
    EOR_AND_ROR(c.s[1].w[i], a.s[1].w[i], b.s[2].w[i], 2 - 1, tmp);
    EOR_AND_ROR(c.s[3].w[i], a.s[3].w[i], b.s[3].w[i], 0, tmp);
    EOR_AND_ROR(c.s[0].w[i], a.s[0].w[i], b.s[3].w[i], 3 - 0, tmp);
    EOR_AND_ROR(c.s[1].w[i], a.s[1].w[i], b.s[3].w[i], 3 - 1, tmp);
    EOR_AND_ROR(c.s[2].w[i], a.s[2].w[i], b.s[3].w[i], 3 - 2, tmp);
  }
  return c;
}

forceinline word_t MXORAND(word_t c, word_t a, word_t b, int ns) {
  b.s[0].w[0] = ~b.s[0].w[0];
  b.s[0].w[1] = ~b.s[0].w[1];
  c = MXORBIC(c, a, b, 0, ns);
  c = MXORBIC(c, a, b, 1, ns);
  return c;
}

forceinline word_t MRND(int ns) {
  word_t w;
  if (ns >= 2) RND(w.s[1].w[0]);
  if (ns >= 2) RND(w.s[1].w[1]);
  if (ns >= 3) RND(w.s[2].w[0]);
  if (ns >= 3) RND(w.s[2].w[1]);
  if (ns >= 4) RND(w.s[3].w[0]);
  if (ns >= 4) RND(w.s[3].w[1]);
  return w;
}

forceinline word_t MMIX(word_t w, int ns) {
  if (ns >= 2) w.s[1].w[0] = ROR32(w.s[1].w[0], 7);
  if (ns >= 2) w.s[1].w[1] = ROR32(w.s[1].w[1], 7);
  if (ns >= 3) w.s[2].w[0] = ROR32(w.s[2].w[0], 13);
  if (ns >= 3) w.s[2].w[1] = ROR32(w.s[2].w[1], 13);
  if (ns >= 4) w.s[3].w[0] = ROR32(w.s[3].w[0], 29);
  if (ns >= 4) w.s[3].w[1] = ROR32(w.s[3].w[1], 29);
  return w;
}

forceinline word_t MREDUCE(word_t w, int nsi, int nso) {
  if (nsi >= 2 && nso < 2) w.s[0].w[0] ^= ROR32(w.s[1].w[0], ROT(1));
  if (nsi >= 2 && nso < 2) w.s[0].w[1] ^= ROR32(w.s[1].w[1], ROT(1));
  if (nsi >= 3 && nso < 3) w.s[0].w[0] ^= ROR32(w.s[2].w[0], ROT(2));
  if (nsi >= 3 && nso < 3) w.s[0].w[1] ^= ROR32(w.s[2].w[1], ROT(2));
  if (nsi >= 4 && nso < 4) w.s[0].w[0] ^= ROR32(w.s[3].w[0], ROT(3));
  if (nsi >= 4 && nso < 4) w.s[0].w[1] ^= ROR32(w.s[3].w[1], ROT(3));
  return w;
}

forceinline word_t MEXPAND(word_t w, int nsi, int nso) {
  return MREDUCE(w, nso, nsi);
}

forceinline word_t MREUSE(word_t w, uint64_t val, int ns) {
  w.s[0].w[0] = (uint32_t)val;
  w.s[0].w[1] = val >> 32;
  w = MMIX(w, ns);
  w = MEXPAND(w, 1, ns);
  return w;
}

forceinline word_t MZERO(int ns) {
  word_t w;
  if (ns == 1) {
    MOVI(w.s[0].w[0], 0);
    MOVI(w.s[0].w[1], 0);
  }
  if (ns >= 2) {
    RND(w.s[1].w[0]);
    RND(w.s[1].w[1]);
    RORI(w.s[1].w[0], w.s[1].w[0], 7);
    RORI(w.s[1].w[1], w.s[1].w[1], 7);
    RORI(w.s[0].w[0], w.s[1].w[0], ROT(1));
    RORI(w.s[0].w[1], w.s[1].w[1], ROT(1));
    if (ns == 2) CLEAR();
  }
  if (ns >= 3) {
    RND(w.s[2].w[0]);
    RND(w.s[2].w[1]);
    RORI(w.s[2].w[0], w.s[2].w[0], 13);
    RORI(w.s[2].w[1], w.s[2].w[1], 13);
    EOR_ROR(w.s[0].w[0], w.s[0].w[0], w.s[2].w[0], ROT(2));
    EOR_ROR(w.s[0].w[1], w.s[0].w[1], w.s[2].w[1], ROT(2));
  }
  if (ns >= 4) {
    RND(w.s[3].w[0]);
    RND(w.s[3].w[1]);
    RORI(w.s[3].w[0], w.s[3].w[0], 29);
    RORI(w.s[3].w[1], w.s[3].w[1], 29);
    EOR_ROR(w.s[0].w[0], w.s[0].w[0], w.s[3].w[0], ROT(3));
    EOR_ROR(w.s[0].w[1], w.s[0].w[1], w.s[3].w[1], ROT(3));
  }
  return w;
}

forceinline word_t MMASK(int n, int ns) {
  uint32_t mask = 0xffffffff >> (n * 4);
  word_t m = MZERO(ns);
  m.s[0].w[0] ^= mask;
  m.s[0].w[1] ^= mask;
  return m;
}

forceinline word_t MREFRESH(word_t w, int ns) {
  word_t r = MZERO(ns);
  return MXOR(w, r, ns);
}

forceinline int MNOTZERO(word_t a, word_t b, int ns) {
  word_t c = MZERO(ns);
  /* note: OR(a,b) = ~BIC(~a,b) */
  a.s[0].w[0] = ~a.s[0].w[0];
  a.s[0].w[1] = ~a.s[0].w[1];
  /* OR first and second 64-bit word */
  c = MXORBIC(c, a, b, 0, ns);
  c = MXORBIC(c, a, b, 1, ns);
  /* OR even and odd words */
  if (ns >= 1) b.s[0].w[0] = c.s[0].w[1];
  if (ns >= 2) b.s[1].w[0] = c.s[1].w[1];
  if (ns >= 3) b.s[2].w[0] = c.s[2].w[1];
  if (ns >= 4) b.s[3].w[0] = c.s[3].w[1];
  a = MXORBIC(a, b, c, 0, ns);
  /* loop to OR 16/8/4/2/1 bit chunks */
  for (int i = 16; i > 0; i >>= 1) {
    if (ns >= 1) b.s[0].w[0] = ROR32(a.s[0].w[0], i);
    if (ns >= 2) b.s[1].w[0] = ROR32(a.s[1].w[0], i);
    if (ns >= 3) b.s[2].w[0] = ROR32(a.s[2].w[0], i);
    if (ns >= 4) b.s[3].w[0] = ROR32(a.s[3].w[0], i);
    c = MXORBIC(c, a, b, 0, ns);
    if (ns >= 1) a.s[0].w[0] = c.s[0].w[0];
    if (ns >= 2) a.s[1].w[0] = c.s[1].w[0];
    if (ns >= 3) a.s[2].w[0] = c.s[2].w[0];
    if (ns >= 4) a.s[3].w[0] = c.s[3].w[0];
  }
  /* unmask result */
  if (ns >= 2) a.s[0].w[0] ^= ROR32(a.s[1].w[0], ROT(1));
  if (ns >= 3) a.s[0].w[0] ^= ROR32(a.s[2].w[0], ROT(2));
  if (ns >= 4) a.s[0].w[0] ^= ROR32(a.s[3].w[0], ROT(3));
  return ~a.s[0].w[0];
}

forceinline share_t LOADSHARE(uint32_t* data, int ns) {
  share_t s;
  uint32_t lo, hi;
  LDR(lo, data, 0);
  LDR(hi, data, 4 * ns);
#if !ASCON_EXTERN_BI
  BD(s.w[0], s.w[1], lo, hi);
  if (ns == 2) CLEAR();
#else
  s.w[0] = lo;
  s.w[1] = hi;
#endif
  return s;
}

forceinline void STORESHARE(uint32_t* data, share_t s, int ns) {
  uint32_t lo, hi;
#if !ASCON_EXTERN_BI
  BI(lo, hi, s.w[0], s.w[1]);
  if (ns == 2) CLEAR();
#else
  lo = s.w[0];
  hi = s.w[1];
#endif
  STR(lo, data, 0);
  STR(hi, data, 4 * ns);
}

forceinline word_t MLOAD(uint32_t* data, int ns) {
  word_t w = {0};
  if (ns >= 1) w.s[0] = LOADSHARE(&(data[0]), ns);
  if (ns >= 2) w.s[1] = LOADSHARE(&(data[1]), ns);
  if (ns >= 3) w.s[2] = LOADSHARE(&(data[2]), ns);
  if (ns >= 4) w.s[3] = LOADSHARE(&(data[3]), ns);
  return w;
}

forceinline void MSTORE(uint32_t* data, word_t w, int ns) {
  if (ns >= 1) STORESHARE(&(data[0]), w.s[0], ns);
  if (ns >= 2) STORESHARE(&(data[1]), w.s[1], ns);
  if (ns >= 3) STORESHARE(&(data[2]), w.s[2], ns);
  if (ns >= 4) STORESHARE(&(data[3]), w.s[3], ns);
}

#endif /* WORD_H_ */
