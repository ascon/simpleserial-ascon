/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// cw dependencies
#include "hal.h"
#include "simpleserial.h"

// ascon dependencies
#include "api.h"
#include "crypto_aead.h"

#ifndef SS_SHARED
#define SS_SHARED 0
#endif

#if SS_SHARED

#include "crypto_aead_shared.h"

// number of masked 32-bit structs (with 64-bit padding)
#define LENGTH(len) ((((len) + 7) / 8) * 2)

mask_m_uint32_t* m = NULL;
mask_c_uint32_t* c = NULL;
mask_ad_uint32_t* a = NULL;
mask_npub_uint32_t* n = NULL;
mask_key_uint32_t* k = NULL;

#else

// number of bytes
#define LENGTH(len) (len)

unsigned char* m = NULL;
unsigned char* c = NULL;
unsigned char* a = NULL;
unsigned char* n = NULL;
unsigned char* k = NULL;

#endif

unsigned long long mlen = 0;
unsigned long long clen = 0;
unsigned long long alen = 0;
unsigned long long len = 0;

#define M 0x01            // data contains m
#define C 0x02            // data contains c
#define A 0x04            // data contains ad
#define N 0x08            // data contains npub
#define K 0x10            // data contains k
#define RUN_ENC 0x20      // run enc after data transfer
#define RUN_DEC 0x40      // run dec after data transfer
#define OMIT_RESULT 0x80  // omit sending result after en/decryption

#ifndef DATA_LEN
#define DATA_LEN 190  // up to 190 for SS_VER_1_1
#endif

#ifndef RESP_LEN
#define RESP_LEN 96
#endif

uint8_t data_out[RESP_LEN] = {0};

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t ascon(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t ascon(uint8_t* data, uint8_t dlen) {
#endif

  uint8_t flags = *data;
  data += 1;
  memset(data_out, 0, RESP_LEN);

  if (flags & M) {
    mlen = *data;
    data += 1;
    len = LENGTH(mlen) * sizeof(*m);
    if (m) free(m);
    m = malloc(len);
    memcpy(m, data, len);
    data += len;
  }

  if (flags & C) {
    clen = *data;
    data += 1;
    len = LENGTH(clen) * sizeof(*c);
    if (c) free(c);
    c = malloc(len);
    memcpy(c, data, len);
    data += len;
  }

  if (flags & A) {
    alen = *data;
    data += 1;
    len = LENGTH(alen) * sizeof(*a);
    if (a) free(a);
    a = malloc(len);
    memcpy(a, data, len);
    data += len;
  }

  if (flags & N) {
    int nlen = CRYPTO_NPUBBYTES;
    len = LENGTH(nlen) * sizeof(*n);
    if (n) free(n);
    n = malloc(len);
    memcpy(n, data, len);
    data += len;
  }

  if (flags & K) {
    int klen = CRYPTO_KEYBYTES;
    len = LENGTH(klen) * sizeof(*k);
    if (k) free(k);
    k = malloc(len);
    memcpy(k, data, len);
    data += len;
  }

  if (flags & RUN_ENC) {
    clen = mlen + CRYPTO_ABYTES;
    len = LENGTH(clen) * sizeof(*c);
    if (c) free(c);
    c = malloc(len);

    trigger_high();
#if SS_SHARED
    crypto_aead_encrypt_shared(c, &clen, m, mlen, a, alen, n, k);
#else
    crypto_aead_encrypt(c, &clen, m, mlen, a, alen, NULL, n, k);
#endif
    trigger_low();

    len = (len < RESP_LEN) ? len : RESP_LEN;
    memcpy(data_out, c, len);
    if ((flags & OMIT_RESULT) == 0) simpleserial_put('r', RESP_LEN, data_out);
  }

  if (flags & RUN_DEC) {
    int result;
    mlen = clen - CRYPTO_ABYTES;
    len = LENGTH(mlen) * sizeof(*m);
    if (m) free(m);
    m = malloc(len);

    trigger_high();
#if SS_SHARED
    result = crypto_aead_decrypt_shared(m, &mlen, c, clen, a, alen, n, k);
#else
    result = crypto_aead_decrypt(m, &mlen, NULL, c, clen, a, alen, n, k);
#endif
    trigger_low();

    data_out[0] = result;
    len = (len < RESP_LEN - 1) ? len : RESP_LEN - 1;
    if (result == 0) memcpy(data_out + 1, m, len);
    if ((flags & OMIT_RESULT) == 0) simpleserial_put('r', RESP_LEN, data_out);
  }

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t echo_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) {
#else
uint8_t echo_test(uint8_t* data, uint8_t dlen) {
#endif
  simpleserial_put('r', RESP_LEN, data);
  return 0x00;
}

int main(void) {
  platform_init();
  init_uart();
  trigger_setup();
  simpleserial_init();

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
  simpleserial_addcmd('a', DATA_LEN, ascon);
  simpleserial_addcmd('e', DATA_LEN, echo_test);
#else  // SS_VER_1_1, SS_VER_1_0
  simpleserial_addcmd('a', DATA_LEN, ascon);
  simpleserial_addcmd('e', DATA_LEN, echo_test);
#endif

  while (1) {
    simpleserial_get();
  }
}
