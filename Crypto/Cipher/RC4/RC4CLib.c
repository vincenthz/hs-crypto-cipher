
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "RC4.h"

/*
 *  Posix C99 standard types:
 *
 *  uint8_t for u_char
 *  uint32_t for int
 */
/* Swap array elements i=State[i] and b=State[j]. */
void swap(uint8_t *i, uint8_t *j) {
  uint8_t temp;
	
  temp = *i;
  *i = *j;
  *j = temp;
}

/* Key scheduling algorithm. Swap array elements based on the key. */
u_char* ksa(u_char *key) {
  uint32_t keylen, j=0, i = 0;
  uint8_t* State = malloc(256*sizeof(u_char));
  // Initialize to the identity permutation
  for(i=0; i<256; i++) {
    State[i] = i;
  }
  keylen = (uint32_t) strlen((char *) key);
	
  for(i=0; i<256; i++) {
    j = (j + State[i] + key[i%keylen]) % 256;
    swap(&State[i], &State[j]);
  }
  return State;
}

/* We pretend the incoming pointer to context is a Ptr (), in
   order to make the Haskell to C transition work.
 */
CCtx* initCtx(uint8_t * key, void* ctx) {
  uint8_t* id_perm = ksa(key);
  ((CCtx *) ctx) -> i = 0;
  ((CCtx *) ctx) -> j = 0;
  ((CCtx *) ctx) -> state = id_perm;
  return ctx;
}

/* Encrypt or Decrypt */
uint8_t* rc4(CCtx *ctx, uint8_t *input, uint32_t len) {
  register uint8_t *output = malloc(len);
  register uint32_t i = ctx -> i;
  register uint32_t j = ctx -> j;
  register uint8_t *state = ctx -> state;
  register uint8_t temp, si, sj;
	
  for(register uint32_t m=0; m<len; m++) {
    i = (i+1) & 0xff;
    si = state[i];
    j = (j+si) & 0xff;
    sj = state[j];
    // swap(&state[i], &state[j]);
    state[i] = sj;
    state[j] = si;
    output[m] = input[m] ^ (state[(si+sj) & 0xff]);
  }

  ctx -> i = i;
  ctx -> j = j;

  return (output);
}
