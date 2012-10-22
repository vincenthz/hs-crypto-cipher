
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "RC4.h"

/* Swap array elements i=State[i] and b=State[j]. */
void swap(u_char *i, u_char *j) {
  u_char temp;
	
  temp = *i;
  *i = *j;
  *j = temp;
}

/* Key scheduling algorithm. Swap array elements based on the key. */
u_char* ksa(u_char *key) {
  int byte, i, keylen, j=0;
  u_char* State = malloc(256);

  // Initialize to the identity permutation
  for(int i=0; i<256; i++) {
    State[i] = i;
  }

  keylen = (int) strlen((char *) key);
	
  for(i=0; i<256; i++) {
    j = (j + State[i] + key[i%keylen]) % 256;
    swap(&State[i], &State[j]);
  }

  return State;
}

/* We pretend the incoming pointer to context is a Ptr (), in
   order to make the Haskell to C transition work.
 */
CCtx* initCtx(u_char * key, void* ctx) {
  u_char* id_perm = ksa(key);

  ((CCtx *) ctx) -> i = 0;
  ((CCtx *) ctx) -> j = 0;
  ((CCtx *) ctx) -> state = id_perm;
  return ctx;
}

/* Encrypt or Decrypt */
u_char* rc4(CCtx *ctx, u_char *input, int len) {
  register u_char *output = malloc(len);
  register int i = ctx -> i;
  register int j = ctx -> j;
  register u_char *state = ctx -> state;
  register u_char temp, si, sj;
	
  for(register int m=0; m<len; m++) {
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
