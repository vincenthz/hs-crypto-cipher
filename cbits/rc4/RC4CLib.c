
/* C Standard includes */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Local include */
#include "RC4.h"

/* Swap array elements i=State[i] and b=State[j]. */
static void swap(uint8_t *i, uint8_t *j)
{
	uint8_t temp;

	temp = *i;
	*i = *j;
	*j = temp;
}

/* Key scheduling algorithm. Swap array elements based on the key. */
uint8_t *initCtx(uint8_t *key, uint8_t * state)
{
	uint32_t keylen, j = 0, i = 0;
	/* Initialize to the identity permutation */
	for (i = 0; i < 256; i++)
		state[i] = i;

	keylen = (uint32_t) strlen((char *) key);

	/* Establish the initial permutation, based on the key	 */
	for (i = 0; i < 256; i++) {
		j = (j + state[i] + key[i % keylen]) % 256;
		swap(&state[i], &state[j]);
	}
	return state;
}

/* Encrypt or Decrypt */
void rc4(uint8_t  * state,
         uint32_t * iptr,
         uint32_t * jptr,
         uint8_t  * input,
         uint32_t   len,
         uint8_t  * output)
{
	uint32_t i = *iptr;
	uint32_t j = *jptr;
	uint32_t m;
	uint8_t si, sj;

	/* The RC4 algorithm */
	for (m = 0; m < len; m++) {
		i = (i + 1) & 0xff;
		si = state[i];
		j = (j + si) & 0xff;
		sj = state[j];
		/* swap(&state[i], &state[j]); */
		state[i] = sj;
		state[j] = si;
		/* Xor the key stream value into the input */
		*output++ = *input++ ^ (state[(si + sj) & 0xff]);
	}

	/* Output new S-box indices */
	*iptr = i;
	*jptr = j;
}
