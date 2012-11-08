
/* Function prototypes */

struct rc4_ctx
{
	uint8_t state[256];
	uint32_t i;
	uint32_t j;
};

// Returns a pointer to the cipher text, which is encrypted in place
// in the cipher text buffer.
void rc4(struct rc4_ctx *ctx, /* rc4 context */
         uint8_t  * input,    // Clear text, input only
         uint32_t   len,      // Clear text length, input only
         uint8_t  * output);  // Cipher text buffer, input only

/* Initialize the context for RC4 encryption
 *
 * Returns the initial permutation, in the same buffer provided as input.
 */
uint8_t* initCtx(uint8_t * key,
                 uint32_t keylen,
                 struct rc4_ctx *ctx);
