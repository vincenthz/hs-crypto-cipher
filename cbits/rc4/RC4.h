
/* Function prototypes */

// Returns a pointer to the cipher text, which is encrypted in place
// in the cipher text buffer.
uint8_t * rc4(uint8_t  * state,    // Permutation (S-box), input/output
              uint32_t * iptr,     // First index to permutation (i), input/output
              uint32_t * jptr,     // Second index to permutation (j), input/output
              uint8_t  * input,    // Clear text, input only
              uint32_t   len,      // Clear text length, input only
              uint8_t  * output);  // Cipher text buffer, input only

/* Initialize the context for RC4 encryption
 *
 * Returns the initial permutation, in the same buffer provided as input.
 */
uint8_t* initCtx(uint8_t * key,    // The encryption key, input only
                 uint8_t * state); // Permutation (S-box) buffer, input only
