
typedef unsigned char u_char;

/* Context for RC4 encryption */
typedef struct {
  unsigned int i;
  unsigned int j;
  u_char * state;
} CCtx;

// Function prototypes
CCtx* initCtx(uint8_t * key, void *ctx);
uint8_t * rc4(CCtx *Ctx, uint8_t *input, uint32_t len);
