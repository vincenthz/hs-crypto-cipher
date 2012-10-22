
typedef unsigned char u_char;

/* Context for RC4 encryption */
typedef struct {
  unsigned int i;
  unsigned int j;
  u_char * state;
} CCtx;

// Function prototypes
CCtx* initCtx(u_char * key, void *ctx);
u_char * rc4(CCtx *Ctx, u_char *input, int len);
