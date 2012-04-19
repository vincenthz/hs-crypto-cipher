/*
 * Copyright (c) 2010-2012 Vincent Hanquez <vincent@snarc.org>
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef CRYPTOCIPHER_AES_H
#define CRYPTOCIPHER_AES_H

#define AES128_NB_ROUNDS 10

#include <stdint.h>

/* aes_key128 need to be 16 aligned by higher layer using the code. */
typedef struct { uint8_t _data[20]; } aes_key128;

void aes_generate_key128(aes_key128 *key, uint8_t *ikey);

/* ECB mode */
void aes_encrypt(uint8_t *out, aes_key128 *key, uint8_t *in, uint32_t blocks);
void aes_decrypt(uint8_t *out, aes_key128 *key, uint8_t *in, uint32_t blocks);

/* CBC mode */
void aes_encrypt_cbc(uint8_t *out, aes_key128 *key, uint8_t *iv, uint8_t *in, uint32_t blocks);
void aes_decrypt_cbc(uint8_t *out, aes_key128 *key, uint8_t *iv, uint8_t *in, uint32_t blocks);

#endif
