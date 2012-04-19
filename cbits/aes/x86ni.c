/*
 * Copyright (c) 2012 Vincent Hanquez <vincent@snarc.org>
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
#include <wmmintrin.h>
#include <tmmintrin.h>
#include "aes.h"

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
{
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

void aes_generate_key128(aes_key128 *key, uint8_t *ikey)
{
	__m128i *k = (__m128i *) key->_data;
	k[0] = _mm_loadu_si128((const __m128i*) ikey);

#define AES_128_key_exp(K, RCON) aes_128_key_expansion(K, _mm_aeskeygenassist_si128(K, RCON))
	k[1]  = AES_128_key_exp(k[0], 0x01);
	k[2]  = AES_128_key_exp(k[1], 0x02);
	k[3]  = AES_128_key_exp(k[2], 0x04);
	k[4]  = AES_128_key_exp(k[3], 0x08);
	k[5]  = AES_128_key_exp(k[4], 0x10);
	k[6]  = AES_128_key_exp(k[5], 0x20);
	k[7]  = AES_128_key_exp(k[6], 0x40);
	k[8]  = AES_128_key_exp(k[7], 0x80);
	k[9]  = AES_128_key_exp(k[8], 0x1B);
	k[10] = AES_128_key_exp(k[9], 0x36);

	/* generate decryption keys in reverse order.
	 * k[10] is shared by last encryption and first decryption rounds
	 * k[20] is shared by first encryption round (and is the original user key) */
	k[11] = _mm_aesimc_si128(k[9]);
	k[12] = _mm_aesimc_si128(k[8]);
	k[13] = _mm_aesimc_si128(k[7]);
	k[14] = _mm_aesimc_si128(k[6]);
	k[15] = _mm_aesimc_si128(k[5]);
	k[16] = _mm_aesimc_si128(k[4]);
	k[17] = _mm_aesimc_si128(k[3]);
	k[18] = _mm_aesimc_si128(k[2]);
	k[19] = _mm_aesimc_si128(k[1]);
}

#define PRELOAD_ENC_KEYS(k) \
	__m128i K0  = k[0]; __m128i K1  = k[1]; __m128i K2  = k[2]; __m128i K3  = k[3]; \
	__m128i K4  = k[4]; __m128i K5  = k[5]; __m128i K6  = k[6]; __m128i K7  = k[7]; \
	__m128i K8  = k[8]; __m128i K9  = k[9]; __m128i K10 = k[10];

#define DO_ENC_BLOCK(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesenc_si128(m, K1); \
	m = _mm_aesenc_si128(m, K2); \
	m = _mm_aesenc_si128(m, K3); \
	m = _mm_aesenc_si128(m, K4); \
	m = _mm_aesenc_si128(m, K5); \
	m = _mm_aesenc_si128(m, K6); \
	m = _mm_aesenc_si128(m, K7); \
	m = _mm_aesenc_si128(m, K8); \
	m = _mm_aesenc_si128(m, K9); \
	m = _mm_aesenclast_si128(m, K10);

#define PRELOAD_DEC_KEYS(k) \
	__m128i K0  = k[10+0]; __m128i K1  = k[10+1]; __m128i K2  = k[10+2]; __m128i K3  = k[10+3]; \
	__m128i K4  = k[10+4]; __m128i K5  = k[10+5]; __m128i K6  = k[10+6]; __m128i K7  = k[10+7]; \
	__m128i K8  = k[10+8]; __m128i K9  = k[10+9]; __m128i K10 = k[0];

#define DO_DEC_BLOCK(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesdec_si128(m, K1); \
	m = _mm_aesdec_si128(m, K2); \
	m = _mm_aesdec_si128(m, K3); \
	m = _mm_aesdec_si128(m, K4); \
	m = _mm_aesdec_si128(m, K5); \
	m = _mm_aesdec_si128(m, K6); \
	m = _mm_aesdec_si128(m, K7); \
	m = _mm_aesdec_si128(m, K8); \
	m = _mm_aesdec_si128(m, K9); \
	m = _mm_aesdeclast_si128(m, K10);

void aes_encrypt(uint8_t *out, aes_key128 *key, uint8_t *in, uint32_t blocks)
{
	uint32_t i;
	uint64_t _out[2] __attribute__((aligned(16)));
	__m128i *k = (__m128i *) key->_data;

	PRELOAD_ENC_KEYS(k);

	for (i = 0; i < blocks; i++, in += 16, out += 16) {
		__m128i m = _mm_loadu_si128((__m128i *) in);

		DO_ENC_BLOCK(m);

		_mm_store_si128((__m128i *) _out, m);
		((uint64_t *) out)[0] = (_out[0]);
		((uint64_t *) out)[1] = (_out[1]);
	}
}

void aes_decrypt(uint8_t *out, aes_key128 *key, uint8_t *in, uint32_t blocks)
{
	uint32_t i;
	uint64_t _out[2] __attribute__((aligned(16)));
	__m128i *k = (__m128i *) key->_data;

	PRELOAD_DEC_KEYS(k);

	for (i = 0; i < blocks; i++, in += 16, out += 16) {
		__m128i m = _mm_loadu_si128((__m128i *) in);

		DO_DEC_BLOCK(m);

		_mm_store_si128((__m128i *) _out, m);
		((uint64_t *) out)[0] = (_out[0]);
		((uint64_t *) out)[1] = (_out[1]);
	}
}

void aes_encrypt_cbc(uint8_t *out, aes_key128 *key, uint8_t *_iv, uint8_t *in, uint32_t blocks)
{
	uint32_t i;
	uint64_t _out[2] __attribute__((aligned(16)));
	__m128i *k = (__m128i *) key->_data;
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_ENC_KEYS(k);

	for (i = 0; i < blocks; i++, in += 16, out += 16) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		m = _mm_xor_si128(m, iv);

		DO_ENC_BLOCK(m);

		_mm_store_si128((__m128i *) _out, m);
		iv = m;
		((uint64_t *) out)[0] = (_out[0]);
		((uint64_t *) out)[1] = (_out[1]);
	}
}

void aes_decrypt_cbc(uint8_t *out, aes_key128 *key, uint8_t *_iv, uint8_t *in, uint32_t blocks)
{
	uint32_t i;
	uint64_t _out[2] __attribute__((aligned(16)));
	__m128i *k = (__m128i *) key->_data;
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_DEC_KEYS(k);

	for (i = 0; i < blocks; i++, in += 16, out += 16) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		__m128i ivnext = m;

		DO_DEC_BLOCK(m);
		m = _mm_xor_si128(m, iv);

		_mm_store_si128((__m128i *) _out, m);
		iv = ivnext;
		((uint64_t *) out)[0] = (_out[0]);
		((uint64_t *) out)[1] = (_out[1]);
	}
}
