// SPDX-License-Identifier: GPL-2.0-only
/*
 * (pseudo) random functions
 * Currently uses SHA-256 to scramble the PRNG state.
 *
 * Copyright IBM Corp. 2024
 */

#include "libcflat.h"
#include "rand.h"
#include <string.h>

/* Begin SHA-256 related definitions */

#define INITAL_HASH { \
	0x6a09e667, \
	0xbb67ae85, \
	0x3c6ef372, \
	0xa54ff53a, \
	0x510e527f, \
	0x9b05688c, \
	0x1f83d9ab, \
	0x5be0cd19, \
}

static const uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ ((~x) & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t rot(uint32_t value, unsigned int count)
{
	return value >> count | value << (32 - count);
}

static inline uint32_t upper_sig0(uint32_t x)
{
	return rot(x, 2) ^ rot(x, 13) ^ rot(x, 22);
}

static inline uint32_t upper_sig1(uint32_t x)
{
	return rot(x, 6) ^ rot(x, 11) ^ rot(x, 25);
}

static inline uint32_t lower_sig0(uint32_t x)
{
	return rot(x, 7) ^ rot(x, 18) ^ (x >> 3);
}

static inline uint32_t lower_sig1(uint32_t x)
{
	return rot(x, 17) ^ rot(x, 19) ^ (x >> 10);
}

enum alphabet { A, B, C, D, E, F, G, H, };

static void sha256_chunk(const uint32_t (*chunk)[16], uint32_t (*hash)[8])
{
	uint32_t w[64];
	uint32_t w_hash[8];

	memcpy(w, chunk, sizeof(*chunk));

	for (int i = 16; i < 64; i++)
		w[i] = lower_sig1(w[i - 2]) + w[i - 7] + lower_sig0(w[i - 15]) + w[i - 16];

	memcpy(w_hash, hash, sizeof(*hash));

	for (int i = 0; i < 64; i++) {
		uint32_t t1, t2;

		t1 = w_hash[H] +
		     upper_sig1(w_hash[E]) +
		     ch(w_hash[E], w_hash[F], w_hash[G]) +
		     K[i] +
		     w[i];

		t2 = upper_sig0(w_hash[A]) + maj(w_hash[A], w_hash[B], w_hash[C]);

		w_hash[H] = w_hash[G];
		w_hash[G] = w_hash[F];
		w_hash[F] = w_hash[E];
		w_hash[E] = w_hash[D] + t1;
		w_hash[D] = w_hash[C];
		w_hash[C] = w_hash[B];
		w_hash[B] = w_hash[A];
		w_hash[A] = t1 + t2;
	}

	for (int i = 0; i < 8; i++)
		(*hash)[i] += w_hash[i];
}

/**
 * sha256_hash - Calculate SHA-256 of input. Only a limited subset of inputs supported.
 * @n: Number of words to hash, must be <= 13
 * @input: Input data to hash
 * @hash: Output hash as a word array, ordered such that the first word contains
 *        the first/leftmost bits of the 256 bit hash
 *
 * Calculate the SHA-256 hash of the input where the input must be a multiple of
 * 4 bytes and at most 52 long. The input is used without any adjustment, so,
 * should the caller want to hash bytes it needs to interpret the bytes in the
 * ordering as defined by the specification, that is big endian.
 * The same applies to interpreting the output array as bytes.
 * The function computes the same as: printf "%08x" ${input[@]} | xxd -r -p | sha256sum .
 */
static void sha256_hash(unsigned int n, const uint32_t (*input)[n], uint32_t (*hash)[8])
{
	/*
	 * Pad according to SHA-2 specification.
	 * First set up length in bits.
	 */
	uint32_t chunk[16] = {
		[15] = sizeof(*input) * 8,
	};

	memcpy(chunk, input, sizeof(*input));
	/* Then add separator */
	chunk[n] = 1 << 31;
	memcpy(hash, (uint32_t[])INITAL_HASH, sizeof(*hash));
	sha256_chunk(&chunk, hash);
}

/* End SHA-256 related definitions */

prng_state prng_init(uint64_t seed)
{
	prng_state state = { .next_word = 0 };
	uint32_t seed_arr[2] = { seed >> 32, seed };

	sha256_hash(ARRAY_SIZE(seed_arr), &seed_arr, &state.hash);
	return state;
}

static void prng_scramble(prng_state *state)
{
	uint32_t input[8];

	memcpy(input, state->hash, sizeof(state->hash));
	sha256_hash(ARRAY_SIZE(input), &input, &state->hash);
	state->next_word = 0;
}

uint32_t prng32(prng_state *state)
{
	if (state->next_word < ARRAY_SIZE(state->hash))
		return state->hash[state->next_word++];

	prng_scramble(state);
	return prng32(state);
}

uint64_t prng64(prng_state *state)
{
	/* explicitly evaluate the high word first */
	uint64_t high = prng32(state);

	return high << 32 | prng32(state);
}
