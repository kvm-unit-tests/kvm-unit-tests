/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * (pseudo) random functions
 *
 * Copyright IBM Corp. 2024
 */
#ifndef _RAND_H_
#define _RAND_H_

#include <stdint.h>

/* Non cryptographically secure PRNG */
typedef struct {
	uint32_t hash[8];
	uint8_t next_word;
} prng_state;
prng_state prng_init(uint64_t seed);
uint32_t prng32(prng_state *state);
uint64_t prng64(prng_state *state);

#endif /* _RAND_H_ */
