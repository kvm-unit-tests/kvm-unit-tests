/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _S390X_UV_H_
#define _S390X_UV_H_

#include <sie.h>

bool uv_os_is_guest(void);
bool uv_os_is_host(void);
bool uv_query_test_call(unsigned int nr);
void uv_init(void);
int uv_setup(void);
void uv_create_guest(struct vm *vm);
void uv_destroy_guest(struct vm *vm);
int uv_unpack(struct vm *vm, uint64_t addr, uint64_t len, uint64_t tweak);
void uv_verify_load(struct vm *vm);

#endif /* UV_H */
