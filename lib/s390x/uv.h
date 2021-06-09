/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _S390X_UV_H_
#define _S390X_UV_H_

bool uv_os_is_guest(void);
bool uv_os_is_host(void);
bool uv_query_test_call(unsigned int nr);
int uv_setup(void);

#endif /* UV_H */
