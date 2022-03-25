/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Functions to retrieve information about the host system.
 *
 * Copyright (c) 2020 Red Hat Inc
 * Copyright 2022 IBM Corp.
 *
 * Authors:
 *  Claudio Imbrenda <imbrenda@linux.ibm.com>
 */

#ifndef _S390X_HARDWARE_H_
#define _S390X_HARDWARE_H_
#include <asm/arch_def.h>

enum s390_host {
	HOST_IS_UNKNOWN,
	HOST_IS_LPAR,
	HOST_IS_KVM,
	HOST_IS_TCG
};

enum s390_host detect_host(void);

static inline bool host_is_tcg(void)
{
	return detect_host() == HOST_IS_TCG;
}

static inline bool host_is_kvm(void)
{
	return detect_host() == HOST_IS_KVM;
}

static inline bool host_is_lpar(void)
{
	return detect_host() == HOST_IS_LPAR;
}

#endif  /* _S390X_HARDWARE_H_ */
