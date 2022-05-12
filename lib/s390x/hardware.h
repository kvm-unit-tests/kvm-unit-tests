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

#define MACHINE_Z15	0x8561
#define MACHINE_Z15T02	0x8562

enum s390_host {
	HOST_IS_UNKNOWN,
	HOST_IS_LPAR,
	HOST_IS_KVM,
	HOST_IS_TCG
};

enum s390_host detect_host(void);

static inline uint16_t get_machine_id(void)
{
	return stidp() >> 16;
}

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

static inline bool host_is_qemu(void)
{
	return host_is_tcg() || host_is_kvm();
}

static inline bool machine_is_z15(void)
{
	uint16_t machine = get_machine_id();

	return machine == MACHINE_Z15 || machine == MACHINE_Z15T02;
}

#endif  /* _S390X_HARDWARE_H_ */
