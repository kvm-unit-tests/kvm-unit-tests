#ifndef _ASMPOWERPC_VPA_H_
#define _ASMPOWERPC_VPA_H_
/*
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#ifndef __ASSEMBLY__

struct vpa {
	uint32_t	descriptor;
	uint16_t	size;
	uint8_t		reserved1[3];
	uint8_t		status;
	uint8_t		reserved2[14];
	uint32_t	fru_node_id;
	uint32_t	fru_proc_id;
	uint8_t		reserved3[56];
	uint8_t		vhpn_change_counters[8];
	uint8_t		reserved4[80];
	uint8_t		cede_latency;
	uint8_t		maintain_ebb;
	uint8_t		reserved5[6];
	uint8_t		dtl_enable_mask;
	uint8_t		dedicated_cpu_donate;
	uint8_t		maintain_fpr;
	uint8_t		maintain_pmc;
	uint8_t		reserved6[28];
	uint64_t	idle_estimate_purr;
	uint8_t		reserved7[28];
	uint16_t	maintain_nr_slb;
	uint8_t		idle;
	uint8_t		maintain_vmx;
	uint32_t	vp_dispatch_count;
	uint32_t	vp_dispatch_dispersion;
	uint64_t	vp_fault_count;
	uint64_t	vp_fault_tb;
	uint64_t	purr_exprop_idle;
	uint64_t	spurr_exprop_idle;
	uint64_t	purr_exprop_busy;
	uint64_t	spurr_exprop_busy;
	uint64_t	purr_donate_idle;
	uint64_t	spurr_donate_idle;
	uint64_t	purr_donate_busy;
	uint64_t	spurr_donate_busy;
	uint64_t	vp_wait3_tb;
	uint64_t	vp_wait2_tb;
	uint64_t	vp_wait1_tb;
	uint64_t	purr_exprop_adjunct_busy;
	uint64_t	spurr_exprop_adjunct_busy;
	uint32_t	supervisor_pagein_count;
	uint8_t		reserved8[4];
	uint64_t	purr_exprop_adjunct_idle;
	uint64_t	spurr_exprop_adjunct_idle;
	uint64_t	adjunct_insns_executed;
	uint8_t		reserved9[120];
	uint64_t	dtl_index;
	uint8_t		reserved10[96];
};

#endif /* __ASSEMBLY__ */

#endif /* _ASMPOWERPC_VPA_H_ */
