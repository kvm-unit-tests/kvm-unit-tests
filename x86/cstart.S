
#include "apic-defs.h"
#include "smp.h"

.global online_cpus

ipi_vector = 0x20

per_cpu_size = PER_CPU_SIZE
max_cpus = MAX_TEST_CPUS

.bss
.align 4096
	. = . + PER_CPU_SIZE * max_cpus
stacktop:

.data

.align 4096
pt:
i = 0
        .rept 1024
        .long 0x1e7 | (i << 22)
        i = i + 1
        .endr

.section .init

.code32

mb_magic = 0x1BADB002
mb_flags = 0x0

	# multiboot header
	.long mb_magic, mb_flags, 0 - (mb_magic + mb_flags)
mb_cmdline = 16

.macro setup_tr_and_percpu
	push %esp
	call setup_tss
	addl $4, %esp
	ltr %ax
	add $(max_cpus * 8), %ax
	mov %ax, %gs
.endm

.macro setup_segments
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %fs
	mov %ax, %gs
	mov %ax, %ss
.endm

.globl start
start:
        lgdtl gdt_descr
        setup_segments
        mov $stacktop, %esp

        push %ebx
        call setup_multiboot
        addl $4, %esp
        call setup_libcflat
        mov mb_cmdline(%ebx), %eax
        mov %eax, __args
        call __setup_args
        call prepare_32
        jmpl $8, $start32

prepare_32:
	mov $(1 << 4), %eax // pse
	mov %eax, %cr4

	mov $pt, %eax
	mov %eax, %cr3

	mov %cr0, %eax
	bts $0, %eax
	bts $31, %eax
	mov %eax, %cr0
	ret

smp_stacktop:	.long stacktop - per_cpu_size

save_id:
	movl $(APIC_DEFAULT_PHYS_BASE + APIC_ID), %eax
	movl (%eax), %eax
	shrl $24, %eax
	lock btsl %eax, online_cpus
	retl

ap_start32:
	setup_segments
	mov $-per_cpu_size, %esp
	lock xaddl %esp, smp_stacktop
	setup_tr_and_percpu
	call load_idt
	call prepare_32
	call reset_apic
	call save_id
	call enable_apic
	call enable_x2apic
	call ap_online

	/* ap_online() should never return */
	ud2

start32:
	setup_tr_and_percpu
	call setup_idt
	call reset_apic
	call save_id
	call mask_pic_interrupts
	call enable_apic
	call bsp_rest_init
        push $__environ
        push $__argv
        push __argc
        call main
	push %eax
	call exit

#include "trampolines.S"
