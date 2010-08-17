

.bss

.section .init

mb_magic = 0x1BADB002
mb_flags = 0x0

	# multiboot header
	.long mb_magic, mb_flags, 0 - (mb_magic + mb_flags)
mb_cmdline = 16

.globl start
start:
	mov mb_cmdline(%ebx), %eax
	mov %eax, __args
	call __setup_args
	pushl $__argv
	pushl __argc
	call main
	push %eax
	call exit


