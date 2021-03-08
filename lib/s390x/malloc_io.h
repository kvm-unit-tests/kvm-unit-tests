/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * I/O allocations
 *
 * Copyright (c) 2021 IBM Corp
 *
 * Authors:
 *  Pierre Morel <pmorel@linux.ibm.com>
 *
 */
#ifndef _S390X_MALLOC_IO_H_
#define _S390X_MALLOC_IO_H_

/*
 * Allocates a page aligned page bound range of contiguous real or
 * absolute memory in the DMA31 region large enough to contain size
 * bytes.
 * If Protected Virtualisation facility is present, shares the pages
 * with the host.
 * If all the pages for the specified size cannot be reserved,
 * the function rewinds the partial allocation and a NULL pointer
 * is returned.
 *
 * @size: the minimal size allocated in byte.
 * @flags: the flags used for the underlying page allocator.
 *
 * Errors:
 *   The allocation will assert the size parameter, will fail if the
 *   underlying page allocator fail or in the case of protected
 *   virtualisation if the sharing of the pages fails.
 *
 * Returns a pointer to the first page in case of success, NULL otherwise.
 */
void *alloc_io_mem(int size, int flags);

/*
 * Frees a previously memory space allocated by alloc_io_mem.
 * If Protected Virtualisation facility is present, unshares the pages
 * with the host.
 * The address must be aligned on a page boundary otherwise an assertion
 * breaks the program.
 */
void free_io_mem(void *p, int size);

#endif /* _S390X_MALLOC_IO_H_ */
